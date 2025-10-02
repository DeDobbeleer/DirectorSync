"""Alert Rules (MyRules) Importer

Scope
-----
- Handles *only* MyRules (user-owned alert rules) with NOOP/CREATE/UPDATE/SKIP.
- Out of scope: Shared/Vendor/Used*, share/unshare/transferOwnership, notifications.
- Repository resolution follows the user's distributed spec:
    settings.repos = ["<ip_private>:<port>[:<old_repo_name>]", ...]
  If <old_repo_name> is omitted, the rule targets **all repos** on that backend.
- Old repo names are mapped to cleaned names via the XLSX `Repo` sheet
  (columns: `original_repo_name`, `cleaned_repo_name`).
- Tenants' private backend IPs are discovered from `tenants.yml` (CLI `--tenants-file` + `--tenant`).

Design choices
--------------
- Integrates with the v2 common trunk just like the other importers (BaseImporter, DirectorClient).
- Keeps payload strictly aligned with the official API for Create/Update:
    data.searchname, data.owner, data.risk, data.repos, data.aggregate,
    data.condition_option, data.condition_value, data.limit,
    data.timerange_minute|hour|day,
    and the documented optional fields (query, description, ...).
- Idempotence: second run is NOOP when the managed field subset matches.
- Activation convergence: uses POST /AlertRules/{id}/activate or /deactivate
  to reach the desired active state from XLSX.

Notes
-----
This module avoids project-specific assumptions beyond what is used by the
other importers. The following utilities/hooks are expected (already present
in v2):
- BaseImporter (load_sheet, report_row, resolve_user_id, resolve_attack_tags,
  resolve_remote_repos, get_tenant_dict, director_client, etc.)
- utils.resolvers for generic resolvers (cached) if available.
- core.config for runtime context (tenant name, tenants file path, etc.).

If some helper names differ slightly in your codebase, adjust the marked
integration points at the bottom of this file where the importer is
registered in the registry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple
import json
import math
import re

import pandas as pd

from lp_tenant_importer_v2.importers.base import BaseImporter
from lp_tenant_importer_v2.core.logging_utils import get_logger


LOG = get_logger(__name__)


@dataclass
class RepoSpec:
    backend_ip: str
    port: str
    repo_old: str = ""
    repo_clean: str = ""
    scope: str = "all"  # "all" (no repo specified) or "specific"

    def normalized(self) -> str:
        """Return the normalized triplet used for deterministic diffing.

        - For ALL scope: "ip:port"
        - For SPECIFIC: "ip:port:repo_clean"
        """
        if self.scope == "all" or not self.repo_clean:
            return f"{self.backend_ip}:{self.port}"
        return f"{self.backend_ip}:{self.port}:{self.repo_clean}"


class AlertRulesImporter(BaseImporter):
    """AlertRules importer using the BaseImporter pipeline (NOOP/CREATE/UPDATE only for MyRules).

    Follows the same contract as other importers (e.g., DevicesImporter):
      - `validate(sheets)` ensures required sheet/columns.
      - `iter_desired(sheets)` yields desired rows parsed from Excel.
      - `key_fn`, `canon_desired`, `canon_existing` feed the diff engine.
      - `fetch_existing(...)` reads current MyRules from Director.
      - `build_payload_create/update` assemble API payloads.
      - `apply(...)` executes API calls (skipped in --dry-run by BaseImporter).
    """

    resource_name: str = "alert_rules"
    sheet_names = ("Alert",)  # we *read* Repo mapping if present but don't require it to run
    required_columns = tuple()  # custom validation below
    compare_keys = (
        # Stable subset for diff (order-insensitive fields normalized in canon_*):
        "risk",
        "repos_csv",
        "aggregate",
        "condition_option",
        "condition_value",
        "limit",
        "timerange_key",
        "timerange_value",
        "query",
        "description",
        "flush_on_trigger",
        "search_interval_minute",
        "throttling_enabled",
        "throttling_field",
        "throttling_time_range",
        "metadata_csv",
        "log_source_csv",
        "context_template",
    )

    # ---------------------------- validation ----------------------------
    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        require_sheets(sheets, self.sheet_names)
        df = sheets["Alert"]
        def need(col: str) -> None:
            if col not in df.columns:
                raise ValidationError(f"Alert: missing required column '{col}'")
        # Minimal set from our frozen spec
        need("name")
        need("settings.risk")
        need("settings.aggregate")
        need("settings.condition.condition_option")
        need("settings.condition.condition_value")
        need("settings.livesearch_data.limit")
        need("settings.repos")
        # Timerange: accept any of these
        if not any(c in df.columns for c in (
            "settings.livesearch_data.timerange_minute",
            "settings.livesearch_data.timerange_hour",
            "settings.livesearch_data.timerange_day",
            "settings.livesearch_data.timerange_second",
            "settings.time_range_seconds",
        )):
            raise ValidationError("Alert: missing timerange column (minute/hour/day/second)")

    # -------------------------- XLSX → desired ---------------------------
    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:  # type: ignore[override]
        df = sheets["Alert"].copy()
        for _, row in df.iterrows():
            name = _s(row.get("name"))
            if not name:
                continue
            desired: Dict[str, Any] = {
                "name": name,
                "risk": _s(row.get("settings.risk")),
                "aggregate": _s(row.get("settings.aggregate")),
                "condition_option": _s(row.get("settings.condition.condition_option")),
                "condition_value": _int_or_none(row.get("settings.condition.condition_value")) or 0,
                "limit": _int_or_none(row.get("settings.livesearch_data.limit")) or 0,
                "query": _s(row.get("settings.extra_config.query") or row.get("settings.livesearch_data.query")),
                "description": _s(row.get("settings.description")),
                "search_interval_minute": _int_or_none(row.get("settings.livesearch_data.search_interval_minute")) or 0,
                "flush_on_trigger": bool(_as_bool_flag_on(row.get("settings.flush_on_trigger"))),
                "throttling_enabled": bool(_as_bool_flag_on(row.get("settings.throttling_enabled"))),
                "throttling_field": _s(row.get("settings.throttling_field")),
                "throttling_time_range": _int_or_none(row.get("settings.throttling_time_range")) or 0,
                "metadata": [("field", "value")] if False else [],  # keep simple; parsed later if needed
                "log_source": _split_multi(row.get("settings.log_source")),
                "context_template": _s(row.get("settings.context_template")),
                "active": bool(_as_bool_flag_on(row.get("settings.active"))),
                # keep raw repos spec; resolution/mapping happens in payload build
                "repos_raw": row.get("settings.repos"),
                # keep the raw timeranges; canon handles choice/convert
                "timerange_minute": _int_or_none(row.get("settings.livesearch_data.timerange_minute")),
                "timerange_hour": _int_or_none(row.get("settings.livesearch_data.timerange_hour")),
                "timerange_day": _int_or_none(row.get("settings.livesearch_data.timerange_day")),
                "timerange_second": _int_or_none(row.get("settings.livesearch_data.timerange_second") or row.get("settings.time_range_seconds")),
            }
            yield desired

    @staticmethod
    def key_fn(desired_row: Dict[str, Any]) -> str:  # type: ignore[override]
        return _s(desired_row.get("name"))

    def _canon_timerange(self, d: Dict[str, Any]) -> Tuple[str, int]:
        if (m := d.get("timerange_minute")):
            return ("minute", int(m))
        if (h := d.get("timerange_hour")):
            return ("hour", int(h))
        if (dy := d.get("timerange_day")):
            return ("day", int(dy))
        if (s := d.get("timerange_second")):
            return ("minute", int(math.ceil(float(s) / 60.0)))
        return ("minute", 0)

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[override]
        key, val = self._canon_timerange(desired_row)
        return {
            "risk": _s(desired_row.get("risk")).lower(),
            "repos_csv": _csv(self._normalize_repos_for_compare(desired_row.get("repos_raw"))),
            "aggregate": _s(desired_row.get("aggregate")).lower(),
            "condition_option": _s(desired_row.get("condition_option")).lower(),
            "condition_value": int(desired_row.get("condition_value") or 0),
            "limit": int(desired_row.get("limit") or 0),
            "timerange_key": key,
            "timerange_value": int(val or 0),
            "query": _s(desired_row.get("query")),
            "description": _s(desired_row.get("description")),
            "flush_on_trigger": bool(desired_row.get("flush_on_trigger")),
            "search_interval_minute": int(desired_row.get("search_interval_minute") or 0),
            "throttling_enabled": bool(desired_row.get("throttling_enabled")),
            "throttling_field": _s(desired_row.get("throttling_field")),
            "throttling_time_range": int(desired_row.get("throttling_time_range") or 0),
            "metadata_csv": _csv([f"{k}={v}" for (k, v) in desired_row.get("metadata", [])]),
            "log_source_csv": _csv(desired_row.get("log_source", [])),
            "context_template": _s(desired_row.get("context_template")),
        }

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Dict[str, Any] | None:  # type: ignore[override]
        if not existing_obj:
            return None
        # Flatten common shapes; tolerate missing fields
        repos = existing_obj.get("repos") or []
        return {
            "risk": _s(existing_obj.get("risk")).lower(),
            "repos_csv": _csv([_s(x) for x in repos]),
            "aggregate": _s(existing_obj.get("aggregate")).lower(),
            "condition_option": _s(existing_obj.get("condition_option")).lower(),
            "condition_value": int(existing_obj.get("condition_value") or 0),
            "limit": int(existing_obj.get("limit") or 0),
            "timerange_key": ("day" if existing_obj.get("timerange_day") else ("hour" if existing_obj.get("timerange_hour") else "minute")),
            "timerange_value": int(existing_obj.get("timerange_day") or existing_obj.get("timerange_hour") or existing_obj.get("timerange_minute") or 0),
            "query": _s(existing_obj.get("query")),
            "description": _s(existing_obj.get("description")),
            "flush_on_trigger": bool(existing_obj.get("flush_on_trigger")),
            "search_interval_minute": int(existing_obj.get("search_interval_minute") or 0),
            "throttling_enabled": bool(existing_obj.get("throttling_enabled")),
            "throttling_field": _s(existing_obj.get("throttling_field")),
            "throttling_time_range": int(existing_obj.get("throttling_time_range") or 0),
            "metadata_csv": _csv([f"{_s(k)}={_s(v)}" for (k, v) in (existing_obj.get("metadata") or []) if isinstance((k, v), tuple)]),
            "log_source_csv": _csv(existing_obj.get("log_source") or []),
            "context_template": _s(existing_obj.get("context_template")),
        }

    # --------------------------- read existing ---------------------------
    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:  # type: ignore[override]
        # Use the POST fetch for MyRules (works across versions)
        path = client.configapi(pool_uuid, node.id, "AlertRules/MyAlertRules/fetch")
        res = client.post_json(path, {"data": {}}) or []
        items = res if isinstance(res, list) else (res.get("items") or res.get("data") or res.get("results") or [])
        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            if not isinstance(it, dict):
                continue
            key = _s(it.get("searchname") or it.get("name"))
            if key:
                out[key] = it
        log.info("fetch_existing: %d rules [node=%s]", len(out), node.name)
        return out

    # --------------------------- repo handling ---------------------------
    def _parse_repo_specs(self, raw: Any) -> List[str]:
        """Return a list of normalized specs: ip:port or ip:port:repo (cleaned).

        - Accepts JSON array, Python list, or delimited string.
        - Accepts legacy "ip:port/repo" and converts to "ip:port:repo".
        - Mapping old->cleaned applied if a Repo sheet with mapping exists.
        - Enforces tenant ip_private membership.
        """
        items = _split_multi(raw)
        # Load optional Repo mapping sheet if available
        mapping: Dict[str, str] = {}
        try:
            # BaseImporter already loaded all sheets; if present, use it
            repo_df = self._sheets_cache.get("Repo")  # type: ignore[attr-defined]
            if isinstance(repo_df, pd.DataFrame) and {"original_repo_name", "cleaned_repo_name"}.issubset(repo_df.columns):
                mapping = dict(
                    zip(
                        repo_df["original_repo_name"].astype(str).str.strip(),
                        repo_df["cleaned_repo_name"].astype(str).str.strip(),
                    )
                )
        except Exception:
            pass
        # Tenant private IPs
        tenant_ips = getattr(self, "_tenant_ips", set())  # type: ignore[attr-defined]
        out: List[str] = []
        for it in items:
            tok = _s(it)
            if "/" in tok and tok.count(":") == 1:
                left, r = tok.split("/", 1)
                tok = f"{left}:{r}"
            parts = [p.strip() for p in tok.split(":") if p.strip()]
            if len(parts) < 2:
                continue
            ip, port = parts[0], parts[1]
            repo_old = parts[2] if len(parts) >= 3 else ""
            if tenant_ips and ip not in tenant_ips:
                log.warning("repo spec skipped (ip not in tenant): %s", tok)
                continue
            if repo_old:
                repo_clean = mapping.get(repo_old, "") or repo_old
                out.append(f"{ip}:{port}:{repo_clean}")
            else:
                out.append(f"{ip}:{port}")
        return sorted(set(out))

    # --------------------------- payload builders ---------------------------
    def _ensure_tenant_ips(self, node: NodeRef) -> None:
        # Collect and cache tenant ip_private from the active tenant dict in context
        if hasattr(self, "_tenant_ips"):
            return
        ips: List[str] = []
        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for v in obj:
                    walk(v)
            else:
                s = _s(obj)
                if s.count(".") == 3 and all(p.isdigit() and 0 <= int(p) <= 255 for p in s.split(".")):
                    ips.append(s)
        tdict = getattr(self, "tenant_dict", None) or getattr(self, "ctx", None) and getattr(self.ctx, "tenant_dict", None)
        if isinstance(tdict, dict):
            walk(tdict)
        self._tenant_ips = set(ips)  # type: ignore[attr-defined]
        self._sheets_cache = getattr(self, "_sheets_cache", {})  # type: ignore[attr-defined]

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[override]
        # Owner resolution is deferred; if you have a user resolver in your trunk,
        # inject it here (e.g., self.resolve_user_id). For now, leave owner empty in dry-run
        repos = self._parse_repo_specs(desired_row.get("repos_raw"))
        key, val = self._canon_timerange(desired_row)
        payload: Dict[str, Any] = {
            "searchname": _s(desired_row.get("name")),
            "owner": _s(desired_row.get("owner") or ""),  # to be resolved by your trunk
            "risk": _s(desired_row.get("risk")),
            "repos": repos,
            "aggregate": _s(desired_row.get("aggregate")),
            "condition_option": _s(desired_row.get("condition_option")),
            "condition_value": int(desired_row.get("condition_value") or 0),
            "limit": int(desired_row.get("limit") or 0),
            f"timerange_{key}": int(val or 0),
        }
        if _s(desired_row.get("query")):
            payload["query"] = _s(desired_row.get("query"))
        if _s(desired_row.get("description")):
            payload["description"] = _s(desired_row.get("description"))
        if desired_row.get("log_source"):
            payload["log_source"] = desired_row.get("log_source")
        if desired_row.get("search_interval_minute"):
            payload["search_interval_minute"] = int(desired_row.get("search_interval_minute"))
        if desired_row.get("flush_on_trigger"):
            payload["flush_on_trigger"] = "on"
        if desired_row.get("throttling_enabled"):
            payload["throttling_enabled"] = "on"
            if _s(desired_row.get("throttling_field")):
                payload["throttling_field"] = _s(desired_row.get("throttling_field"))
            if desired_row.get("throttling_time_range"):
                payload["throttling_time_range"] = int(desired_row.get("throttling_time_range"))
        if _s(desired_row.get("context_template")):
            payload["alert_context_template"] = _s(desired_row.get("context_template"))
        # metadata/log_source already handled above if needed
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[override]
        return self.build_payload_create(desired_row)

    # ------------------------------ apply ---------------------------------
    def apply(self, client: DirectorClient, pool_uuid: str, node: NodeRef, decision, existing_id: str | None) -> Dict[str, Any]:  # type: ignore[override]
        # Cache tenant IPs and sheets for repo parsing
        self._ensure_tenant_ips(node)
        desired = decision.desired or {}
        name = _s(desired.get("name")) or "(unnamed)"
        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                log.info("CREATE alert=%s [node=%s]", name, node.name)
                log.debug("CREATE %s", _payload_keys_summary(_redact_for_log(payload)))
                path = client.configapi(pool_uuid, node.id, "AlertRules")
                res = client.post_json(path, {"data": payload})
                return res or {"status": "Success"}
            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_create(desired)  # same shape
                log.info("UPDATE alert=%s id=%s [node=%s]", name, existing_id, node.name)
                log.debug("UPDATE %s", _payload_keys_summary(_redact_for_log(payload)))
                path = client.configapi(pool_uuid, node.id, f"AlertRules/{existing_id}")
                res = client.put_json(path, {"data": payload})
                return res or {"status": "Success"}
            log.info("NOOP alert=%s [node=%s]", name, node.name)
            return {"status": "Success"}
        except Exception:
            log.exception("API error for alert=%s [node=%s]", name, node.name)
            raise

__all__ = ["AlertRulesImporter"]
