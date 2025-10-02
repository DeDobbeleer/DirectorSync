from __future__ import annotations
"""AlertRules importer (DirectorSync v2)

Follows the SAME pipeline and style as other importers (e.g. Devices/Repos):
  - BaseImporter drives: load → validate → fetch → diff → plan → apply
  - We implement only the hooks: validate, iter_desired, key_fn, canon_*, fetch_existing,
    build_payload_*, apply.
Scope: MyRules only (NOOP/CREATE/UPDATE/SKIP). No sharing/ownership transfer, no notifications.
"""
import logging
import math
from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd

from .base import BaseImporter, NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError

log = logging.getLogger(__name__)

RESOURCE = "AlertRules"  # Director API resource path

# ------------------------------- helpers ------------------------------------

def _s(v: Any) -> str:
    if v is None:
        return ""
    try:
        if pd.isna(v):  # type: ignore[attr-defined]
            return ""
    except Exception:
        pass
    return str(v).strip()


def _int_or_none(v: Any) -> int | None:
    try:
        if v is None:
            return None
        if isinstance(v, (int, float)):
            return int(v)
        s = _s(v)
        return int(s) if s else None
    except Exception:
        return None


def _split_multi(cell: Any, seps: Tuple[str, ...] = ("|", ",", "")) -> List[str]:
    raw = _s(cell)
    if not raw:
        return []
    canon = raw
    for s in seps[1:]:
        canon = canon.replace(s, seps[0])
    parts = [p.strip() for p in canon.split(seps[0]) if p.strip()]
    # also accept JSON-ish arrays without full json.loads (defensive)
    if len(parts) == 1 and parts[0].startswith("[") and parts[0].endswith("]"):
        mid = parts[0].strip("[] ")
        parts = [p.strip().strip('"') for p in mid.split(",") if p.strip()]
    return parts


def _normalize_repos(raw: Any, repo_map_df: pd.DataFrame | None) -> List[str]:
    """Return normalized repo specs as list of strings: `ip:port` or `ip:port:Repo_CLEANED`.

    - Accepts list/CSV/pipe/newline or legacy `ip:port/repo` and converts to colon form.
    - If a Repo sheet is provided with `original_repo_name` → `cleaned_repo_name`, map it.
    (Tenant IP filtering is intentionally not enforced here to stay consistent with
     other importers' XLSX-only parsing at this stage. If needed later, do it in apply.)
    """
    items = _split_multi(raw)
    mapping: Dict[str, str] = {}
    if isinstance(repo_map_df, pd.DataFrame) and {"original_repo_name", "cleaned_repo_name"}.issubset(repo_map_df.columns):
        mapping = dict(
            zip(
                repo_map_df["original_repo_name"].astype(str).str.strip(),
                repo_map_df["cleaned_repo_name"].astype(str).str.strip(),
            )
        )
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
        if repo_old:
            repo_clean = mapping.get(repo_old, repo_old)
            out.append(f"{ip}:{port}:{repo_clean}")
        else:
            out.append(f"{ip}:{port}")
    return sorted(set(out))


# ----------------------------- importer --------------------------------------

class AlertRulesImporter(BaseImporter):
    """Importer for **AlertRules/MyRules**.

    Sheet: "Alert"
    Required columns: name, settings.risk, settings.aggregate,
        settings.condition.condition_option, settings.condition.condition_value,
        settings.livesearch_data.limit, settings.repos,
        and one of timerange columns (minute/hour/day/second or time_range_seconds).
    """

    resource_name: str = "alert_rules"
    sheet_names = ("Alert",)
    required_columns = tuple()  # custom validation below (like other modules)

    # Stable subset for diffing (order-insensitive fields normalized in canon_*):
    compare_keys = (
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
        "log_source_csv",
        "context_template",
    )

    # ---------------------------- validation ----------------------------
    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        if "Alert" not in sheets:
            raise ValidationError("Missing required sheet: Alert")
        df = sheets["Alert"]
        def need(col: str) -> None:
            if col not in df.columns:
                raise ValidationError(f"Alert: missing required column '{col}'")
        need("name")
        need("settings.risk")
        need("settings.aggregate")
        need("settings.condition.condition_option")
        need("settings.condition.condition_value")
        need("settings.livesearch_data.limit")
        need("settings.repos")
        if not any(c in df.columns for c in (
            "settings.livesearch_data.timerange_minute",
            "settings.livesearch_data.timerange_hour",
            "settings.livesearch_data.timerange_day",
            "settings.livesearch_data.timerange_second",
            "settings.time_range_seconds",
        )):
            raise ValidationError("Alert: missing timerange column (minute/hour/day/second)")

    # -------------------------- XLSX → desired ---------------------------
    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets["Alert"].copy()
        # Optional mapping sheet for repo names
        repo_map_df: pd.DataFrame | None = sheets.get("Repo") if isinstance(sheets.get("Repo"), pd.DataFrame) else None
        for _, row in df.iterrows():
            name = _s(row.get("name"))
            if not name:
                continue
            # Timerange normalization happens later
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
                "flush_on_trigger": _s(row.get("settings.flush_on_trigger")).lower() in {"on", "true", "1", "yes"},
                "throttling_enabled": _s(row.get("settings.throttling_enabled")).lower() in {"on", "true", "1", "yes"},
                "throttling_field": _s(row.get("settings.throttling_field")),
                "throttling_time_range": _int_or_none(row.get("settings.throttling_time_range")) or 0,
                "log_source": _split_multi(row.get("settings.log_source")),
                "context_template": _s(row.get("settings.context_template")),
                "active": _s(row.get("settings.active")).lower() in {"on", "true", "1", "yes"},
                # repos normalized here (mapping applied if sheet present)
                "repos_norm": _normalize_repos(row.get("settings.repos"), repo_map_df),
                # raw timeranges retained for conversion
                "timerange_minute": _int_or_none(row.get("settings.livesearch_data.timerange_minute")),
                "timerange_hour": _int_or_none(row.get("settings.livesearch_data.timerange_hour")),
                "timerange_day": _int_or_none(row.get("settings.livesearch_data.timerange_day")),
                "timerange_second": _int_or_none(row.get("settings.livesearch_data.timerange_second") or row.get("settings.time_range_seconds")),
            }
            yield desired

    # ------------------------ canonicalization (diff) ------------------------
    @staticmethod
    def key_fn(desired_row: Dict[str, Any]) -> str:
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

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        key, val = self._canon_timerange(desired_row)
        return {
            "risk": _s(desired_row.get("risk")).lower(),
            "repos_csv": ",".join(sorted([_s(x) for x in desired_row.get("repos_norm", [])])),
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
            "log_source_csv": ",".join(sorted([_s(x) for x in desired_row.get("log_source", [])])),
            "context_template": _s(desired_row.get("context_template")),
        }

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if not existing_obj:
            return None
        repos = existing_obj.get("repos") or []
        # Timerange can be represented via minute/hour/day fields
        t_key = (
            "day" if existing_obj.get("timerange_day") else (
                "hour" if existing_obj.get("timerange_hour") else "minute"
            )
        )
        t_val = int(existing_obj.get(f"timerange_{t_key}") or 0)
        return {
            "risk": _s(existing_obj.get("risk")).lower(),
            "repos_csv": ",".join(sorted([_s(x) for x in repos if _s(x)])),
            "aggregate": _s(existing_obj.get("aggregate")).lower(),
            "condition_option": _s(existing_obj.get("condition_option")).lower(),
            "condition_value": int(existing_obj.get("condition_value") or 0),
            "limit": int(existing_obj.get("limit") or 0),
            "timerange_key": t_key,
            "timerange_value": t_val,
            "query": _s(existing_obj.get("query")),
            "description": _s(existing_obj.get("description")),
            "flush_on_trigger": bool(existing_obj.get("flush_on_trigger")),
            "search_interval_minute": int(existing_obj.get("search_interval_minute") or 0),
            "throttling_enabled": bool(existing_obj.get("throttling_enabled")),
            "throttling_field": _s(existing_obj.get("throttling_field")),
            "throttling_time_range": int(existing_obj.get("throttling_time_range") or 0),
            "log_source_csv": ",".join(sorted([_s(x) for x in (existing_obj.get("log_source") or [])])),
            "context_template": _s(existing_obj.get("context_template")),
        }

    # ----------------------------- read existing -----------------------------
    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        """Return {searchname -> object} using MyRules fetch (tolerate shapes)."""
        path = client.configapi(pool_uuid, node.id, f"{RESOURCE}/MyAlertRules/fetch")
        data = client.post_json(path, {"data": {}}) or []
        if isinstance(data, dict):
            items = data.get("items") or data.get("data") or data.get("results") or []
        elif isinstance(data, list):
            items = data
        else:
            items = []
        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            if not isinstance(it, dict):
                continue
            key = _s(it.get("searchname") or it.get("name"))
            if key:
                out[key] = it
        log.info("fetch_existing: %d rules [node=%s]", len(out), node.name)
        return out

    # --------------------------- payload builders ----------------------------
    def _timerange_kv(self, d: Dict[str, Any]) -> Tuple[str, int]:
        k, v = self._canon_timerange(d)
        return k, v

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        k, v = self._timerange_kv(desired_row)
        payload: Dict[str, Any] = {
            "searchname": _s(desired_row.get("name")),
            "owner": _s(desired_row.get("owner") or ""),  # owner resolution may be handled elsewhere
            "risk": _s(desired_row.get("risk")),
            "repos": desired_row.get("repos_norm", []),
            "aggregate": _s(desired_row.get("aggregate")),
            "condition_option": _s(desired_row.get("condition_option")),
            "condition_value": int(desired_row.get("condition_value") or 0),
            "limit": int(desired_row.get("limit") or 0),
            f"timerange_{k}": int(v or 0),
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
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        return self.build_payload_create(desired_row)

    # -------------------------------- apply ----------------------------------
    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        desired = decision.desired or {}
        name = _s(desired.get("name")) or "(unnamed)"
        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                log.info("CREATE alert=%s [node=%s]", name, node.name)
                log.debug("CREATE payload=%s", payload)
                return client.create_resource(pool_uuid, node.id, RESOURCE, payload)
            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id})
                log.info("UPDATE alert=%s id=%s [node=%s]", name, existing_id, node.name)
                log.debug("UPDATE payload=%s", payload)
                return client.update_resource(pool_uuid, node.id, RESOURCE, existing_id, payload)
            log.info("NOOP alert=%s [node=%s]", name, node.name)
            return {"status": "Success"}
        except Exception:
            log.exception("API error for alert=%s [node=%s]", name, node.name)
            raise


__all__ = ["AlertRulesImporter"]
