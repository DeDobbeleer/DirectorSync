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
    """Importer for Logpoint Alert Rules (MyRules only).

    This class follows the standard v2 importer contract used by the existing
    importers. The pipeline is: load → validate → fetch_existing → diff → apply →
    converge_activation → report.
    """

    IMPORTER_NAME = "alert_rules"
    SHEET_NAME = "Alert"

    # Minimal required set per official API (Create/Edit)
    REQUIRED_API_FIELDS = {
        "searchname",
        "owner",
        "risk",
        "repos",
        "aggregate",
        "condition_option",
        "condition_value",
        "limit",
        # At least one of the timerange variants must be provided
        # (we accept minute/hour/day and convert from seconds if present)
    }

    # Columns we expect from the Alert sheet (best-effort; some are optional)
    EXPECTED_COLUMNS = [
        "name",
        "settings.active",
        "settings.description",
        "settings.extra_config.query",
        "settings.repos",
        "settings.risk",
        "settings.aggregate",
        "settings.condition.condition_option",
        "settings.condition.condition_value",
        "settings.livesearch_data.timerange_minute",
        "settings.livesearch_data.timerange_hour",
        "settings.livesearch_data.timerange_day",
        "settings.livesearch_data.timerange_second",
        "settings.livesearch_data.limit",
        "settings.log_source",
        "settings.assigned_to",
        "settings.attack_tag",
        "settings.metadata",
        "settings.is_context_template_enabled",
        "settings.context_template",
        "settings.flush_on_trigger",
        "settings.throttling_enabled",
        "settings.throttling_field",
        "settings.throttling_time_range",
        "settings.livesearch_data.search_interval_minute",
        # legacy/variants we *may* convert if present
        "settings.time_range_seconds",
    ]

    def run_for_nodes(self, *args: Any, **kwargs: Any) -> pd.DataFrame:  # noqa: D401 (kept for BaseImporter parity)
        """Entry point called by the CLI runner (kept for parity with v2)."""
        # 1) Load
        df = self._load_alert_sheet()
        # 2) Validate
        self._validate_input(df)
        # 3) Resolve supporting maps (tenant IPs, repo map, users, etc.)
        tenant_ips = self._collect_tenant_private_ips()
        repo_map = self._load_repo_clean_map()
        # 4) Fetch existing from Director
        existing = self._fetch_existing_myrules()
        index_by_name = {r.get("searchname") or r.get("name"): r for r in existing}
        # 5) Build plan rows
        plan: List[Dict[str, Any]] = []
        for idx, row in df.iterrows():
            try:
                plan_row = self._build_plan_row(row, tenant_ips, repo_map, index_by_name)
            except Exception as exc:  # robust isolation per-row
                LOG.exception("alert_rules: row %s failed during planning", idx)
                plan_row = {
                    "siem": self.ctx.siem_id,
                    "node": self.ctx.node_name,
                    "name": row.get("name", "<unknown>"),
                    "result": "skip",
                    "action": "Invalid row",
                    "status": "—",
                    "error": str(exc),
                }
            plan.append(plan_row)
        # 6) Apply plan
        applied = self._apply_plan(plan)
        # 7) Report as DataFrame (uniform columns)
        return pd.DataFrame(applied)

    # ---------------------------- Load & Validate ---------------------------- #

    def _load_alert_sheet(self) -> pd.DataFrame:
        """Load the Alert sheet as a DataFrame via BaseImporter helpers.

        This method uses BaseImporter.load_sheet if available; otherwise, it
        falls back to self.xlsx_reader which is what other importers already use.
        """
        df = self.load_sheet(self.SHEET_NAME)
        # Normalize columns that are sometimes missing in sample files
        for col in self.EXPECTED_COLUMNS:
            if col not in df.columns:
                df[col] = None
        return df

    def _validate_input(self, df: pd.DataFrame) -> None:
        """Validate minimal Alert sheet constraints.

        - name must be present (searchname)
        - required fields must be present or derivable
        - settings.repos must be parseable according to distributed spec
        """
        # name
        missing_name = df["name"].isna() | (df["name"].astype(str).str.strip() == "")
        if missing_name.any():
            LOG.warning("alert_rules: some rows are missing 'name' → will SKIP")
        # limit
        if "settings.livesearch_data.limit" not in df.columns:
            raise ValueError("Alert sheet is missing 'settings.livesearch_data.limit'")

    # -------------------------- Supporting datasets ------------------------- #

    def _collect_tenant_private_ips(self) -> List[str]:
        """Collect all private backend IPs for the active tenant from tenants.yml.

        The BaseImporter / context already parsed tenants.yml (used by other
        importers). We traverse the sub-tree of the selected tenant and collect
        any IPv4-looking tokens to form the allowed set.
        """
        tenant_dict = self.get_tenant_dict()  # provided by BaseImporter
        ips: List[str] = []
        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for v in obj:
                    walk(v)
            else:
                s = str(obj).strip()
                parts = s.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    ips.append(s)
        walk(tenant_dict)
        # de-dup + stable order
        uniq = sorted(set(ips))
        if not uniq:
            raise ValueError("No private backend IPs found for tenant (tenants.yml)")
        LOG.debug("alert_rules: tenant private IPs = %s", uniq)
        return uniq

    def _load_repo_clean_map(self) -> Dict[str, str]:
        """Load old→cleaned repo name map from the `Repo` sheet (XLSX)."""
        try:
            repo_df = self.load_sheet("Repo")
        except Exception as exc:  # pragma: no cover - guardrail
            LOG.warning("alert_rules: Repo sheet not found: %s", exc)
            return {}
        # Expect columns: original_repo_name, cleaned_repo_name
        if "original_repo_name" not in repo_df.columns or "cleaned_repo_name" not in repo_df.columns:
            LOG.warning("alert_rules: Repo sheet missing mapping columns; proceeding without mapping")
            return {}
        mapping = (
            repo_df[["original_repo_name", "cleaned_repo_name"]]
            .dropna(how="any")
            .assign(original_repo_name=lambda d: d["original_repo_name"].astype(str).str.strip())
            .assign(cleaned_repo_name=lambda d: d["cleaned_repo_name"].astype(str).str.strip())
        )
        m = dict(zip(mapping["original_repo_name"], mapping["cleaned_repo_name"]))
        LOG.debug("alert_rules: loaded %d repo name mappings", len(m))
        return m

    # --------------------------- Director API IO ---------------------------- #

    def _fetch_existing_myrules(self) -> List[Dict[str, Any]]:
        """Fetch MyRules from Director to build the current state for diffing."""
        client = self.director_client
        payload = {"data": {}}  # optional filters could be added later
        resp = client.post_json(
            client.configapi(self.ctx.pool_uuid, self.ctx.node_id, "AlertRules/MyAlertRules/fetch"),
            json=payload,
        )
        rules = resp or []
        if not isinstance(rules, list):
            LOG.warning("alert_rules: unexpected fetch response type: %s", type(rules))
            rules = []
        return rules

    def _create_rule(self, data: Dict[str, Any]) -> Dict[str, Any]:
        client = self.director_client
        url = client.configapi(self.ctx.pool_uuid, self.ctx.node_id, "AlertRules")
        return client.post_json(url, json={"data": data}) or {}

    def _update_rule(self, rule_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        client = self.director_client
        url = client.configapi(self.ctx.pool_uuid, self.ctx.node_id, f"AlertRules/{rule_id}")
        return client.put_json(url, json={"data": data}) or {}

    def _activate_rule(self, rule_id: str) -> None:
        client = self.director_client
        url = client.configapi(self.ctx.pool_uuid, self.ctx.node_id, f"AlertRules/{rule_id}/activate")
        client.post_json(url, json={"data": {}})

    def _deactivate_rule(self, rule_id: str) -> None:
        client = self.director_client
        url = client.configapi(self.ctx.pool_uuid, self.ctx.node_id, f"AlertRules/{rule_id}/deactivate")
        client.post_json(url, json={"data": {}})

    # ------------------------------- Planning ------------------------------- #

    def _build_plan_row(
        self,
        row: pd.Series,
        tenant_ips: List[str],
        repo_map: Dict[str, str],
        existing_by_name: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build one plan row from a single XLSX line.

        Returns a dict with the standard report columns.
        """
        name = str(row.get("name") or "").strip()
        if not name:
            return self._report_skip(name, "Missing 'name' (searchname)")

        # Owner (required) → resolve via resolvers or tenant default
        owner_id = self.resolve_user_id(row)
        if not owner_id:
            return self._report_skip(name, "Missing or unresolved owner user ID")

        # Required fields
        risk = self._require_str(row, "settings.risk", name)
        aggregate = self._require_str(row, "settings.aggregate", name)
        cond_opt = self._require_str(row, "settings.condition.condition_option", name)
        cond_val = self._require_int(row, "settings.condition.condition_value", name)
        limit = self._require_int(row, "settings.livesearch_data.limit", name, min_value=1)

        # Timerange (accept any minute|hour|day or convert from seconds)
        timerange = self._pick_timerange(row)
        if not timerange:
            return self._report_skip(name, "Missing timerange (minute/hour/day/second)")

        # Parse and normalize repos for this tenant
        repos_value = row.get("settings.repos")
        repo_specs = self._parse_repo_specs(repos_value)
        if not repo_specs:
            return self._report_skip(name, "No repos provided in settings.repos")

        normalized_repos: List[str] = []
        for spec in repo_specs:
            if spec.backend_ip not in tenant_ips:
                return self._report_skip(name, f"Backend IP {spec.backend_ip} not in tenant ip_private")
            # scope
            if spec.repo_old:
                cleaned = repo_map.get(spec.repo_old, "")
                if not cleaned:
                    return self._report_skip(name, f"Repo mapping missing for '{spec.repo_old}'")
                spec.repo_clean = cleaned
                spec.scope = "specific"
            else:
                spec.scope = "all"
            normalized_repos.append(spec.normalized())

        # Optional fields
        data: Dict[str, Any] = {
            "searchname": name,
            "owner": owner_id,
            "risk": risk,
            "aggregate": aggregate,
            "condition_option": cond_opt,
            "condition_value": cond_val,
            "limit": limit,
            "repos": normalized_repos,
        }
        data.update(timerange)

        # Optional mapping helpers
        q = (row.get("settings.extra_config.query") or row.get("settings.livesearch_data.query") or "").strip()
        if q:
            data["query"] = q
        desc = (row.get("settings.description") or "").strip()
        if desc:
            data["description"] = desc
        log_src = row.get("settings.log_source")
        if isinstance(log_src, (list, tuple)):
            data["log_source"] = list(log_src)
        assigned = self.resolve_assigned_user_id(row)
        if assigned:
            data["assigned_to"] = assigned
        attack_ids = self.resolve_attack_tags(row)
        if attack_ids:
            data["attack_tag"] = attack_ids
        meta = row.get("settings.metadata")
        if isinstance(meta, list):
            data["metadata"] = meta
        if self._truthy(row.get("settings.is_context_template_enabled")):
            data["apply_jinja_template"] = "on"
        ctx_tpl = (row.get("settings.context_template") or "").strip()
        if ctx_tpl:
            data["alert_context_template"] = ctx_tpl
        if self._truthy(row.get("settings.flush_on_trigger")):
            data["flush_on_trigger"] = "on"
        if self._truthy(row.get("settings.throttling_enabled")):
            data["throttling_enabled"] = "on"
            field = (row.get("settings.throttling_field") or "").strip()
            trange = row.get("settings.throttling_time_range")
            if not field or not isinstance(trange, (int, float)):
                return self._report_skip(name, "Throttling enabled but field/time_range missing")
            data["throttling_field"] = field
            data["throttling_time_range"] = int(trange)
        s_int = row.get("settings.livesearch_data.search_interval_minute")
        if isinstance(s_int, (int, float)) and s_int > 0:
            data["search_interval_minute"] = int(s_int)

        # Activation desired state
        active_target = self._truthy(row.get("settings.active"))

        # Diff against existing
        ex = existing_by_name.get(name)
        if not ex:
            action = "create"
            rule_id = None
        else:
            rule_id = ex.get("id") or ex.get("_id") or ex.get("uuid")
            if self._is_identical(ex, data):
                return self._report_result(name, "noop", "Identical subset", status="—")
            action = "update"

        return {
            "siem": self.ctx.siem_id,
            "node": self.ctx.node_name,
            "name": name,
            "payload": data,
            "active_target": active_target,
            "existing_id": rule_id,
            "result": action,  # provisional: create/update
            "action": "Not applied yet",
            "status": "Pending",
            "error": "—",
        }

    # ----------------------------- Apply & Report --------------------------- #

    def _apply_plan(self, plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for item in plan:
            if item.get("result") in {"noop", "skip"}:
                out.append(item)
                continue
            name = item["name"]
            data = item["payload"]
            active_target: bool = bool(item.get("active_target"))
            try:
                if item.get("result") == "create":
                    resp = self._create_rule(data)
                    rule_id = resp.get("id") or resp.get("_id") or resp.get("uuid")
                    item["existing_id"] = rule_id
                    item["action"] = "Created"
                else:
                    rule_id = item.get("existing_id")
                    if not rule_id:
                        raise RuntimeError("Missing existing rule id for update")
                    self._update_rule(rule_id, data)
                    item["action"] = "Updated"
                # converge activation
                if rule_id:
                    self._converge_activation(rule_id, active_target)
                item["status"] = "OK"
                item["result"] = item["result"]  # keep create/update
            except Exception as exc:
                LOG.exception("alert_rules: apply failed for '%s'", name)
                item["status"] = "Failed"
                item["error"] = str(exc)
                item["result"] = "error"
            out.append(item)
        return out

    def _converge_activation(self, rule_id: str, target_active: bool) -> None:
        if target_active is None:
            return
        # We use fire-and-forget; if idempotence is needed, fetch-or-passively ignore errors
        try:
            if target_active:
                self._activate_rule(rule_id)
            else:
                self._deactivate_rule(rule_id)
        except Exception:
            LOG.warning("alert_rules: activation convergence failed for id=%s", rule_id)

    # ------------------------------ Utilities ------------------------------- #

    def _report_skip(self, name: str, reason: str) -> Dict[str, Any]:
        return {
            "siem": self.ctx.siem_id,
            "node": self.ctx.node_name,
            "name": name,
            "result": "skip",
            "action": reason,
            "status": "—",
            "error": "—",
        }

    def _report_result(self, name: str, result: str, action: str, status: str = "—") -> Dict[str, Any]:
        return {
            "siem": self.ctx.siem_id,
            "node": self.ctx.node_name,
            "name": name,
            "result": result,
            "action": action,
            "status": status,
            "error": "—",
        }

    @staticmethod
    def _require_str(row: pd.Series, col: str, name: str) -> str:
        val = (row.get(col) or "").strip()
        if not val:
            raise ValueError(f"Row '{name}': missing required column '{col}'")
        return val

    @staticmethod
    def _require_int(row: pd.Series, col: str, name: str, min_value: Optional[int] = None) -> int:
        raw = row.get(col)
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            raise ValueError(f"Row '{name}': missing required integer '{col}'")
        try:
            val = int(raw)
        except Exception as exc:  # pragma: no cover
            raise ValueError(f"Row '{name}': invalid integer in '{col}': {raw}") from exc
        if min_value is not None and val < min_value:
            raise ValueError(f"Row '{name}': '{col}' must be >= {min_value}")
        return val

    @staticmethod
    def _truthy(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        return s in {"1", "true", "on", "yes", "y"}

    def _pick_timerange(self, row: pd.Series) -> Dict[str, int]:
        # prefer explicit minute/hour/day
        minute = row.get("settings.livesearch_data.timerange_minute")
        hour = row.get("settings.livesearch_data.timerange_hour")
        day = row.get("settings.livesearch_data.timerange_day")
        if isinstance(minute, (int, float)) and minute > 0:
            return {"timerange_minute": int(minute)}
        if isinstance(hour, (int, float)) and hour > 0:
            return {"timerange_hour": int(hour)}
        if isinstance(day, (int, float)) and day > 0:
            return {"timerange_day": int(day)}
        # fallback: seconds → minutes (ceil)
        sec = row.get("settings.livesearch_data.timerange_second") or row.get("settings.time_range_seconds")
        if isinstance(sec, (int, float)) and sec > 0:
            minutes = math.ceil(float(sec) / 60.0)
            return {"timerange_minute": int(minutes)}
        return {}

    def _parse_repo_specs(self, value: Any) -> List[RepoSpec]:
        """Parse settings.repos according to the distributed spec.

        Accepts JSON array string, Python list, or delimited string with ',', ';', '|', or newlines.
        Items are in the form "ip:port[:old_repo_name]".
        """
        if value is None:
            return []
        items: List[str]
        if isinstance(value, list):
            items = [str(x).strip() for x in value if str(x).strip()]
        else:
            s = str(value).strip()
            # Try JSON array first
            try:
                maybe = json.loads(s)
                if isinstance(maybe, list):
                    items = [str(x).strip() for x in maybe if str(x).strip()]
                else:
                    items = [s]
            except Exception:
                # Fallback: split
                for sep in ["\n", "|", ";", ","]:
                    if sep in s:
                        items = [p.strip() for p in s.split(sep) if p.strip()]
                        break
                else:
                    items = [s]
        specs: List[RepoSpec] = []
        for it in items:
            ip, port, repo_old = self._split_repo_token(it)
            specs.append(RepoSpec(backend_ip=ip, port=port, repo_old=repo_old))
        return specs

    @staticmethod
    def _split_repo_token(token: str) -> Tuple[str, str, str]:
        # Accept either ip:port:repo or ip:port/repo (legacy)
        tok = token.strip()
        if "/" in tok and tok.count(":") == 1:
            left, repo = tok.split("/", 1)
            ip, port = left.split(":", 1)
            return ip.strip(), port.strip(), repo.strip()
        parts = tok.split(":")
        if len(parts) >= 3:
            return parts[0].strip(), parts[1].strip(), parts[2].strip()
        if len(parts) == 2:
            return parts[0].strip(), parts[1].strip(), ""
        if len(parts) == 1:
            return parts[0].strip(), "", ""
        return "", "", ""

    def _is_identical(self, existing: Dict[str, Any], desired: Dict[str, Any]) -> bool:
        """Compare only the managed subset of fields for idempotence.

        We ignore system-managed fields and anything out-of-scope (e.g., sharing, notifications).
        """
        # Build comparable dicts
        def pick(d: Dict[str, Any]) -> Dict[str, Any]:
            keys = {
                "searchname",
                "owner",
                "risk",
                "repos",
                "aggregate",
                "condition_option",
                "condition_value",
                "limit",
                "timerange_minute",
                "timerange_hour",
                "timerange_day",
                "query",
                "description",
                "log_source",
                "assigned_to",
                "attack_tag",
                "metadata",
                "apply_jinja_template",
                "alert_context_template",
                "flush_on_trigger",
                "throttling_enabled",
                "throttling_field",
                "throttling_time_range",
                "search_interval_minute",
            }
            return {k: d.get(k) for k in keys if k in d}

        a = pick(existing)
        b = pick(desired)
        # repos can be returned unsorted; compare as sets while keeping determinism for other fields
        def normalize_repos(x: Any) -> List[str]:
            if isinstance(x, list):
                return sorted(str(i) for i in x)
            return []
        a_repos = normalize_repos(a.pop("repos", None))
        b_repos = normalize_repos(b.pop("repos", None))
        return a == b and a_repos == b_repos


# ------------------------------ Registry hook ------------------------------ #
# If your project uses an automatic registry, ensure this class is exposed.
# For example, lp_tenant_importer_v2/importers/__init__.py should import this
# symbol or register it in the dynamic registry.

__all__ = ["AlertRulesImporter"]
