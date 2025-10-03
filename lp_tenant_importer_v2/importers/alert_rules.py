from __future__ import annotations
"""AlertRules importer (DirectorSync v2) — clean implementation.

- Matches BaseImporter hooks used elsewhere in the repo.
- Resolves `owner` by listing Users on the node and mapping name/email/username -> user id.
- Skips rows with unknown owner (no API call).
- Ensures correct payload types for Director API (AlertRules).
"""
from typing import Any, Dict, Iterable, List, Tuple
import logging
import math

import pandas as pd

from .base import BaseImporter, NodeRef, ValidationError
from ..core.director_client import DirectorClient

log = logging.getLogger(__name__)

RESOURCE = "AlertRules"


def _s(v: Any) -> str:
    return str(v).strip() if v is not None else ""


class AlertRulesImporter(BaseImporter):
    """Importer for **AlertRules/MyRules**.

    Sheets expected: `Alert` with columns at least:
      - name
      - settings.risk
      - settings.aggregate
      - settings.condition.condition_option
      - settings.condition.condition_value
      - settings.livesearch_data.limit
      - settings.repos
      - one of timerange columns (minute/hour/day/second or time_range_seconds).
    """
    # minimal BaseImporter metadata (kept for consistency if used)
    resource_name: str = "alert_rules"
    sheet_names = ("Alert",)
    required_columns = tuple()  # custom validation below

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
        if not any(
            c in df.columns
            for c in (
                "settings.livesearch_data.timerange_minute",
                "settings.livesearch_data.timerange_hour",
                "settings.livesearch_data.timerange_day",
                "settings.livesearch_data.timerange_second",
                "settings.time_range_seconds",
            )
        ):
            raise ValidationError(
                "Alert: missing timerange column (minute/hour/day/second)"
            )

    # ------------------------------ desired ------------------------------
    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:  # type: ignore[override]
        df = sheets["Alert"].fillna("")
        for _, r in df.iterrows():
            d: Dict[str, Any] = {
                "name": _s(r.get("name")),
                "owner": (_s(r.get("settings.user")) or _s(r.get("owner"))),
                "risk": _s(r.get("settings.risk")).lower(),
                "aggregate": _s(r.get("settings.aggregate")).lower(),
                "condition_option": _s(r.get("settings.condition.condition_option")).lower(),
                "condition_value": int(r.get("settings.condition.condition_value") or 0),
                "limit": int(r.get("settings.livesearch_data.limit") or 0),
                "timerange_minute": _s(r.get("settings.livesearch_data.timerange_minute")),
                "timerange_hour": _s(r.get("settings.livesearch_data.timerange_hour")),
                "timerange_day": _s(r.get("settings.livesearch_data.timerange_day")),
                "timerange_second": _s(r.get("settings.livesearch_data.timerange_second")),
                "time_range_seconds": _s(r.get("settings.time_range_seconds")),
                "repos": [s.strip() for s in _s(r.get("settings.repos")).split(",") if s.strip()],
                "log_source": [s.strip() for s in _s(r.get("settings.log_source")).split(",") if s.strip()],
                "searchname": _s(r.get("settings.searchname")) or _s(r.get("name")),
                "flush_on_trigger": bool(r.get("settings.flush_on_trigger")),
                "throttling_enabled": bool(r.get("settings.throttling_enabled")),
                "throttling_field": _s(r.get("settings.throttling_field")),
                "throttling_time_range": _s(r.get("settings.throttling_time_range")),
                "search_interval_minute": _s(r.get("settings.search_interval_minute")),
                "context_template": _s(r.get("settings.alert_context_template")) or _s(r.get("settings.context_template")),
            }
            # Normalizations
            d["repos_norm"] = [x for x in d["repos"] if x]
            d["log_source_norm"] = [x for x in d["log_source"] if x]
            # Compute timerange fallback from seconds
            if d.get("time_range_seconds") and not any(
                d.get(k) for k in ("timerange_minute", "timerange_hour", "timerange_day", "timerange_second")
            ):
                try:
                    sec = int(d["time_range_seconds"])
                    d["timerange_second"] = str(sec)
                except Exception:
                    pass
            yield d

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
            f"timerange_{key}": val,
            "searchname": _s(desired_row.get("searchname")),
        }

    # ------------------------------ users cache ------------------------------
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Users cache: node_id -> { lookup_key_lower: user_id }
        self._users_cache: dict[str, dict[str, str]] = {}
        self._users_loaded: set[str] = set()

    def _get_profile_option_default_owner(self) -> str:
        """Read resources/profiles.yml and return profiles.AlertRules.options.default_owner if present."""
        import os
        try:
            import yaml  # type: ignore
        except Exception:
            return ""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # lp_tenant_importer_v2/
        res_path = os.path.join(base_dir, "resources", "profiles.yml")
        if not os.path.exists(res_path):
            return ""
        try:
            with open(res_path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            prof = (data.get("profiles") or {}).get("AlertRules") or {}
            opts = prof.get("options") or {}
            val = opts.get("default_owner") or ""
            return val.strip() if isinstance(val, str) else ""
        except Exception:
            return ""

    def _load_users_for_node(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        node_key = node.id
        if node_key in self._users_loaded:
            return
        try:
            raw = client.list_resource(pool_uuid, node.id, "Users") or []
        except Exception:
            raw = []
        idx: dict[str, str] = {}
        for u in raw:
            uid = _s(u.get("id"))
            if not uid:
                continue
            for k in (
                u.get("id"),
                u.get("username"),
                (u.get("display_name") or u.get("name")),
                (u.get("email") or u.get("emailAddress")),
            ):
                key = _s(k).lower()
                if key:
                    idx[key] = uid
        self._users_cache[node_key] = idx
        self._users_loaded.add(node_key)
        log.debug("Users cache loaded: node=%s size=%d", node.name, len(idx))

    def _resolve_owner_id(self, client: DirectorClient, pool_uuid: str, node: NodeRef, owner_raw: str) -> str:
        """Return a valid Director user id for this node (case-insensitive resolution), or '' if not found."""
        self._load_users_for_node(client, pool_uuid, node)
        lookup = _s(owner_raw)
        if not lookup:
            return ""
        idx = self._users_cache.get(node.id) or {}
        # Direct exact id
        if lookup in idx.values():
            return lookup
        # Case-insensitive by common keys (username/display_name/email)
        return idx.get(lookup.lower(), "")

    # ------------------------------ fetching ------------------------------
    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:  # type: ignore[override]
        """Return existing rules by name for diffing (list_resource)."""
        try:
            items = client.list_resource(pool_uuid, node.id, RESOURCE) or []
        except Exception as exc:
            log.warning("fetch_existing failed [node=%s]: %s", node.name, exc)
            items = []
        existing: Dict[str, Dict[str, Any]] = {}
        for it in items:
            nm = _s(it.get("name") or it.get("searchname"))
            if nm:
                existing[nm] = it
        log.info("fetch_existing: %d rules [node=%s]", len(existing), node.name)
        return existing

    # ------------------------------ payloads ------------------------------
    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """Build payload for AlertRules.create (types validated)."""
        # Resolve and validate owner (must be a string id here)
        owner_raw = desired_row.get("owner")
        if isinstance(owner_raw, (list, tuple)) and owner_raw:
            owner_id = _s(owner_raw[0])
        else:
            owner_id = _s(owner_raw)
        if not owner_id:
            owner_id = self._get_profile_option_default_owner()
        if not owner_id:
            raise ValidationError("owner is required and could not be resolved from context or profiles.yml")

        # Validate repos
        repos = desired_row.get("repos_norm", [])
        if not isinstance(repos, list) or not repos or not all(isinstance(x, str) and x.strip() for x in repos):
            raise ValidationError("repos must be a non-empty list of strings")

        payload: Dict[str, Any] = {
            "name": _s(desired_row.get("name")),
            "owner": owner_id,
            "risk": _s(desired_row.get("risk")).lower(),
            "aggregate": _s(desired_row.get("aggregate")).lower(),
            "condition_option": _s(desired_row.get("condition_option")).lower(),
            "condition_value": int(desired_row.get("condition_value") or 0),
            "limit": int(desired_row.get("limit") or 0),
            "repos": repos,
            "searchname": _s(desired_row.get("searchname")) or _s(desired_row.get("name")),
        }

        # timerange fields
        key, val = self._canon_timerange(desired_row)
        if val:
            payload[f"timerange_{key}"] = val

        # log_source optional
        if desired_row.get("log_source_norm"):
            payload["log_source"] = desired_row.get("log_source_norm")

        # search interval
        if desired_row.get("search_interval_minute"):
            payload["search_interval_minute"] = int(desired_row.get("search_interval_minute"))

        # switches
        if desired_row.get("flush_on_trigger"):
            payload["flush_on_trigger"] = "on"
        if desired_row.get("throttling_enabled"):
            payload["throttling_enabled"] = "on"
            if _s(desired_row.get("throttling_field")):
                payload["throttling_field"] = _s(desired_row.get("throttling_field"))
            if desired_row.get("throttling_time_range"):
                payload["throttling_time_range"] = int(desired_row.get("throttling_time_range"))

        # context template
        if _s(desired_row.get("context_template")):
            payload["alert_context_template"] = _s(desired_row.get("context_template"))

        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_row: Dict[str, Any]) -> Dict[str, Any]:
        """Build payload for AlertRules.update (reuse create builder)."""
        return self.build_payload_create(desired_row)

    # ------------------------------ apply ------------------------------
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

        # Resolve owner -> user id BEFORE calling API (CREATE/UPDATE only)
        if decision.op in ("CREATE", "UPDATE"):
            owner_input = desired.get("owner") or self._get_profile_option_default_owner()
            owner_resolved = self._resolve_owner_id(client, pool_uuid, node, owner_input or "")
            if not owner_resolved:
                log.warning("SKIP %s alert=%s [node=%s] reason=Unknown owner '%s' (no API call)",
                            decision.op, name, node.name, owner_input)
                return {"status": "Skipped", "reason": f"Unknown owner '{owner_input}'"}
            if owner_input != owner_resolved:
                log.info("owner resolved: '%s' -> id=%s [node=%s]", owner_input, owner_resolved, node.name)
            desired["owner"] = owner_resolved

        try:
            if decision.op == "CREATE":
                try:
                    payload = self.build_payload_create(desired)
                except ValidationError as ve:
                    log.warning("SKIP CREATE alert=%s [node=%s] reason=%s (no API call)", name, node.name, ve)
                    return {"status": "Skipped", "reason": str(ve)}
                log.info("CREATE alert=%s [node=%s]", name, node.name)
                log.debug("CREATE payload=%s", payload)
                return client.create_resource(pool_uuid, node.id, RESOURCE, payload)

            if decision.op == "UPDATE" and existing_id:
                try:
                    payload = self.build_payload_update(desired, {"id": existing_id})
                except ValidationError as ve:
                    log.warning("SKIP UPDATE alert=%s id=%s [node=%s] reason=%s (no API call)",
                                name, existing_id, node.name, ve)
                    return {"status": "Skipped", "reason": str(ve)}
                log.info("UPDATE alert=%s id=%s [node=%s]", name, existing_id, node.name)
                log.debug("UPDATE payload=%s", payload)
                return client.update_resource(pool_uuid, node.id, RESOURCE, existing_id, payload)

            log.info("NOOP alert=%s [node=%s]", name, node.name)
            return {"status": "Success"}

        except Exception as exc:
            # Convert HTTP/errors to a clean per-row result without stacktrace propagation
            msg = str(exc)
            log.error("APPLY FAILED alert=%s [node=%s]: %s", name, node.name, msg)
            return {"status": "Failed", "error": msg}


__all__ = ["AlertRulesImporter"]
