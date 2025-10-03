
from __future__ import annotations
"""
AlertRules importer (DirectorSync v2) — hardened implementation.

- Resolves `owner` by listing Users on the node (username/display_name/email → id).
- If owner can't be resolved: SKIP (no API call), like other importers.
- Accepts numeric strings like "30.0" safely for all integer fields.
- Ensures `searchname` is present (falls back to `name`).
- Preserves prior behaviour of repos/log_source normalization and timerange handling.
"""
from typing import Any, Dict, Iterable, List, Tuple
import logging
import math
import json
import pandas as pd
import re
import ast

from .base import BaseImporter, NodeRef, ValidationError
from ..core.director_client import DirectorClient

log = logging.getLogger(__name__)

RESOURCE = "AlertRules"
FETCHARLERT = "AlertRules/MyAlertRules/fetch"

def _s(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def _to_int(v: Any, *, ceil_from_seconds: bool = False) -> int:
    """Coerce common spreadsheet values to int.

    Accepts numbers, numeric strings (e.g. "5", "30.0"), blank -> 0.
    If ceil_from_seconds=True, we treat value as seconds and return ceil(seconds/60).
    """
    if v is None or v == "":
        return 0
    try:
        # Already an int
        if isinstance(v, int):
            return v
        # Excel often gives floats-as-strings like "30.0"
        f = float(str(v).strip())
        if ceil_from_seconds:
            return int(math.ceil(f / 60.0))
        return int(f)
    except Exception:
        raise ValidationError(f"invalid integer value: {v!r}")


def _s(value: Any) -> str:
    """Return a trimmed string for any value; empty string for None."""
    return str(value).strip() if value is not None else ""


def _uniq(items: Iterable[str]) -> List[str]:
    """Return a list with duplicates removed while preserving order."""
    seen: set[str] = set()
    out: List[str] = []
    for it in items:
        if it not in seen:
            out.append(it)
            seen.add(it)
    return out


def _parse_list_cell(cell: Any) -> List[str]:
    """
    Parse an Excel cell into a clean list of strings.

    Accepted formats:
      - JSON arrays: ["a","b"]
      - Delimited text using ',', ';', '|' or newlines.

    Behavior:
      - Trims quotes/brackets left-overs.
      - Filters empty entries.
      - Deduplicates while preserving order.
    """
    text = _s(cell)
    if not text:
        return []

    raw = text.strip()

    # 1) Try strict JSON first for cells that look like arrays.
    if raw.startswith("[") and raw.endswith("]"):
        try:
            arr = json.loads(raw)
            return _uniq([_s(x) for x in arr if _s(x)])
        except Exception:
            # Fall back to tolerant text parsing if JSON is malformed.
            pass

    # 2) Tolerant text parsing: normalize common separators to comma.
    for sep in ("\n", ";", "|"):
        raw = raw.replace(sep, ",")

    parts = [p.strip() for p in raw.split(",") if p.strip()]
    cleaned: List[str] = []
    for p in parts:
        # Remove stray quotes/brackets commonly found in CSV/Excel exports.
        p2 = p.strip().strip('"').strip("'").strip()
        if p2 == "[]":
            continue
        p2 = p2.strip("[]").strip()
        if p2:
            cleaned.append(p2)

    return _uniq(cleaned)


def _parse_list_field(raw) -> list[str]:
    """
    Parse a cell value into a clean list[str].

    Accepts:
      - JSON arrays: ["a","b"]
      - Python-like arrays: ['a', 'b']
      - CSV-ish strings: "a,b" or "a; b | c" (comma/semicolon/pipe/newlines)

    Guarantees:
      - Trims stray quotes/brackets even when unbalanced
      - Deduplicates while preserving order
      - Filters empty entries
    """
    def _soft_clean(s: str) -> str:
        # Remove common wrappers even if unbalanced: quotes and brackets
        s = (s or "").strip()
        s = s.strip().lstrip("[").rstrip("]").strip()
        # Strip one leading/trailing quote if present (even if not paired)
        if s.startswith(("'", '"')):
            s = s[1:].lstrip()
        if s.endswith(("'", '"')):
            s = s[:-1].rstrip()
        return s.strip()

    # 1) Already a list
    if isinstance(raw, list):
        vals = [_soft_clean(str(x)) for x in raw]

    # 2) Try JSON, then Python literal (for ['...','...'] from Excel)
    elif isinstance(raw, str):
        s = raw.strip()
        parsed = None
        if s:
            # JSON first
            try:
                parsed = json.loads(s)
            except Exception:
                parsed = None
            # Python literal if JSON failed
            if not isinstance(parsed, list):
                try:
                    lit = ast.literal_eval(s)
                    if isinstance(lit, list):
                        parsed = lit
                except Exception:
                    parsed = None

        if isinstance(parsed, list):
            vals = [_soft_clean(str(x)) for x in parsed]
        else:
            # 3) Tolerant CSV fallback
            tmp = s.replace("\n", ",").replace(";", ",").replace("|", ",")
            parts = [p for p in tmp.split(",") if p is not None]
            vals = [_soft_clean(p) for p in parts]
    else:
        vals = []

    # 4) Drop empties + dedupe (order-preserving)
    seen = set()
    clean: list[str] = []
    for v in vals:
        if not v:
            continue
        if v not in seen:
            clean.append(v)
            seen.add(v)
    return clean


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
    resource_name: str = "alert_rules"
    sheet_names = ("Alert",)
    required_columns = tuple()  # custom validation below
 
 
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # logger instance per-importer (cohérent avec les autres importers)
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        # cache des règles par node.id
        self._existing_cache: Dict[str, Dict[str, Any]] = {}
        
        # Users cache: node_id -> { lookup_key_lower: user_id }
        self._users_cache: dict[str, dict[str, str]] = {}
        self._users_loaded: set[str] = set()
        # Node-level cache: { node_name: {rule_id: rule_obj, ...} }
        self._rules_cache: dict[str, dict[str, dict]] = {}
        # Node-level caches:
        #  - by_id:   { node_name: {rule_id: rule_payload} }
        #  - by_name: { node_name: {normalized_name: rule_payload} }
        self._rules_cache_by_id: dict[str, dict[str, dict]] = {}
        self._rules_cache_by_name: dict[str, dict[str, dict]] = {} 
        # Cache of existing alerts per node_id: { node_id: {name: row, ...}, ... }
        self._alerts_by_node: dict[str, dict[str, dict]] = {}

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


    def _normalize_name(self, value: str) -> str:
        """Normalize a rule name for consistent case-insensitive lookups."""
        return (value or "").strip().lower()

    def _index_rules(self, items: list[dict]) -> tuple[dict[str, dict], dict[str, dict]]:
        """
        Build two indices:
        - by_id:    keyed by 'id' or '_id'
        - by_name:  keyed by normalized 'searchname' (preferred) or 'name'
        """
        by_id: dict[str, dict] = {}
        by_name: dict[str, dict] = {}

        for it in items or []:
            rid = str(it.get("_id") or it.get("id") or "").strip()
            if rid:
                by_id[rid] = it
            nm = it.get("searchname") if it.get("searchname") else it.get("name")
            key = self._normalize_name(str(nm or ""))
            if key:
                by_name[key] = it

        return by_id, by_name

    def get_rule_by_name(self, node: dict, name: str) -> dict | None:
        """
        Return a rule payload by (case-insensitive) name or searchname.
        Uses node-level cache, fetches if needed.
        """
        node_name = node.get("name") or node.get("display_name") or "unknown"
        key = self._normalize_name(name)

        # Warm cache if missing
        if node_name not in self._rules_cache_by_name:
            self.fetch_existing(node)

        return self._rules_cache_by_name.get(node_name, {}).get(key)

    # ------------------------------ desired ------------------------------
    
    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:  # type: ignore[override]
        df = sheets["Alert"].fillna("")
        for _, r in df.iterrows():
            d: Dict[str, Any] = {
                "name": _s(r.get("name")),
                # owner priority: settings.user then owner
                "owner": (_s(r.get("settings.user")) or _s(r.get("owner"))),
                "risk": _s(r.get("settings.risk")).lower(),
                "aggregate": _s(r.get("settings.aggregate")).lower(),
                "condition_option": _s(r.get("settings.condition.condition_option")).lower(),
                "condition_value": _to_int(r.get("settings.condition.condition_value")),
                "limit": _to_int(r.get("settings.livesearch_data.limit")),
                "timerange_minute": _s(r.get("settings.livesearch_data.timerange_minute")),
                "timerange_hour": _s(r.get("settings.livesearch_data.timerange_hour")),
                "timerange_day": _s(r.get("settings.livesearch_data.timerange_day")),
                "timerange_second": _s(r.get("settings.livesearch_data.timerange_second")),
                "time_range_seconds": _s(r.get("settings.time_range_seconds")),
                
                # Parse repos/log_source with JSON-first strategy; then tolerant text.
                "repos": _parse_list_cell(r.get("settings.repos")),
                "log_source": _parse_list_cell(r.get("settings.log_source")),                
                               
                "searchname": _s(r.get("settings.searchname")) or _s(r.get("name")),
                "flush_on_trigger": bool(r.get("settings.flush_on_trigger")),
                "throttling_enabled": bool(r.get("settings.throttling_enabled")),
                "throttling_field": _s(r.get("settings.throttling_field")),
                "throttling_time_range": _s(r.get("settings.throttling_time_range")),
                "search_interval_minute": _s(r.get("settings.search_interval_minute")),
                "context_template": _s(r.get("settings.alert_context_template")) or _s(r.get("settings.context_template")),
                # optional query passthrough if present in sheet (prevents Monitor "Query cannot be empty")
                "query": _s(r.get("settings.extra_config.query")),
            }
            
            # Normalized copies used in payload build (already cleaned & deduped).
            d["repos_norm"] = [x for x in d["repos"] if x]
            d["log_source_norm"] = [x for x in d["log_source"] if x]

            # Compute timerange fallback from seconds
            if d.get("time_range_seconds") and not any(
                d.get(k) for k in ("timerange_minute", "timerange_hour", "timerange_day", "timerange_second")
            ):
                try:
                    sec = _to_int(d["time_range_seconds"])
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
            return ("minute", _to_int(m))
        if (h := d.get("timerange_hour")):
            return ("hour", _to_int(h))
        if (dy := d.get("timerange_day")):
            return ("day", _to_int(dy))
        if (s := d.get("timerange_second")):
            # seconds → minutes (ceil)
            return ("minute", _to_int(s, ceil_from_seconds=True))
        return ("minute", 0)

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        # key, val = self._canon_timerange(desired_row)
        return {
            "risk": _s(desired_row.get("risk")).lower(),
            "repos_csv": ",".join(sorted([_s(x) for x in desired_row.get("repos_norm", [])])),
            "aggregate": _s(desired_row.get("aggregate")).lower(),
            "condition_option": _s(desired_row.get("condition_option")).lower(),
            "condition_value": _to_int(desired_row.get("condition_value")),
            "limit": _to_int(desired_row.get("limit")),
            "timerange_day":  _to_int(desired_row.get("timerange_day")),
            "timerange_hour":  _to_int(desired_row.get("timerange_hour")),
            "timerange_minute":  _to_int(desired_row.get("timerange_minute")),
            "searchname": _s(desired_row.get("searchname")),
        }

    # ------------------------------ users cache ------------------------------


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

    def _index_rules_by_id(self, items: list[dict]) -> dict[str, dict]:
        """
        Build a dict keyed by rule id for fast lookups and diffing.
        Safely handles missing keys; logs in DEBUG the raw payload.
        """
        indexed: dict[str, dict] = {}
        for it in items or []:
            rid = str(it.get("_id") or it.get("id") or "").strip()
            if rid:
                indexed[rid] = it
        return indexed

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        """
        Fetch all alert rules visible to the current user on the given node, using
        the standard POST + monitor flow via DirectorClient.fetch_resource().
        Returns a dict mapping `rule_name -> full_rule_payload`.

        Contract with BaseImporter:
        - Always return a dict (possibly empty), never None.
        - Keys are the canonical names used by `key_fn()`.
        """
        # 1) POST sans payload vers l’endpoint "MyAlertRules/fetch"
        resp = client.fetch_resource(
            pool_uuid=pool_uuid,
            node_id=node.id,
            resource="AlertRules/MyAlertRules/fetch",
            data={},   # POST sans payload d'après la doc/framework
        )

        # 2) Extraire le résultat monitorisé (framework: monitor_ok = (bool, payload))
        rows = []
        monitor_ok = resp.get("monitor_ok")
        if isinstance(monitor_ok, tuple) and monitor_ok[0] and monitor_ok[1]:
            payload = monitor_ok[1] or {}
            response = payload.get("response") or {}
            rows = response.get("rows") or []
        else:
            # Pas d’erreur levée ici : on respecte le contrat et on renvoie un dict vide.
            self.log.warning("fetch_existing: monitor not OK on node=%s; returning empty mapping", node.name)
            mapping: Dict[str, Dict[str, Any]] = {}
            self._existing_cache[node.id] = mapping
            return mapping

        # 3) Construire le mapping `name -> full_object`
        mapping: Dict[str, Dict[str, Any]] = {}
        for item in rows:
            name = item.get("name")
            if not name:
                continue
            mapping[name] = item

        # 4) Cache + log debug
        self._existing_cache[node.id] = mapping
        self.log.debug("fetch_existing: cached %d alert(s) for node=%s", len(mapping), node.name)
        return mapping

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



        # Read raw values coming from Excel mapping
        raw_repos = desired_row.get("repos") 
        raw_log_source = desired_row.get("log_source")

        repos = _parse_list_field(raw_repos)
        log_source = _parse_list_field(raw_log_source)

        # DEBUG dump to verify
        self.log.debug("parsed repos=%s", repos)
        self.log.debug("parsed log_source=%s", log_source)

        payload: Dict[str, Any] = {
            "name": _s(desired_row.get("name")),
            "owner": owner_id,
            "risk": _s(desired_row.get("risk")).lower(),
            "aggregate": _s(desired_row.get("aggregate")).lower(),
            "condition_option": _s(desired_row.get("condition_option")).lower(),
            "condition_value": _to_int(desired_row.get("condition_value")),
            "limit": _to_int(desired_row.get("limit")),
            "repos": repos,
            "log_source": log_source,
            "searchname": _s(desired_row.get("searchname")) or _s(desired_row.get("name")),
            "timerange_day": int(desired_row.get("timerange_day")),
            "timerange_hour": int(desired_row.get("timerange_hour")),
            "timerange_minute": int(desired_row.get("timerange_minute")),
        }

        # timerange fields
        # key, val = self._canon_timerange(desired_row)
        # if val:
        #     payload[f"timerange_{key}"] = val

        # log_source optional
        if desired_row.get("log_source_norm"):
            payload["log_source"] = desired_row.get("log_source_norm")

        # search interval
        if desired_row.get("search_interval_minute"):
            payload["search_interval_minute"] = _to_int(desired_row.get("search_interval_minute"))

        # switches
        if desired_row.get("flush_on_trigger"):
            payload["flush_on_trigger"] = "on"
        if desired_row.get("throttling_enabled"):
            payload["throttling_enabled"] = "on"
            if _s(desired_row.get("throttling_field")):
                payload["throttling_field"] = _s(desired_row.get("throttling_field"))
            if desired_row.get("throttling_time_range"):
                payload["throttling_time_range"] = _to_int(desired_row.get("throttling_time_range"))

        # context template
        if _s(desired_row.get("context_template")):
            payload["alert_context_template"] = _s(desired_row.get("context_template"))

        # optional query passthrough (prevents empty query validation on some setups)
        if _s(desired_row.get("query")):
            payload["query"] = _s(desired_row.get("query"))
            
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
            # prefer settings.user if present, else any provided owner, else profiles.yml default
            owner_input = (desired.get("owner") or self._get_profile_option_default_owner())
            owner_resolved = self._resolve_owner_id(client, pool_uuid, node, owner_input or "")
            if not owner_resolved:
                log.warning(
                    "SKIP %s alert=%s [node=%s] reason=Unknown owner '%s' (no API call)",
                    decision.op, name, node.name, owner_input
                )
                return {"status": "Skipped", "reason": f"Unknown owner '{owner_input}'"}
            if owner_input != owner_resolved:
                log.info("owner resolved: '%s' -> id=%s [node=%s]", owner_input, owner_resolved, node.name)
            desired["owner"] = owner_resolved
        # alert_rules.py — dans apply(), juste avant CREATE/UPDATE
        self.log.debug(
            "apply: node=%s name=%s payload_keys=%s timerange=%s repos=%s log_source=%s",
            node.id,
            payload.get("name") or payload.get("searchname"),
            sorted(payload.keys()),
            (payload.get("timerange_day"), payload.get("timerange_hour"), payload.get("timerange_minute")),
             payload.get("repos"),
             payload.get("log_source"),
           )
        try:
            if decision.op == "CREATE":
                try:
                    payload = self.build_payload_create(desired)
                    log.debug(f"new collected and normalized payload: {payload}")
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
