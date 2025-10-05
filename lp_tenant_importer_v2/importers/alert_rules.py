from __future__ import annotations
"""
AlertRules importer (DirectorSync v2)

Key points:
- Fetches existing rules via POST AlertRules/MyAlertRules/fetch (framework standard),
  then monitors the returned URL and caches results per node.
- Robust parsing & normalization for 'repos' and 'log_source' coming from Excel.
- Repos expansion:
    * Keep literal 'IP:port[/name]' as-is.
    * 'default' / '_logpoint' / '_logpointAlert' -> 127.0.0.1:<port>/<name>.
    * Otherwise treat token as repo name (old/original). Remap with repo_name_map
      if present, then expand across tenant backend/all_in_one private IPs.
- Extensive DEBUG logging to trace transformations and payload building.
"""

from typing import Any, Dict, Iterable, List, Tuple
import ast
import json
import logging
import math
import os
import re

import pandas as pd

from .base import BaseImporter, NodeRef, ValidationError, TenantConfig
from ..core.director_client import DirectorClient

log = logging.getLogger(__name__)

RESOURCE = "AlertRules"
FETCH_ENDPOINT = "AlertRules/MyAlertRules/fetch"

# ------------------------ helpers ------------------------


def _s(v: Any) -> str:
    """Return trimmed string, or empty string for None."""
    return str(v).strip() if v is not None else ""


def _to_int(v: Any, *, ceil_from_seconds: bool = False) -> int:
    """Coerce common spreadsheet values to int."""
    if v is None or v == "":
        return 0
    try:
        if isinstance(v, int):
            return v
        f = float(str(v).strip())
        if ceil_from_seconds:
            return int(math.ceil(f / 60.0))
        return int(f)
    except Exception:
        raise ValidationError(f"invalid integer value: {v!r}")


def _parse_list_field(raw: Any) -> List[str]:
    """
    Parse a cell value into a clean list[str].

    Accepts:
      - JSON arrays: ["a","b"]
      - Python-like arrays: ['a', 'b']
      - CSV-ish: "a,b" or "a; b | c" (comma/semicolon/pipe/newlines)

    Trims stray quotes/brackets and dedupes while preserving order.
    """
    def _soft_clean(s: str) -> str:
        s = (s or "").strip()
        s = s.strip().lstrip("[").rstrip("]").strip()
        if s.startswith(("'", '"')):
            s = s[1:].lstrip()
        if s.endswith(("'", '"')):
            s = s[:-1].rstrip()
        return s.strip()

    # Already a list
    if isinstance(raw, list):
        vals = [_soft_clean(str(x)) for x in raw]
    elif isinstance(raw, str):
        s = raw.strip()
        parsed = None
        if s:
            # JSON first
            try:
                parsed = json.loads(s)
            except Exception:
                parsed = None
            # Python literal
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
            tmp = s.replace("\n", ",").replace(";", ",").replace("|", ",")
            parts = [p for p in tmp.split(",")]
            vals = [_soft_clean(p) for p in parts]
    else:
        vals = []

    seen, out = set(), []
    for v in vals:
        if not v:
            continue
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out

_RE_IP_PORT = re.compile(
    r"^\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s*:\s*(?P<port>\d{2,5})/(?P<repo>.*)?\s*$"
)

def _is_literal_repo_path(token: str) -> bool:
    """True if token is already 'IP:port[/name]'."""
    return bool(_RE_IP_PORT.match(token))


def _get_repo_port_from_profiles() -> int:
    """
    Optional override from resources/profiles.yml:
      profiles.AlertRules.options.repo_port
    Falls back to 5504 if not found.
    """
    try:
        import yaml  # type: ignore
    except Exception:
        return 5504

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    res_path = os.path.join(base_dir, "resources", "profiles.yml")
    if not os.path.exists(res_path):
        return 5504
    try:
        with open(res_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        port = (((data.get("profiles") or {})
                 .get("AlertRules") or {})
                .get("options") or {}).get("repo_port")
        if isinstance(port, int) and port > 0:
            return port
    except Exception:
        pass
    return 5504


def _expand_local_repo(token: str, port: int) -> str:
    """Map 'default'/'_logpoint'/'_logpointAlert' to 127.0.0.1:<port>/<name>."""
    name = token.strip()
    return f"127.0.0.1:{port}/{name}"


def _build_repo_paths_for_backends(repo_name: str | None, backend_ips: List[str], port: int) -> List[str]:
    """
    Generate '<ip>:<port>/<repo_name>' for each backend/private IP.
    If repo_name is falsy (None/empty), generate '<ip>:<port>' to target all repos.
    """
    paths: List[str] = []
    for ip in backend_ips:
        if not ip:
            continue
        if repo_name:
            paths.append(f"{ip}:{port}/{repo_name}")
        else:
            paths.append(f"{ip}:{port}")
    # dedupe while preserving order
    seen, out = set(), []
    for p in paths:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


# ------------------------ importer ------------------------


class AlertRulesImporter(BaseImporter):
    """
    Importer for AlertRules.

    Expected sheet: 'Alert'
    """

    resource_name: str = "alert_rules"
    sheet_names = ("Alert",)
    required_columns = tuple()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # caches
        self._existing_cache: Dict[str, Dict[str, Any]] = {}   # node.id -> { name: payload }
        self._users_cache: Dict[str, Dict[str, str]] = {}      # node.id -> lower_key -> user_id
        self._users_loaded: set[str] = set()

        # Provided/filled by runner if needed:
        self._repo_map: Dict[str, str] = {}     # original -> cleaned name
        self.tenant_nodes: List[Dict[str, Any]] | None = None  # nodes of tenant (to collect ip_private)

    @property
    def repo_name_map(self) -> Dict[str, str]:
        """Shortcut to the 'original -> cleaned' repository name map."""
        return self._repo_map

    # ------------------------ validation ------------------------

    def _build_repo_name_map(self, sheets: Dict[str, pd.DataFrame]) -> Dict[str, str]:
        """Build mapping {original_repo_name -> cleaned_repo_name} from optional 'Repo' sheet."""
        if "Repo" not in sheets:
            return {}
        df = sheets["Repo"]
        cols = {c.lower(): c for c in df.columns}
        src = cols.get("original_repo_name")
        dst = cols.get("cleaned_repo_name")
        if not src or not dst:
            return {}

        mapping: Dict[str, str] = {}
        for _, row in df.iterrows():
            k = _s(row.get(src))
            v = _s(row.get(dst))
            if k and v:
                mapping[k] = v
        return mapping

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
        self._repo_map = self._build_repo_name_map(sheets)
        self.backend_ips = self._collect_backend_ips()

    # ------------------------ desired rows ------------------------

    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:  # type: ignore[override]
        df = sheets["Alert"].fillna("")
        for _, r in df.iterrows():
            d: Dict[str, Any] = {
                "name": _s(r.get("name")),
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
                "repos": _parse_list_field(r.get("settings.repos")),
                "log_source": _parse_list_field(r.get("settings.log_source")),
                "searchname": _s(r.get("settings.searchname")) or _s(r.get("name")),
                "flush_on_trigger": bool(r.get("settings.flush_on_trigger")),
                "throttling_enabled": bool(r.get("settings.throttling_enabled")),
                "throttling_field": _s(r.get("settings.throttling_field")),
                "throttling_time_range": _s(r.get("settings.throttling_time_range")),
                "search_interval_minute": _s(r.get("settings.search_interval_minute")),
                "context_template": _s(r.get("settings.alert_context_template")) or _s(r.get("settings.context_template")),
                "query": _s(r.get("settings.extra_config.query")),
            }

            if d.get("time_range_seconds") and not any(
                d.get(k)
                for k in (
                    "timerange_minute",
                    "timerange_hour",
                    "timerange_day",
                    "timerange_second",
                )
            ):
                try:
                    sec = _to_int(d["time_range_seconds"])
                    d["timerange_second"] = str(sec)
                except Exception:
                    pass

            yield d

    @staticmethod
    def key_fn(desired_row: Dict[str, Any]) -> str:
        return _s(desired_row.get("name"))

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "risk": _s(desired_row.get("risk")).lower(),
            "repos_csv": ",".join(sorted([_s(x) for x in desired_row.get("repos") or []])),
            "aggregate": _s(desired_row.get("aggregate")).lower(),
            "condition_option": _s(desired_row.get("condition_option")).lower(),
            "condition_value": _to_int(desired_row.get("condition_value")),
            "limit": _to_int(desired_row.get("limit")),
            "timerange_day": _to_int(desired_row.get("timerange_day")),
            "timerange_hour": _to_int(desired_row.get("timerange_hour")),
            "timerange_minute": _to_int(desired_row.get("timerange_minute")),
            "searchname": _s(desired_row.get("searchname")),
        }
    
    def canon_existing(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "risk": _s(row.get("risk")).lower(),
            "repos_csv": ",".join(sorted([_s(x) for x in row.get("repos") or []])),
            "aggregate": _s(row.get("aggregate")).lower(),
            "condition_option": _s(row.get("condition_option")).lower(),
            "condition_value": _to_int(row.get("condition_value")),
            "limit": _to_int(row.get("limit")),
            "timerange_day": _to_int(row.get("timerange_day")),
            "timerange_hour": _to_int(row.get("timerange_hour")),
            "timerange_minute": _to_int(row.get("timerange_minute")),
            "searchname": _s(row.get("searchname")),
        }

    # ------------------------ users/owner ------------------------

    def _get_profile_option_default_owner(self) -> str:
        """Read resources/profiles.yml and return profiles.AlertRules.options.default_owner if present."""
        try:
            import yaml  # type: ignore
        except Exception:
            return ""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
        idx: Dict[str, str] = {}
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
        """Return a valid Director user id for this node (or '' if not found)."""
        self._load_users_for_node(client, pool_uuid, node)
        lookup = _s(owner_raw)
        if not lookup:
            return ""
        idx = self._users_cache.get(node.id) or {}
        if lookup in idx.values():
            return lookup
        return idx.get(lookup.lower(), "")

    # ------------------------ repos expansion ------------------------

    def _collect_backend_ips(self) -> List[str]:
        """
        Collect private OpenVPN IPs from tenant nodes (backend/all_in_one).
        Runner should set self.tenant_nodes.
        """
        ips: List[str] = []
        tenant_siems = self.tenant_ctx.siems if self.tenant_ctx.siems else None
        log.debug(f"tenant siems content: {tenant_siems}")
        if tenant_siems:
            siem_types = ("backends", "backend", "all_in_one", "all-in-one", "allinone")
            for siem_type in siem_types:
                for node in tenant_siems.get(siem_type, []):
                    ip_priv = node.ip_private
                    if ip_priv:
                        ips.append(ip_priv)
            log.debug(f"siems private IPs list: {ips}")
        else:
            log.error(f"no siems defined for this tenant: {self.tenant_name}")
            
        # dedupe
        seen, out = set(), []
        for ip in ips:
            if ip and ip not in seen:
                out.append(ip)
                seen.add(ip)
        return out

    def _normalize_and_expand_repos(self, raw_value: Any, node: NodeRef) -> List[str]:
        """
        Convert 'settings.repos' into final repo paths according to the rules described in the module docstring.
        """
        tokens = _parse_list_field(raw_value)
        log.debug("repos(raw)=%s", tokens)
        if not tokens:
            return []

        port = _get_repo_port_from_profiles()
        backend_ips = self._collect_backend_ips()
        special_local = {"default", "_logpoint", "_LogPointAlerts"}

        final: List[str] = []
        for t in tokens:
            log.debug("repo start for loop '%s'", t)
            tt = t.strip()
            
            if _is_literal_repo_path(tt):
                m = _RE_IP_PORT.match(tt)
                mRepo = m.group("repo","")
                log.debug("repo token found '%s'", mRepo)
                if isinstance(mRepo, str) and mRepo:
                    if not mRepo in special_local:
                        final.append(_expand_local_repo(mRepo, port))
                    else:
                        repo_token = self.repo_name_map.get(mRepo, mRepo)
                        if backend_ips:
                            expanded = _build_repo_paths_for_backends(mRepo, backend_ips, port)
                            final.extend(expanded)
                            log.debug("repo token '%s' -> expanded=%s", mRepo, expanded)
                        else:
                            final.append(tt)
                            log.warning("repo token '%s' -> no backend IPs; kept as='%s'", tt, mRepo)
                else:
                    continue
            else:
                log.debug("repo litteral not found '%s'", tt)

        # dedupe preserving order
        seen, out = set(), []
        for p in final:
            if p not in seen:
                out.append(p)
                seen.add(p)

        log.debug("repos(expanded)=%s", out)
        return out

    # ------------------------ fetch existing (framework) ------------------------

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        """
        Fetch all alert rules visible to the current user on the given node using the framework:
        - POST (no payload) to AlertRules/MyAlertRules/fetch
        - Follow monitor URL (handled by DirectorClient.fetch_resource) to get rows
        - Cache mapping: name -> payload
        """
        resp = client.fetch_resource(
            pool_uuid=pool_uuid,
            node_id=node.id,
            resource=FETCH_ENDPOINT,
            data={},  # POST without payload
        )

        rows = []
        monitor_ok = resp.get("monitor_ok")
        if isinstance(monitor_ok, tuple) and monitor_ok[0] and monitor_ok[1]:
            payload = monitor_ok[1] or {}
            response = (payload.get("response") or {})
            rows = response.get("rows") or []
        else:
            log.warning("fetch_existing: monitor not OK on node=%s; returning empty map", node.name)
            mapping: Dict[str, Dict[str, Any]] = {}
            self._existing_cache[node.id] = mapping
            return mapping

        mapping: Dict[str, Dict[str, Any]] = {}
        for item in rows:
            nm = item.get("name")
            if nm:
                mapping[str(nm)] = item

        self._existing_cache[node.id] = mapping
        log.debug("fetch_existing: cached %d alert(s) for node=%s", len(mapping), node.name)
        return mapping

    # ------------------------ payloads ------------------------

    def build_payload_create(self, desired_row: Dict[str, Any], node: NodeRef | None = None) -> Dict[str, Any]:
        """Build payload for create; performs repo expansion if node is provided."""
        owner_raw = desired_row.get("owner")
        if isinstance(owner_raw, (list, tuple)) and owner_raw:
            owner_id = _s(owner_raw[0])
        else:
            owner_id = _s(owner_raw)
        if not owner_id:
            owner_id = self._get_profile_option_default_owner()
        if not owner_id:
            raise ValidationError("owner is required and could not be resolved")

        payload: Dict[str, Any] = {
            "name": _s(desired_row.get("name")),
            "owner": owner_id,
            "risk": _s(desired_row.get("risk")).lower(),
            "aggregate": _s(desired_row.get("aggregate")).lower(),
            "condition_option": _s(desired_row.get("condition_option")).lower(),
            "condition_value": _to_int(desired_row.get("condition_value")),
            "limit": _to_int(desired_row.get("limit")),
            "searchname": _s(desired_row.get("searchname")) or _s(desired_row.get("name")),
            "timerange_day": _to_int(desired_row.get("timerange_day")),
            "timerange_hour": _to_int(desired_row.get("timerange_hour")),
            "timerange_minute": _to_int(desired_row.get("timerange_minute")),
        }

        # repos/log_source parse (raw) for debug
        repos_raw = desired_row.get("repos")
        log_source_raw = desired_row.get("log_source")
        log.debug("build_payload_create: repos(raw)=%s", repos_raw)
        log.debug("build_payload_create: log_source(raw)=%s", log_source_raw)

        # normalize log_source
        log_source = _parse_list_field(log_source_raw)
        payload["log_source"] = log_source
        log.debug("build_payload_create: log_source(parsed)=%s", payload["log_source"])

        # normalize & expand repos
        if self.backend_ips:
            payload["repos"] = self._normalize_and_expand_repos(repos_raw, node)
        else:
            payload["repos"] = _parse_list_field(repos_raw)
        log.debug("build_payload_create: repos(final)=%s", payload["repos"])

        # flags/intervals
        if desired_row.get("flush_on_trigger"):
            payload["flush_on_trigger"] = "on"
        if desired_row.get("throttling_enabled"):
            payload["throttling_enabled"] = "on"
            if _s(desired_row.get("throttling_field")):
                payload["throttling_field"] = _s(desired_row.get("throttling_field"))
            if desired_row.get("throttling_time_range"):
                payload["throttling_time_range"] = _to_int(desired_row.get("throttling_time_range"))
        if desired_row.get("search_interval_minute"):
            payload["search_interval_minute"] = _to_int(desired_row.get("search_interval_minute"))

        # context template
        if _s(desired_row.get("context_template")):
            payload["alert_context_template"] = _s(desired_row.get("context_template"))

        # optional query passthrough
        if _s(desired_row.get("query")):
            payload["query"] = _s(desired_row.get("query"))

        log.debug("build_payload_create: payload_keys=%s", sorted(payload.keys()))
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_row: Dict[str, Any], node: NodeRef | None = None) -> Dict[str, Any]:
        """Build payload for update; same fields as create."""
        return self.build_payload_create(desired_row, node=node)

    # ------------------------ apply ------------------------

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

        # Resolve owner for CREATE/UPDATE
        if decision.op in ("CREATE", "UPDATE"):
            owner_input = (desired.get("owner") or self._get_profile_option_default_owner())
            owner_resolved = self._resolve_owner_id(client, pool_uuid, node, owner_input or "")
            if not owner_resolved:
                log.warning(
                    "SKIP %s alert=%s [node=%s] reason=Unknown owner '%s'",
                    decision.op, name, node.name, owner_input
                )
                return {"status": "Skipped", "reason": f"Unknown owner '{owner_input}'"}
            if owner_input != owner_resolved:
                log.info("owner resolved: '%s' -> id=%s [node=%s]", owner_input, owner_resolved, node.name)
            desired["owner"] = owner_resolved

        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired, node=node)
                log.info("CREATE alert=%s [node=%s]", name, node.name)
                log.debug("CREATE payload=%s", payload)
                return client.create_resource(pool_uuid, node.id, RESOURCE, payload)

            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id}, node=node)
                log.info("UPDATE alert=%s id=%s [node=%s]", name, existing_id, node.name)
                log.debug("UPDATE payload=%s", payload)
                return client.update_resource(pool_uuid, node.id, RESOURCE, existing_id, payload)

            log.info("NOOP alert=%s [node=%s]", name, node.name)
            return {"status": "Success"}

        except Exception as exc:
            msg = str(exc)
            log.error("APPLY FAILED alert=%s [node=%s]: %s", name, node.name, msg)
            return {"status": "Failed", "error": msg}


__all__ = ["AlertRulesImporter"]
