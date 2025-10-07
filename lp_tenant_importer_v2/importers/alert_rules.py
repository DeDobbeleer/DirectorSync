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
- NEW: settings.attack_tag in XLSX may contain MITRE hashes (or technique IDs or labels);
  we now resolve these tokens to the final attack tag IDs expected by the API using the
  MitreAttacks catalog (FetchMitreAttacks) cached per pool.
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
        self._incident_groups_cache: Dict[str, Dict[str, str]] = {}  # node.id -> lower_name_or_id -> id
        self._incident_groups_loaded: set[str] = set()
        self._mitre_cache_by_pool: Dict[str, Dict[str, str]] = {}     # pool_uuid -> lower_token -> attack_id
        self._mitre_loaded_pools: set[str] = set()

    def _resolve_user_id(self, client: DirectorClient, pool_uuid: str, node: NodeRef, lookup: str) -> str:
        """Generic user resolver: accepts id/username/display_name/email; returns id or ''."""
        self._load_users_for_node(client, pool_uuid, node)
        lk = _s(lookup)
        if not lk:
            return ""
        idx = self._users_cache.get(node.id) or {}
        if lk in idx.values():  # already an id
            return lk
        return idx.get(lk.lower(), "")

    def _load_incident_groups_for_node(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        """Build cache name/id -> id for incident user groups. Tries common resource names safely."""
        if node.id in self._incident_groups_loaded:
            return
        candidates = ("IncidentUserGroups", "IncidentGroups", "IncidentGroup")
        raw = []
        for res in candidates:
            try:
                raw = client.list_resource(pool_uuid, node.id, res) or []
                if raw:
                    break
            except Exception:
                raw = []
        idx: Dict[str, str] = {}
        for g in raw:
            gid = _s(g.get("id"))
            if not gid:
                continue
            for k in (g.get("id"), g.get("name"), g.get("display_name")):
                key = _s(k).lower()
                if key:
                    idx[key] = gid
        self._incident_groups_cache[node.id] = idx
        self._incident_groups_loaded.add(node.id)
        log.debug("Incident groups cache loaded: node=%s size=%d", node.name, len(idx))

    def _resolve_incident_group_ids(self, client: DirectorClient, pool_uuid: str, node: NodeRef, items: List[str]) -> List[str]:
        """Resolve list of names/ids into list of ids; quietly drop unknown with WARNING."""
        self._load_incident_groups_for_node(client, pool_uuid, node)
        idx = self._incident_groups_cache.get(node.id) or {}
        out: List[str] = []
        for it in (items or []):
            key = _s(it).lower()
            if not key:
                continue
            if key in idx:
                out.append(idx[key])
            elif it in idx.values():  # already an id
                out.append(it)
            else:
                log.warning("Unknown incident group '%s' [node=%s] - ignored", it, node.name)
        # dedupe / stable
        seen, uniq = set(), []
        for gid in out:
            if gid not in seen:
                uniq.append(gid)
                seen.add(gid)
        return uniq

    def _load_mitre_attacks(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        """Fetch MITRE catalog once per pool; map various tokens (id/name/technique/hash) -> id."""
        if pool_uuid in self._mitre_loaded_pools:
            return
        mapping: Dict[str, str] = {}
        try:
            # Standardized fetch via monitor API, similar to other fetch_* flows
            res = client.fetch_resource(
                pool_uuid=pool_uuid,
                node_id=node.id,
                resource="MitreAttacks/FetchMitreAttacks",
                data={},
            ) or {}
            mon = res.get("monitor_ok")
            rows = []
            if isinstance(mon, tuple) and mon[0] and mon[1]:
                payload = mon[1] or {}
                rows = (payload.get("response") or {}).get("rows") or []
            # Build index
            for r in rows:
                log.debug(f"dump mitre payload row: {r}")
                attack_id = _s(r.get("id")) or _s(r.get("attack_id")) or _s(r.get("name"))
                if not attack_id:
                    continue
                label = _s(r.get("name")) or _s(r.get("label"))
                tech = _s(r.get("technique_id")) or _s(r.get("attack_id"))
                # Common hash key variants in catalog
                for hk in ("hash", "hash_id", "mitre_hash", "id_hash"):
                    hval = _s(r.get(hk))
                    if hval:
                        mapping[hval.lower()] = attack_id
                # Primary keys
                mapping[_s(attack_id).lower()] = attack_id
                if label:
                    mapping[_s(label).lower()] = attack_id
                if tech:
                    mapping[_s(tech).lower()] = attack_id
                log.debug(f"Mitre map entry dump: {mapping}")
        except Exception as exc:
            log.warning("Failed fetching MITRE attacks catalog (pool=%s): %s", pool_uuid, exc)
        self._mitre_cache_by_pool[pool_uuid] = mapping
        self._mitre_loaded_pools.add(pool_uuid)
        log.debug("MITRE cache loaded: pool=%s size=%d", pool_uuid, len(mapping))

    def _resolve_attack_tags(self, client: DirectorClient, pool_uuid: str, node: NodeRef, items: List[str]) -> List[str]:
        """Resolve mixed tokens (hash/id/technique/name or 'token|label') to MITRE ids; drop unknown with WARNING."""
        self._load_mitre_attacks(client, pool_uuid, node)
        idx = self._mitre_cache_by_pool.get(pool_uuid) or {}
        out: List[str] = []
        for it in (items or []):
            token = _s(it)
            if not token:
                continue
            # Allow 'X|Y' forms where X is the canonical token (hash or technique)
            if "|" in token:
                token = token.split("|", 1)[0].strip()
            key = token.lower()
            if key in idx:
                out.append(idx[key])
            else:
                log.warning("Unknown MITRE attack token '%s' (pool=%s) - ignored", it, pool_uuid)
        # keep only known IDs (those present in idx.values())
        valid_ids = set(idx.values())
        out = [v for v in out if v in valid_ids]
        # dedupe / stable
        seen, uniq = set(), []
        for v in out:
            if v not in seen:
                uniq.append(v)
                seen.add(v)
        return uniq

    @staticmethod
    def _to_bool(v: Any) -> bool:
        """Normalize common truthy/falsey spreadsheet tokens to bool."""
        s = _s(v).lower()
        if isinstance(v, bool):
            return v
        return s in {"1", "y", "yes", "true", "on"}

    @staticmethod
    def _parse_metadata(raw: Any) -> List[Dict[str, str]]:
        """
        Accept JSON array of {field,value} objects or 'k=v; k2=v2' csv-ish string.
        Return a list sorted by 'field' for stable diffs; invalid pairs are ignored with WARNING.
        """
        items: List[Dict[str, str]] = []
        if raw is None:
            return items
        txt = str(raw).strip()
        if not txt:
            return items
        parsed = None
        # JSON first
        try:
            parsed = json.loads(txt)
        except Exception:
            parsed = None
        if isinstance(parsed, list):
            for obj in parsed:
                f = _s((obj or {}).get("field"))
                val = _s((obj or {}).get("value"))
                if f and val:
                    items.append({"field": f, "value": val})
                else:
                    log.warning("metadata item missing field/value -> skipped: %r", obj)
        else:
            # key=value; key2=value2
            tmp = txt.replace("\n", ";").replace("|", ";").replace(",", ";")
            for chunk in tmp.split(";"):
                if "=" not in chunk:
                    continue
                k, v = chunk.split("=", 1)
                k, v = _s(k), _s(v)
                if k and v:
                    items.append({"field": k, "value": v})
                else:
                    log.warning("metadata kv missing field/value -> skipped: %r", chunk)
        # sort by field and dedupe (last wins)
        dedup: Dict[str, str] = {}
        for it in items:
            dedup[it["field"]] = it["value"]
        canon = [{"field": k, "value": dedup[k]} for k in sorted(dedup)]
        return canon

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
                # NEW FIELDS
                "apply_jinja_template": self._to_bool(r.get("settings.apply_jinja_template")),
                "assigned_to": _s(r.get("settings.assigned_to")),
                # NOTE: In XLSX, settings.attack_tag may contain hashes/technique IDs/labels.
                # Resolution to final IDs happens later in apply() using _resolve_attack_tags().
                "attack_tag": _parse_list_field(r.get("settings.attack_tag")),
                "manageable_by": _parse_list_field(r.get("settings.manageable_by")),
                "metadata": _s(r.get("settings.metadata")),
                "original_data": self._to_bool(r.get("settings.original_data")),
                "description": _s(r.get("settings.description")),
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
        base = {
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
        # NEW FIELDS added to diff to trigger UPDATE on changes
        if desired_row.get("apply_jinja_template"):
            base["apply_jinja_template"] = "on"
        if _s(desired_row.get("description")):
            base["description"] = _s(desired_row.get("description"))
        base["original_data"] = bool(desired_row.get("original_data"))
        # manageable_by / attack_tag / assigned_to: we compare raw tokens (best-effort)
        # (they are further resolved to IDs in apply())
        mb = _parse_list_field(desired_row.get("manageable_by"))
        at = _parse_list_field(desired_row.get("attack_tag"))
        if mb:
            base["manageable_by_csv"] = ",".join(sorted([_s(x).lower() for x in mb]))
        if at:
            base["attack_tag_csv"] = ",".join(sorted([_s(x).lower() for x in at]))
        if _s(desired_row.get("assigned_to")):
            base["assigned_to_raw"] = _s(desired_row.get("assigned_to")).lower()
        # metadata normalized deterministically
        meta = self._parse_metadata(desired_row.get("metadata"))
        if meta:
            base["metadata_json"] = json.dumps(meta, separators=(",", ":"), ensure_ascii=False)
        return base        
    
    def canon_existing(self, row: Dict[str, Any]) -> Dict[str, Any]:
        base = {
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
        # Mirror new fields if present in existing rows
        if _s(row.get("apply_jinja_template")) == "on":
            base["apply_jinja_template"] = "on"
        if _s(row.get("description")):
            base["description"] = _s(row.get("description"))
        base["original_data"] = bool(row.get("original_data"))
        mb = row.get("manageable_by") or []
        at = row.get("attack_tag") or []
        if mb:
            base["manageable_by_csv"] = ",".join(sorted([_s(x).lower() for x in mb]))
        if at:
            base["attack_tag_csv"] = ",".join(sorted([_s(x).lower() for x in at]))
        if _s(row.get("assigned_to")):
            base["assigned_to_raw"] = _s(row.get("assigned_to")).lower()
        meta = row.get("metadata") or []
        if isinstance(meta, list) and meta:
            # normalize to our canonical shape
            meta_norm = [{"field": _s(m.get("field")), "value": _s(m.get("value"))} for m in meta if _s(m.get("field")) and _s(m.get("value"))]
            # sort/dedupe by field
            dedup: Dict[str, str] = {}
            for it in meta_norm:
                dedup[it["field"]] = it["value"]
            meta_canon = [{"field": k, "value": dedup[k]} for k in sorted(dedup)]
            base["metadata_json"] = json.dumps(meta_canon, separators=(",", ":"), ensure_ascii=False)
        return base        

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
        backend_ips = self.backend_ips or []
        special_local = {"default", "_logpoint", "_LogPointAlerts"}

        final: List[str] = []
        for t in tokens:
            
            log.debug("repo start for loop '%s'", t)
            
            if _is_literal_repo_path(t):
                m = _RE_IP_PORT.match(t)
                mRepo = m.group("repo")
                log.debug("repo token found '%s'", mRepo)
                if isinstance(mRepo, str) and mRepo:
                    if mRepo in special_local:
                        final.append(_expand_local_repo(mRepo, port))
                    else:
                        mRepoMap = self.repo_name_map.get(mRepo, mRepo)
                        if backend_ips:
                            expanded = _build_repo_paths_for_backends(mRepoMap, backend_ips, port)
                            final.extend(expanded)
                            log.debug("repo token '%s' -> expanded=%s", mRepoMap, expanded)
                        else:
                            final.append(t)
                            log.warning("repo token '%s' -> no backend IPs; kept as='%s'", t, mRepoMap)
                else:
                    continue
            else:
                log.debug("repo litteral not found '%s'", t)

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

        # apply_jinja_template flag (string "on")
        if desired_row.get("apply_jinja_template"):
            if not payload.get("alert_context_template"):
                log.warning("apply_jinja_template='on' but no alert_context_template provided - keeping flag anyway")
            payload["apply_jinja_template"] = "on"

        # context template
        if _s(desired_row.get("context_template")):
            payload["alert_context_template"] = _s(desired_row.get("context_template"))

        # optional query passthrough
        if _s(desired_row.get("query")):
            payload["query"] = _s(desired_row.get("query"))
        
        # NEW FIELDS payload
        if _s(desired_row.get("description")):
            payload["description"] = _s(desired_row.get("description"))
        # Note: 'assigned_to' / 'attack_tag' / 'manageable_by' are resolved in apply() into IDs
        if _s(desired_row.get("assigned_to")):
            payload["assigned_to"] = _s(desired_row.get("assigned_to"))
        atk = desired_row.get("attack_tag") or []
        if isinstance(atk, list) and atk:
            payload["attack_tag"] = list(atk)
        mby = desired_row.get("manageable_by") or []
        if isinstance(mby, list) and mby:
            payload["manageable_by"] = list(mby)
        # metadata normalized
        meta = self._parse_metadata(desired_row.get("metadata"))
        if meta:
            payload["metadata"] = meta
        # original_data boolean
        if "original_data" in desired_row:
            payload["original_data"] = bool(desired_row.get("original_data"))

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

        # Resolve owner / assignee / groups / mitre tags for CREATE/UPDATE
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

            # assigned_to (user id)
            assignee_raw = _s(desired.get("assigned_to"))
            if assignee_raw:
                assignee_id = self._resolve_user_id(client, pool_uuid, node, assignee_raw)
                if assignee_id:
                    desired["assigned_to"] = assignee_id
                else:
                    log.warning("Unknown assignee '%s' [node=%s] - dropping field", assignee_raw, node.name)
                    desired.pop("assigned_to", None)

            # manageable_by (incident groups)
            manageable_raw = desired.get("manageable_by") or []
            if manageable_raw:
                manageable_ids = self._resolve_incident_group_ids(client, pool_uuid, node, manageable_raw)
                if manageable_ids:
                    desired["manageable_by"] = manageable_ids
                else:
                    desired.pop("manageable_by", None)

            # attack_tag (MITRE): resolve XLSX tokens (hash/technique/name) -> final IDs
            attack_raw = desired.get("attack_tag") or []
            if attack_raw:
                attack_ids = self._resolve_attack_tags(client, pool_uuid, node, attack_raw)
                if attack_ids:
                    desired["attack_tag"] = attack_ids
                else:
                    desired.pop("attack_tag", None)
        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired, node=node)
                log.info("CREATE alert=%s [node=%s]", name, node.name)
                log.debug("CREATE payload=%s", payload)
                res = client.create_resource(pool_uuid, node.id, RESOURCE, payload)
                return self._monitor_result(client, node, res, "create")

            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id}, node=node)
                log.info("UPDATE alert=%s id=%s [node=%s]", name, existing_id, node.name)
                log.debug("UPDATE payload=%s", payload)
                res = client.update_resource(pool_uuid, node.id, RESOURCE, existing_id, payload)
                return self._monitor_result(client, node, res, "update")

            log.info("NOOP alert=%s [node=%s]", name, node.name)
            return {"status": "Success"}

        except Exception as exc:
            msg = str(exc)
            log.error("APPLY FAILED alert=%s [node=%s]: %s", name, node.name, msg)
            return {"status": "Failed", "error": msg}

    @staticmethod
    def _monitor_result(
        client: DirectorClient,  # noqa: ARG002 (kept for parity with Repos importer)
        node: NodeRef,           # noqa: ARG002
        res: Dict[str, Any],
        action: str,             # noqa: ARG002
    ) -> Dict[str, Any]:
        """Normalize async monitor result (kept minimal and consistent)."""
        status = "Success"
        mon_ok = None
        branch = None
        if isinstance(res, dict):
            branch = res.get("monitor_branch")
            mon_ok = res.get("monitor_ok")
            status = res.get("status") or status
            error = res.get("result")

        return {"status": status, "monitor_ok": mon_ok, "monitor_branch": branch, "error": error}

__all__ = ["AlertRulesImporter"]
