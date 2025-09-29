from __future__ import annotations

"""
Syslog Collectors importer (DirectorSync v2) — PATCH COMPLET

Objectifs du patch
------------------
• Résoudre les Policies de traitement (ProcessingPolicy) :
    XLSX(DeviceFetcher.processpolicy=ID source) → XLSX(ProcessingPolicy.policy_name)
    → API(nœud).policy_name → policy_id DESTINATION.
  Si non résoluble : SKIP explicite avec message.

• Orchestration proxy :
    - Créer/laisser créer d'abord les collectors `use_as_proxy`.
    - Pour les collectors `uses_proxy`, vérifier via un cache local si
      toutes les IP de `proxy_ip` sont présentes (proxys existants ou
      à créer dans ce batch). Sinon : SKIP explicite.

• Conformité API (payload):
    - `use_as_proxy`  → ne PAS envoyer hostname / proxy_ip / processpolicy.
    - `direct` (None) → ne PAS envoyer hostname / proxy_ip, DOIT envoyer processpolicy (ID DEST).
    - `uses_proxy`    → DOIT envoyer processpolicy (ID DEST) + proxy_ip.

• Rapport fidèle :
    - Les cas invalides/ingouvernables sont SKIP avant POST
      (évite faux "Success" quand le monitor échoue plus tard).

• Diff stable :
    - Compare sur un sous-ensemble canonique en mappant processpolicy → NOM
      côté existing (via API) et côté desired (via XLSX), pour éviter
      les faux diff dus aux IDs.

Pipeline v2 réutilisé : load → validate → fetch → diff → plan → apply → report
"""

import logging
from typing import Any, Dict, Iterable, List, Tuple, Set

import pandas as pd

from .base import BaseImporter, NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError

log = logging.getLogger(__name__)


# ------------------------------- helpers ------------------------------------

def _to_str(v: Any) -> str:
    """Return a clean string without NaNs/None and with surrounding whitespace stripped."""
    if v is None:
        return ""
    try:
        if pd.isna(v):  # type: ignore[attr-defined]
            return ""
    except Exception:  # pragma: no cover — defensive
        pass
    return str(v).strip()


def _split_multi(cell: Any, seps: Tuple[str, ...] = ("|", ",")) -> List[str]:
    """Split multi-valued cells on '|' or ',' and return trimmed parts (empty if none)."""
    raw = _to_str(cell)
    if not raw:
        return []
    canon = raw
    for s in seps[1:]:
        canon = canon.replace(s, seps[0])
    return [p.strip() for p in canon.split(seps[0]) if p.strip()]


_ALLOWED_PROXY = {"use_as_proxy", "uses_proxy"}


def _norm_proxy_condition(v: Any) -> str | None:
    s = _to_str(v)
    if not s:
        return None
    low = s.lower()
    if low in _ALLOWED_PROXY:
        return low
    if low in {"none", "no", "direct"}:
        return None
    # keep original for clearer error messages
    return s


# ----------------------------- importer --------------------------------------

class SyslogCollectorsImporter(BaseImporter):
    """Importer for **SyslogCollector** resources avec mapping PP & garde-fous proxy.

    Sheets attendues :
      • "DeviceFetcher" (lignes filtrées app == "SyslogCollector")
      • "ProcessingPolicy" (optionnelle mais nécessaire si des rows
         requièrent une processpolicy) : doit contenir ID source → NOM.

    Sous-ensemble stable comparé (listes triées) :
      proxy_condition, processpolicy (NOM), proxy_ip[], hostname[], charset, parser
    """

    resource_name: str = "syslog_collectors"
    sheet_names = ("DeviceFetcher", "ProcessingPolicy")

    # Diff subset (processpolicy = NOM, pas ID) :
    compare_keys = (
        "proxy_condition",
        "processpolicy",   # NOM
        "proxy_ip",
        "hostname",
        "charset",
        "parser",
    )

    # Director API resources
    RESOURCE = "SyslogCollector"
    DEVICES_RESOURCE = "Devices"
    PROCESSPOLICY_RESOURCES = ("ProcessingPolicy", "ProcessPolicy")

    # per-node caches
    _dev_name_to_id: Dict[str, Dict[str, str]]        # node_id -> {device_name -> device_id}
    _dev_id_to_name: Dict[str, Dict[str, str]]        # node_id -> {device_id -> device_name}
    _pp_name_to_id: Dict[str, Dict[str, str]]         # node_id -> {policy_name -> policy_id}
    _pp_id_to_name: Dict[str, Dict[str, str]]         # node_id -> {policy_id -> policy_name}
    _proxy_ip_cache: Dict[str, Set[str]]              # node_id -> {proxy_ip}

    # XLSX cache (global au tenant)
    _pp_source_to_name: Dict[str, str]                # source_id -> policy_name

    def __init__(self) -> None:
        self._dev_name_to_id = {}
        self._dev_id_to_name = {}
        self._pp_name_to_id = {}
        self._pp_id_to_name = {}
        self._proxy_ip_cache = {}
        self._pp_source_to_name = {}
        # context for payload builders
        self._current_node: NodeRef | None = None
        self._current_client: DirectorClient | None = None
        self._current_pool: str | None = None

    # ---------------------------- validation ---------------------------------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        if "DeviceFetcher" not in sheets:
            raise ValidationError("Missing required sheet: DeviceFetcher")
        df = sheets["DeviceFetcher"].copy()
        cols = {str(c).strip().lower(): str(c) for c in df.columns}

        def col(*names: str) -> str | None:
            for n in names:
                k = n.strip().lower()
                if k in cols:
                    return cols[k]
            return None

        c_name = col("device_name", "name")
        c_app = col("app")
        c_hostname = col("hostname", "hostnames")
        c_parser = col("parser")
        c_charset = col("charset")
        c_pp = col("processpolicy", "process_policy")
        c_pc = col("proxy_condition")
        c_pip = col("proxy_ip", "proxy ips", "proxy-ips")

        needed = [c_name, c_app, c_parser, c_charset]
        if not all(needed):
            raise ValidationError(
                "DeviceFetcher: missing one of required columns (device_name, app, charset, parser)"
            )

        # Soft check: au moins une ligne SyslogCollector
        mask = df[c_app].astype(str).str.strip().str.lower() == "syslogcollector"
        if not mask.any():
            raise ValidationError("DeviceFetcher: no rows with app == 'SyslogCollector'")

        # Feuille ProcessingPolicy → cache source_id → name (optionnelle)
        if "ProcessingPolicy" in sheets:
            ppdf = sheets["ProcessingPolicy"].copy()
            pcols = {str(c).strip().lower(): str(c) for c in ppdf.columns}

            def pcol(*names: str) -> str | None:
                for n in names:
                    k = n.strip().lower()
                    if k in pcols:
                        return pcols[k]
                return None

            cp_id = pcol("policy_id", "id")
            cp_name = pcol("policy_name", "name", "title")
            if cp_id and cp_name:
                for _, row in ppdf.iterrows():
                    sid = _to_str(row[cp_id])
                    sname = _to_str(row[cp_name])
                    if sid and sname:
                        self._pp_source_to_name[sid] = sname
            else:
                log.warning("ProcessingPolicy sheet present but missing id/name columns; will try name-only resolution from DeviceFetcher if provided.")
        else:
            log.info("No ProcessingPolicy sheet; will require 'processpolicy' as NAME in DeviceFetcher or skip when needed.")

        # Mémoriser les alias de colonnes pour iter_desired
        self._colmap = {
            "device_name": c_name,
            "app": c_app,
            "hostname": c_hostname,
            "parser": c_parser,
            "charset": c_charset,
            "processpolicy": c_pp,
            "proxy_condition": c_pc,
            "proxy_ip": c_pip,
        }

    # ------------------------- XLSX → desired rows ---------------------------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets["DeviceFetcher"].copy()
        cm = self._colmap

        for _, row in df.iterrows():
            if _to_str(row[cm["app"]]).lower() != "syslogcollector":
                continue

            device_name = _to_str(row[cm["device_name"]])
            if not device_name:
                continue

            desired: Dict[str, Any] = {
                "device_name": device_name,
                "hostname": _split_multi(row[cm["hostname"]]) if cm.get("hostname") else [],
                "parser": _to_str(row[cm["parser"]]),
                "charset": _to_str(row[cm["charset"]]),
                "proxy_condition": _norm_proxy_condition(row[cm["proxy_condition"]]) if cm.get("proxy_condition") else None,
                "proxy_ip": _split_multi(row[cm["proxy_ip"]]) if cm.get("proxy_ip") else [],
            }

            # processpolicy: on lit ce qu'il y a dans DeviceFetcher
            #  - si c'est un ID source, on le traduira en NOM via _pp_source_to_name
            #  - s'il n'existe pas et qu'on est en mode uses_proxy/direct, on pourra SKIP
            if cm.get("processpolicy"):
                desired["processpolicy_source"] = _to_str(row[cm["processpolicy"]])
            else:
                desired["processpolicy_source"] = ""

            # Enrichissement d'aide pour diff/rapport : NOM si dispo dès maintenant
            src = desired.get("processpolicy_source", "")
            pp_name = self._pp_source_to_name.get(src) or src  # si DF donne déjà un nom
            desired["processpolicy_name"] = _to_str(pp_name)

            yield desired

    # ------------------------ canonicalization (diff) ------------------------

    @staticmethod
    def key_fn(desired_row: Dict[str, Any]) -> str:
        return _to_str(desired_row.get("device_name"))

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "proxy_condition": desired_row.get("proxy_condition"),
            # IMPORTANT: on compare par NOM pour stabilité
            "processpolicy": _to_str(desired_row.get("processpolicy_name")),
            "proxy_ip": sorted([_to_str(x) for x in desired_row.get("proxy_ip", [])]),
            "hostname": sorted([_to_str(x) for x in desired_row.get("hostname", [])]),
            "charset": _to_str(desired_row.get("charset")),
            "parser": _to_str(desired_row.get("parser")),
        }

    @staticmethod
    def _g(obj: Dict[str, Any] | None, key: str) -> Any:
        if not obj:
            return None
        if key in obj:
            return obj.get(key)
        data = obj.get("data") if isinstance(obj, dict) else None
        return (data or {}).get(key)

    def _ensure_pp_maps(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        if node.id in self._pp_name_to_id and node.id in self._pp_id_to_name:
            return
        name_to_id: Dict[str, str] = {}
        id_to_name: Dict[str, str] = {}
        for res in self.PROCESSPOLICY_RESOURCES:
            try:
                raw = client.list_resource(pool_uuid, node.id, res) or []
            except Exception:
                log.exception("Failed listing %s on node=%s", res, node.name)
                continue
            items: List[Dict[str, Any]]
            if isinstance(raw, list):
                items = [x for x in raw if isinstance(x, dict)]
            elif isinstance(raw, dict):
                items = [x for x in (raw.get("items") or raw.get("data") or raw.get("results") or []) if isinstance(x, dict)]
            else:
                items = []
            for it in items:
                pid = _to_str(it.get("id") or it.get("policy_id"))
                pname = _to_str(it.get("name") or it.get("policy_name") or it.get("title"))
                if pid and pname:
                    name_to_id[pname] = pid
                    id_to_name[pid] = pname
        self._pp_name_to_id[node.id] = name_to_id
        self._pp_id_to_name[node.id] = id_to_name
        log.debug("PP cache built: %d policies [node=%s]", len(name_to_id), node.name)

    def _resolve_pp_dest_id(self, desired_row: Dict[str, Any]) -> tuple[str | None, str | None]:
        """Retourne (dest_id, reason_if_missing). Utilise _current_* context."""
        node = self._current_node
        client = self._current_client
        pool = self._current_pool
        if not node or not client or not pool:
            return None, "Internal error: current context not set"

        src = _to_str(desired_row.get("processpolicy_source"))
        name = _to_str(self._pp_source_to_name.get(src) or desired_row.get("processpolicy_name"))
        if not name:
            return None, "ProcessingPolicy name not available from XLSX"

        self._ensure_pp_maps(client, pool, node)
        dest = self._pp_name_to_id.get(node.id, {}).get(name)
        if not dest:
            return None, f"ProcessingPolicy not found on node '{node.name}': {name}"
        return dest, None

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if not existing_obj:
            return None
        # Normalize lists and strings
        proxy_ip = self._g(existing_obj, "proxy_ip") or []
        if not isinstance(proxy_ip, list):
            proxy_ip = [proxy_ip] if _to_str(proxy_ip) else []
        hostname = self._g(existing_obj, "hostname") or []
        if not isinstance(hostname, list):
            hostname = [hostname] if _to_str(hostname) else []

        # Map processpolicy ID → NOM (via cache si dispo)
        pid = _to_str(self._g(existing_obj, "processpolicy"))
        pname = None
        node = getattr(self, "_current_node", None)
        if node and node.id in self._pp_id_to_name:
            pname = self._pp_id_to_name[node.id].get(pid)

        return {
            "proxy_condition": _to_str(self._g(existing_obj, "proxy_condition")) or None,
            "processpolicy": _to_str(pname) if pname else _to_str(pid),  # tombe sur ID si nom inconnu
            "proxy_ip": sorted([_to_str(x) for x in proxy_ip]),
            "hostname": sorted([_to_str(x) for x in hostname]),
            "charset": _to_str(self._g(existing_obj, "charset")),
            "parser": _to_str(self._g(existing_obj, "parser")),
        }

    # ----------------------------- read existing -----------------------------

    def _ensure_device_maps(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        if node.id in self._dev_name_to_id and node.id in self._dev_id_to_name:
            return
        raw = client.list_resource(pool_uuid, node.id, self.DEVICES_RESOURCE) or []
        id_to_name: Dict[str, str] = {}
        name_to_id: Dict[str, str] = {}

        def _add(gid: str, gname: str) -> None:
            if gid and gname:
                id_to_name[gid] = gname
                name_to_id[gname] = gid

        if isinstance(raw, list):
            items = [x for x in raw if isinstance(x, dict)]
        elif isinstance(raw, dict):
            items = [x for x in (raw.get("items") or raw.get("data") or raw.get("devices") or raw.get("results") or []) if isinstance(x, dict)]
        else:
            items = []
        for item in items:
            gid = _to_str(item.get("id") or item.get("device_id"))
            gname = _to_str(item.get("name") or item.get("device_name"))
            if gid and gname:
                _add(gid, gname)
        self._dev_id_to_name[node.id] = id_to_name
        self._dev_name_to_id[node.id] = name_to_id
        log.debug("Device cache built: %d devices [node=%s]", len(id_to_name), node.name)

    def _register_proxy_candidates_from_existing(self, items: List[Dict[str, Any]], node: NodeRef) -> None:
        """Alimente le cache proxy avec ce qu'on peut déduire du payload retourné."""
        s = self._proxy_ip_cache.setdefault(node.id, set())
        for it in items:
            pc = _to_str(it.get("proxy_condition")).lower()
            # Certaines versions exposent encore des hosts/ips sur use_as_proxy en lecture.
            if pc == "use_as_proxy":
                hosts = (
                    self._g(it, "hostname")
                    or self._g(it, "hostnames")
                    or self._g(it, "ip")
                    or self._g(it, "ips")
                    or []
                )
                if not isinstance(hosts, list):
                    hosts = [hosts] if _to_str(hosts) else []
                for h in hosts:
                    if _to_str(h):
                        s.add(_to_str(h))
            # On ajoute aussi les proxy_ip des collectors uses_proxy existants
            pips = self._g(it, "proxy_ip") or []
            if not isinstance(pips, list):
                pips = [pips] if _to_str(pips) else []
            for ip in pips:
                if _to_str(ip):
                    s.add(_to_str(ip))

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        # Contexte pour canon_existing (mapping PP id→nom)
        self._current_node = node  # type: ignore[attr-defined]
        self._current_client = client  # type: ignore[attr-defined]
        self._current_pool = pool_uuid  # type: ignore[attr-defined]
        self._ensure_pp_maps(client, pool_uuid, node)
        self._ensure_device_maps(client, pool_uuid, node)

        # Certaines versions ne supportent pas le GET sur SyslogCollector (405).
        try:
            data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []
        except Exception:
            log.exception("Failed listing %s on node=%s — treating as empty list", self.RESOURCE, node.name)
            data = []

        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            items_any = (
                data.get("items") or data.get("data") or data.get("collectors") or data.get("results") or []
            )
            items = [x for x in items_any if isinstance(x, dict)]
        else:  # pragma: no cover — defensive
            items = []

        # Proxy cache depuis l'existant (meilleure chance d'éviter faux Success)
        self._register_proxy_candidates_from_existing(items, node)

        id_to_name = self._dev_id_to_name.get(node.id, {})
        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            dev_id = _to_str(it.get("device_id") or self._g(it, "device_id"))
            dev_name = id_to_name.get(dev_id) or _to_str(it.get("device_name"))
            key = dev_name or dev_id or ""
            if not key:
                continue
            out[key] = dict(it)
        return out

    # --------------------------- payload builders ----------------------------

    def _device_id_for_name(self, node: NodeRef, name: str) -> str | None:
        name_to_id = self._dev_name_to_id.get(node.id, {})
        return name_to_id.get(name) or name_to_id.get(name.strip())

    def _validate_proxy_combo(self, desired: Dict[str, Any]) -> tuple[bool, str | None]:
        pc = desired.get("proxy_condition")
        src = _to_str(desired.get("processpolicy_source"))
        name = _to_str(desired.get("processpolicy_name"))
        pips: List[str] = desired.get("proxy_ip", []) or []

        if pc == "use_as_proxy":
            # charset/parser requis par UI/API, mais pas de hostname/proxy_ip/pp dans payload
            if not desired.get("charset") or not desired.get("parser"):
                return False, "Missing charset or parser"
            return True, None

        if pc == "uses_proxy":
            if (not src and not name):
                return False, "Missing processpolicy (XLSX)"
            if not pips:
                return False, "Missing proxy_ip"
            if not desired.get("charset") or not desired.get("parser"):
                return False, "Missing charset or parser"
            return True, None

        # direct (None)
        if (not src and not name) or (not desired.get("charset") or not desired.get("parser")):
            return False, "Missing processpolicy, charset, or parser"
        if pips:
            return False, "Unexpected proxy_ip for direct collector"
        return True, None

    def _known_proxies_for_node(self, node: NodeRef) -> Set[str]:
        return self._proxy_ip_cache.setdefault(node.id, set())

    def _inject_proxy_candidates_from_desired(self, desired: Dict[str, Any], node: NodeRef) -> None:
        # Si use_as_proxy dans XLSX a des hostnames (souvent des IP), on les enregistre comme proxys prévus
        if desired.get("proxy_condition") == "use_as_proxy":
            s = self._proxy_ip_cache.setdefault(node.id, set())
            for h in desired.get("hostname", []) or []:
                if _to_str(h):
                    s.add(_to_str(h))

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        node = getattr(self, "_current_node", None)
        client = getattr(self, "_current_client", None)
        pool = getattr(self, "_current_pool", None)
        if not node or not client or not pool:
            raise RuntimeError("Internal error: current context not set")

        dev_name = _to_str(desired_row.get("device_name"))
        dev_id = self._device_id_for_name(node, dev_name)
        if not dev_id:
            raise ValidationError(f"Unknown device_name on node '{node.name}': {dev_name}")

        ok, err = self._validate_proxy_combo(desired_row)
        if not ok:
            raise ValidationError(f"{dev_name}: {err}")

        # Règles API : 
        # - use_as_proxy / direct → ne pas envoyer hostname/proxy_ip
        # - uses_proxy → envoyer proxy_ip + processpolicy (ID DEST)
        pc = desired_row.get("proxy_condition")

        payload: Dict[str, Any] = {
            "device_id": dev_id,
            "charset": _to_str(desired_row.get("charset")),
            "parser": _to_str(desired_row.get("parser")),
        }
        if pc is not None:
            payload["proxy_condition"] = pc

        # processpolicy résolution → ID DEST selon pc
        if pc in ("uses_proxy", None):  # uses_proxy ou direct
            dest_id, reason = self._resolve_pp_dest_id(desired_row)
            if not dest_id:
                raise ValidationError(f"{dev_name}: {reason}")
            payload["processpolicy"] = dest_id

        if pc == "uses_proxy":
            payload["proxy_ip"] = [x for x in desired_row.get("proxy_ip", []) if _to_str(x)]
            # hostname facultatif côté API; on ne l'envoie que s'il est fourni
            hosts = [x for x in desired_row.get("hostname", []) if _to_str(x)]
            if hosts:
                payload["hostname"] = hosts
        # else: use_as_proxy/direct → ne pas inclure hostname/proxy_ip

        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        p = self.build_payload_create(desired_row)
        if existing_obj and existing_obj.get("id"):
            p["id"] = _to_str(existing_obj["id"])
        return p

    # -------------------------------- apply ----------------------------------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        # Contexte pour builders/mapping
        self._current_node = node  # type: ignore[attr-defined]
        self._current_client = client  # type: ignore[attr-defined]
        self._current_pool = pool_uuid  # type: ignore[attr-defined]

        desired = decision.desired or {}
        dev_name = _to_str(desired.get("device_name")) or "(unnamed)"

        # Alimenter le cache des proxys avec les use_as_proxy prévus dans ce batch
        self._inject_proxy_candidates_from_desired(desired, node)

        # Skip proactif pour uses_proxy si proxys inconnus
        pc = desired.get("proxy_condition")
        if pc == "uses_proxy":
            wanted = [ip for ip in (desired.get("proxy_ip") or []) if _to_str(ip)]
            known = self._known_proxies_for_node(node)
            missing = [ip for ip in wanted if ip not in known]
            if missing:
                msg = (
                    f"Skipped: proxy_ip not found on node '{node.name}': "
                    + ", ".join(missing)
                    + ". Create the corresponding 'use_as_proxy' collectors first."
                )
                log.warning("SKIP uses_proxy collector for device=%s [node=%s]: %s", dev_name, node.name, msg)
                return {"status": "Skipped", "reason": msg}

        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                log.info("CREATE syslog_collector device=%s [node=%s]", dev_name, node.name)
                log.debug("CREATE payload=%s", payload)
                return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)

            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id})
                log.info(
                    "UPDATE syslog_collector device=%s id=%s [node=%s]",
                    dev_name,
                    existing_id,
                    node.name,
                )
                log.debug("UPDATE payload=%s", payload)
                return client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)

            # NOOP / SKIP
            log.info("NOOP syslog_collector device=%s [node=%s]", dev_name, node.name)
            return {"status": "Success"}
        except Exception:  # pragma: no cover — defensive
            log.exception("API error for syslog_collector device=%s [node=%s]", dev_name, node.name)
            raise
