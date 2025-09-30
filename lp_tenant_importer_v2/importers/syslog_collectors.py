# lp_tenant_importer_v2/importers/syslog_collectors.py
from __future__ import annotations

"""
Syslog Collectors importer (DirectorSync v2)

Strictly aligned to BaseImporter pipeline and coding style used in the existing
importers (e.g., processing_policies.py, devices.py).

Product truth recap:
- Workbook is filtered by app == "SyslogCollector" (device-scoped only).
- Mandatory fields for CREATE/UPDATE: device_name (resolved to id), charset,
  parser, proxy_condition in {"use_as_proxy", "uses_proxy", "None"}.
- Matrix:
  * use_as_proxy  : proxy_ip = empty, hostname = empty, processpolicy = empty
  * uses_proxy    : proxy_ip required (≥1) & each IP must correspond to a device
                    that has a SyslogCollector with proxy_condition=use_as_proxy
                    (already present on the node or created earlier in this run),
                    hostname required, processpolicy required
  * None          : proxy_ip empty, hostname empty, processpolicy required
- ProcessingPolicy resolution: workbook provides a *source id* that we map to a
  *name* via the "ProcessingPolicies" sheet, then we resolve name → id on the node.
- We deliberately ignore any "log_collector" field in this project.
- We implement a phase-like ordering by yielding all `use_as_proxy` desired rows
  first, then `None`, then `uses_proxy`. During `apply`, when we CREATE a proxy,
  we update an in-memory proxy-IP set so subsequent `uses_proxy` rows see it.

Resulting diff:
- We compare on names (processpolicy_name) and order-insensitive lists (proxy_ip, hostname)
  normalized to CSV strings for subset equality, following the simplicity of other importers.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter
from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError

log = logging.getLogger(__name__)

# ----------------------------- helpers ------------------------------------


_EMPTY = {"", "nan", "none", "null", "-"}


def _is_blank(x: Any) -> bool:
    if x is None:
        return True
    if isinstance(x, float):
        try:
            if pd.isna(x):
                return True
        except Exception:
            pass
    s = str(x).strip()
    return s == "" or s.lower() in _EMPTY


def _s(x: Any) -> str:
    return "" if _is_blank(x) else str(x).strip()


def _split_multi(cell: Any, seps: Tuple[str, ...] = ("|", ",")) -> List[str]:
    raw = _s(cell)
    if not raw:
        return []
    canon = raw
    for s in seps[1:]:
        canon = canon.replace(s, seps[0])
    parts = [p.strip() for p in canon.split(seps[0])]
    return sorted({p for p in parts if p})


def _csv(parts: Iterable[str]) -> str:
    return ",".join(sorted({_s(x) for x in parts if _s(x)}))


def _norm_condition(v: Any) -> str:
    low = _s(v).lower()
    mapping = {"use_as_proxy": "use_as_proxy", "uses_proxy": "uses_proxy", "none": "None"}
    return mapping.get(low, _s(v))


def _node_tag(node: NodeRef) -> str:
    return f"{getattr(node, 'name', '')}|{getattr(node, 'id', '')}"


# ------------------------------ model -------------------------------------


@dataclass(frozen=True)
class _DesiredSC:
    device_name: str
    parser: str
    charset: str
    proxy_condition: str  # "use_as_proxy" | "uses_proxy" | "None"
    proxy_ips: List[str]
    hostnames: List[str]
    processpolicy_name: str  # empty string means "not set"


# ----------------------------- importer -----------------------------------


class SyslogCollectorsImporter(BaseImporter):
    """
    SyslogCollector importer using the BaseImporter pipeline.

    Sheet:
      - "SyslogCollector" (preferred) or "SyslogCollectors" (alias)
    Required columns (case-insensitive):
      - app, device_name, parser, charset, proxy_condition
    Optional columns:
      - proxy_ip (list), hostname (list), processpolicy (source PP id from workbook)
    """

    # BaseImporter contract (we override validate, so required_columns is unused here)
    resource_name: str = "syslog_collectors"
    sheet_names = ("DeviceFetcher","SyslogCollector", "SyslogCollectors")
    required_columns = tuple()

    # Stable subset used by diff engine (node-agnostic)
    compare_keys = ("proxy_condition", "parser", "charset", "proxy_ips", "hostnames", "processpolicy_name")

    # Director API resource name
    RESOURCE = "SyslogCollector"

    # Per-node caches
    _device_name_to_id: Dict[str, Dict[str, str]]          # node.id -> {device_name -> device_id}
    _device_name_to_ip: Dict[str, Dict[str, str]]          # node.id -> {device_name -> device_ip}
    _pp_name_to_id: Dict[str, Dict[str, str]]              # node.id -> {pp_name -> pp_id}
    _pp_id_to_name: Dict[str, Dict[str, str]]              # node.id -> {pp_id -> pp_name}
    _available_proxy_ips: Dict[str, set]                   # node.id -> {ip strings}
    _xlsx_pp_id_to_name: Dict[str, str]                    # workbook-level cache (source id -> name)
    _sheet_key: str                                        # chosen sheet name in this run

    def __init__(self) -> None:
        super().__init__()
        self._device_name_to_id = {}
        self._device_name_to_ip = {}
        self._pp_name_to_id = {}
        self._pp_id_to_name = {}
        self._available_proxy_ips = {}
        self._xlsx_pp_id_to_name = {}
        self._sheet_key = "SyslogCollector"

    # ----------------------------- validate --------------------------------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        """
        Custom validation to support sheet alias and case-tolerant columns.
        """
        # Choose the actual sheet present
        chosen: Optional[str] = None
        for s in self.sheet_names:
            if s in sheets:
                chosen = s
                break
        if not chosen:
            raise ValidationError("Missing required sheet: SyslogCollector (or SyslogCollectors)")

        self._sheet_key = chosen
        df = sheets[chosen]

        # Build lowercase->original column name map
        cols = {str(c).strip().lower(): str(c) for c in df.columns}

        def need(*names: str) -> str:
            for n in names:
                k = n.strip().lower()
                if k in cols:
                    return cols[k]
            raise ValidationError(f"{chosen}: missing required column ({' / '.join(names)})")

        # Required
        need("app")
        need("device_name", "device", "name")
        need("parser")
        need("charset")
        need("proxy_condition", "condition", "mode")

        # Optional columns not enforced; we discover at iter_desired time.

        # Build workbook-level PP source-id -> name mapping if sheet present
        if "ProcessingPolicies" in sheets:
            pp = sheets["ProcessingPolicies"].copy()
            pp.columns = [str(c).strip() for c in pp.columns]

            def pick_col(df: pd.DataFrame, *cands: str) -> Optional[str]:
                for c in cands:
                    if c in df.columns:
                        return c
                return None

            c_id = pick_col(pp, "id", "pp_id", "policy_id")
            c_nm = pick_col(pp, "policy_name", "name")
            if c_id and c_nm:
                self._xlsx_pp_id_to_name = {
                    _s(r[c_id]): _s(r[c_nm])
                    for _, r in pp.iterrows()
                    if not _is_blank(r.get(c_id)) and not _is_blank(r.get(c_nm))
                }
        else:
            self._xlsx_pp_id_to_name = {}

        log.info("syslog_collectors: validation passed (sheet='%s')", chosen)

    # -------------------------- XLSX → desired -----------------------------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        """
        Yield desired rows in three-phase order:
          1) use_as_proxy
          2) None
          3) uses_proxy
        """
        df: pd.DataFrame = sheets[self._sheet_key].copy()
        # Normalize headers (keep original for access)
        cols = {str(c).strip().lower(): str(c) for c in df.columns}

        def col(*names: str) -> Optional[str]:
            for n in names:
                k = n.strip().lower()
                if k in cols:
                    return cols[k]
            return None

        c_app = col("app")
        c_dev = col("device_name", "device", "name")
        c_par = col("parser")
        c_chr = col("charset")
        c_con = col("proxy_condition", "condition", "mode")
        c_pip = col("proxy_ip", "proxy_ips", "proxy ip")
        c_hst = col("hostname", "hostnames")
        c_pps = col("processpolicy", "processingpolicy", "pp_id")

        if not all([c_app, c_dev, c_par, c_chr, c_con]):
            raise ValidationError("SyslogCollector: missing one of required columns")

        # Filter on app == SyslogCollector
        df = df[(df[c_app].astype(str).str.strip() == "SyslogCollector")].copy()

        phase_A: List[Dict[str, Any]] = []
        phase_B: List[Dict[str, Any]] = []
        phase_C: List[Dict[str, Any]] = []

        for _, row in df.iterrows():
            device_name = _s(row[c_dev])
            if not device_name:
                continue  # silently drop unnamed rows (same tolerance as other importers)

            desired = _DesiredSC(
                device_name=device_name,
                parser=_s(row[c_par]),
                charset=_s(row[c_chr]),
                proxy_condition=_norm_condition(row[c_con]),
                proxy_ips=_split_multi(row[c_pip]) if c_pip else [],
                hostnames=_split_multi(row[c_hst]) if c_hst else [],
                processpolicy_name=self._xlsx_pp_id_to_name.get(_s(row[c_pps]), "") if c_pps else "",
            )
            as_dict = {
                "device_name": desired.device_name,
                "parser": desired.parser,
                "charset": desired.charset,
                "proxy_condition": desired.proxy_condition,
                "proxy_ips": desired.proxy_ips,
                "hostnames": desired.hostnames,
                "processpolicy_name": desired.processpolicy_name,
            }

            if desired.proxy_condition == "use_as_proxy":
                phase_A.append(as_dict)
            elif desired.proxy_condition == "None":
                phase_B.append(as_dict)
            else:
                phase_C.append(as_dict)

        # Yield in phase order
        for item in phase_A + phase_B + phase_C:
            yield item

    # --------------------------- canonical (diff) --------------------------

    @staticmethod
    def key_fn(desired_row: Dict[str, Any]) -> str:
        return _s(desired_row.get("device_name"))

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "proxy_condition": _norm_condition(desired_row.get("proxy_condition")),
            "parser": _s(desired_row.get("parser")),
            "charset": _s(desired_row.get("charset")),
            "proxy_ips": _csv(desired_row.get("proxy_ips", [])),
            "hostnames": _csv(desired_row.get("hostnames", [])),
            "processpolicy_name": _s(desired_row.get("processpolicy_name")),
        }

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not existing_obj:
            return None
        return {
            "proxy_condition": _norm_condition(existing_obj.get("proxy_condition")),
            "parser": _s(existing_obj.get("parser")),
            "charset": _s(existing_obj.get("charset")),
            "proxy_ips": _csv(existing_obj.get("proxy_ips") or []),
            "hostnames": _csv(existing_obj.get("hostnames") or []),
            "processpolicy_name": _s(existing_obj.get("processpolicy_name")),
        }

    # ----------------------------- read existing ---------------------------

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        """
        Return {device_name -> existing_obj} for the node, and fill caches:
          - device name → id / ip
          - PP name ↔ id
          - available proxy IPs (devices whose SyslogCollector is use_as_proxy)
        """
        node_t = _node_tag(node)
        log.info("fetch_existing: start [node=%s]", node_t)

        # --- Devices (name/id/ip maps) ---
        self._device_name_to_id[node.id] = {}
        self._device_name_to_ip[node.id] = {}
        dev_raw = client.list_resource(pool_uuid, node.id, "Devices") or []
        dev_items: List[Dict[str, Any]]
        if isinstance(dev_raw, list):
            dev_items = [x for x in dev_raw if isinstance(x, dict)]
        elif isinstance(dev_raw, dict):
            dev_items = (dev_raw.get("data") or dev_raw.get("items") or dev_raw.get("devices") or []) or []
            dev_items = [x for x in dev_items if isinstance(x, dict)]
        else:
            dev_items = []

        def _dev_ip(d: Dict[str, Any]) -> str:
            # Be tolerant to common field names
            for k in ("ip", "ip_address", "ipaddress", "device_ip", "management_ip"):
                v = d.get(k)
                if _s(v):
                    # if list, pick the first IP (Devices importer stores list)
                    if isinstance(v, list) and v:
                        return _s(v[0])
                    return _s(v)
            return ""

        for it in dev_items:
            name = _s(it.get("name"))
            did = _s(it.get("id"))
            if name and did:
                self._device_name_to_id[node.id][name] = did
                self._device_name_to_ip[node.id][name] = _dev_ip(it)

        # --- ProcessingPolicy (PP name/id maps for enriching existing) ---
        self._pp_name_to_id[node.id] = {}
        self._pp_id_to_name[node.id] = {}
        pp_raw = client.list_resource(pool_uuid, node.id, "ProcessingPolicy") or []
        pp_items: List[Dict[str, Any]]
        if isinstance(pp_raw, list):
            pp_items = [x for x in pp_raw if isinstance(x, dict)]
        elif isinstance(pp_raw, dict):
            pp_items = (pp_raw.get("data") or pp_raw.get("items") or pp_raw.get("results") or []) or []
            pp_items = [x for x in pp_items if isinstance(x, dict)]
        else:
            pp_items = []

        for it in pp_items:
            nm = _s(it.get("name") or it.get("policy_name"))
            pid = _s(it.get("id"))
            if nm and pid:
                self._pp_name_to_id[node.id][nm] = pid
                self._pp_id_to_name[node.id][pid] = nm

        # --- Existing SyslogCollector per device + proxy index by device IP ---
        existing: Dict[str, Dict[str, Any]] = {}
        proxy_ips: set = set()

        for dev in dev_items:
            dev_name = _s(dev.get("name"))
            dev_id = _s(dev.get("id"))
            if not dev_name or not dev_id:
                continue
            try:
                plugins = client.list_subresource(
                    pool_uuid, node.id, "Devices", f"{dev_id}/plugins"
                ) or []
            except Exception as exc:  # pragma: no cover (defensive)
                log.error(
                    "fetch_existing: list plugins failed device=%s [node=%s] err=%s",
                    dev_name, node_t, exc
                )
                continue

            # Accept list or dict("data"/"items")
            if isinstance(plugins, dict):
                items = plugins.get("data") or plugins.get("items") or []
            else:
                items = plugins

            for p in items or []:
                if not isinstance(p, dict):
                    continue
                if _s(p.get("app")) != "SyslogCollector":
                    continue

                obj: Dict[str, Any] = {
                    "id": _s(p.get("uuid") or p.get("id")),
                    "device_id": dev_id,
                    "device_name": dev_name,
                    "proxy_condition": _norm_condition(p.get("proxy_condition") or p.get("condition") or p.get("mode")),
                    "parser": _s(p.get("parser")),
                    "charset": _s(p.get("charset")),
                    "proxy_ips": _split_multi(p.get("proxy_ip") or p.get("ips") or p.get("addresses")),
                    "hostnames": _split_multi(p.get("hostname") or p.get("hostnames")),
                }
                # Enrich: PP name from id (if any)
                pp_id = _s(p.get("processpolicy") or p.get("processpolicy_id"))
                obj["processpolicy_name"] = self._pp_id_to_name[node.id].get(pp_id, "")

                existing[dev_name] = obj

                # Build proxy IP index from *device IP* when it's a proxy
                if obj["proxy_condition"] == "use_as_proxy":
                    ip = self._device_name_to_ip[node.id].get(dev_name, "")
                    if ip:
                        proxy_ips.add(ip)

        self._available_proxy_ips[node.id] = proxy_ips
        log.info(
            "fetch_existing: found %d syslog collectors; proxies=%d [node=%s]",
            len(existing), len(proxy_ips), node_t
        )
        return existing

    # --------------------------- payload builders ---------------------------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build the POST payload. Device id and PP id are resolved in apply()
        using per-node caches and the _current_node sentinel.
        """
        d = {k: v for k, v in desired_row.items()}
        # Resolve device id
        node = getattr(self, "_current_node", None)
        if node is None:
            raise RuntimeError("current node not set in apply()")

        dev_id = self._device_name_to_id.get(node.id, {}).get(_s(d.get("device_name")) or "")
        if not dev_id:
            # apply() handles SKIP logic; raise here to surface neat error upstream
            raise RuntimeError(f"Device not found: '{_s(d.get('device_name'))}'")

        payload: Dict[str, Any] = {
            "device_id": dev_id,
            "proxy_condition": _norm_condition(d.get("proxy_condition")),
            "parser": _s(d.get("parser")),
            "charset": _s(d.get("charset")),
        }

        cond = payload["proxy_condition"]
        if cond == "use_as_proxy":
            # must be empty
            return payload

        # resolve PP id (required for None/uses_proxy)
        pp_name = _s(d.get("processpolicy_name"))
        if pp_name:
            pp_id = self._pp_name_to_id.get(node.id, {}).get(pp_name, "")
            if pp_id:
                payload["processpolicy"] = pp_id

        if cond == "None":
            # lists must be empty; processpolicy already set (if known)
            return payload

        # uses_proxy
        ips = [x for x in d.get("proxy_ips", []) if _s(x)]
        host = [x for x in d.get("hostnames", []) if _s(x)]
        if ips:
            payload["proxy_ip"] = ips
        if host:
            payload["hostname"] = host
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        p = self.build_payload_create(desired_row)
        # The Director API usually expects the id at path level; some endpoints also
        # accept an 'id' in body. Be tolerant but avoid injecting unless necessary.
        return p

    # -------------------------------- apply --------------------------------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Apply decision with strict validation and dependency checks on the *node*.
        Returns a dict suitable for BaseImporter to enrich the report row.
        """
        # Make node available to payload builders
        self._current_node = node  # type: ignore[attr-defined]

        desired = dict(decision.desired or {})
        dev_name = _s(desired.get("device_name")) or "(unnamed)"
        node_t = _node_tag(node)
        cond = _norm_condition(desired.get("proxy_condition"))
        parser = _s(desired.get("parser"))
        charset = _s(desired.get("charset"))
        pp_name = _s(desired.get("processpolicy_name"))
        ips = [x for x in desired.get("proxy_ips", []) if _s(x)]
        hosts = [x for x in desired.get("hostnames", []) if _s(x)]

        # ---- Mandatory field checks (common) ----
        if not parser or not charset or not cond:
            msg = "Missing mandatory fields (parser/charset/proxy_condition)"
            log.warning("apply: SKIP device=%s reason=%s [node=%s]", dev_name, msg, node_t)
            return {"status": "Skipped", "error": msg}

        # ---- Matrix enforcement ----
        if cond == "use_as_proxy":
            if ips or hosts or pp_name:
                msg = "use_as_proxy requires empty proxy_ip, hostname, processpolicy"
                log.warning("apply: SKIP device=%s reason=%s [node=%s]", dev_name, msg, node_t)
                return {"status": "Skipped", "error": msg}

        elif cond == "None":
            if ips or hosts or not pp_name:
                msg = "None requires processpolicy (and empty proxy_ip/hostname)"
                log.warning("apply: SKIP device=%s reason=%s [node=%s]", dev_name, msg, node_t)
                return {"status": "Skipped", "error": msg}
            if pp_name not in self._pp_name_to_id.get(node.id, {}):
                msg = f"Unknown processpolicy on node: '{pp_name}'"
                log.warning("apply: SKIP device=%s reason=%s [node=%s]", dev_name, msg, node_t)
                return {"status": "Skipped", "error": msg}

        elif cond == "uses_proxy":
            if not ips or not hosts or not pp_name:
                msg = "uses_proxy requires proxy_ip[], hostname[], and processpolicy"
                log.warning("apply: SKIP device=%s reason=%s [node=%s]", dev_name, msg, node_t)
                return {"status": "Skipped", "error": msg}
            if pp_name not in self._pp_name_to_id.get(node.id, {}):
                msg = f"Unknown processpolicy on node: '{pp_name}'"
                log.warning("apply: SKIP device=%s reason=%s [node=%s]", dev_name, msg, node_t)
                return {"status": "Skipped", "error": msg}
            # Check proxy IP presence on node (post "phase A" logical order)
            missing = [ip for ip in ips if ip not in self._available_proxy_ips.get(node.id, set())]
            if missing:
                msg = "Missing proxy IP(s) on node (no use_as_proxy present): " + ", ".join(missing)
                log.warning("apply: SKIP device=%s reason=%s [node=%s]", dev_name, msg, node_t)
                return {"status": "Skipped", "error": msg}

        else:
            msg = f"Invalid proxy_condition: '{cond}'"
            log.warning("apply: SKIP device=%s reason=%s [node=%s]", dev_name, msg, node_t)
            return {"status": "Skipped", "error": msg}

        # ---- Build payload and call API ----
        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                log.info("CREATE syslog_collector device=%s [node=%s]", dev_name, node.name)
                log.debug("CREATE payload=%s", payload)
                res = client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)

                # If we created a *proxy* (use_as_proxy), update in-memory proxy set so
                # subsequent uses_proxy rows can pass within the same run.
                if cond == "use_as_proxy":
                    # Add this device's IP to the available set (if known)
                    dev_ip = self._device_name_to_ip.get(node.id, {}).get(dev_name, "")
                    if dev_ip:
                        self._available_proxy_ips.setdefault(node.id, set()).add(dev_ip)

                return {
                    "status": res.get("status"),
                    "monitor_ok": res.get("monitor_ok"),
                    "monitor_branch": res.get("monitor_branch"),
                }

            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id})
                log.info("UPDATE syslog_collector device=%s id=%s [node=%s]", dev_name, existing_id, node.name)
                log.debug("UPDATE payload=%s", payload)
                res = client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)
                return {
                    "status": res.get("status"),
                    "monitor_ok": res.get("monitor_ok"),
                    "monitor_branch": res.get("monitor_branch"),
                }

            # NOOP (and SKIP surfaced above as 'status: Skipped')
            log.info("NOOP syslog_collector device=%s [node=%s]", dev_name, node.name)
            return {"status": "Success"}

        except Exception:  # pragma: no cover — defensive
            log.exception("API error for syslog_collector device=%s [node=%s]", dev_name, node.name)
            raise
