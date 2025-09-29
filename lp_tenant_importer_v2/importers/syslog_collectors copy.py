from __future__ import annotations

"""
Syslog Collectors importer (DirectorSync v2)

Idempotent algorithm using the common v2 pipeline:
  load → validate → fetch → diff → plan → apply → report

Spreadsheet contract (sheet "DeviceFetcher"): rows where app == "SyslogCollector".
Conditional requirements depend on proxy_condition:

- use_as_proxy:
    * MUST: parser, charset
    * MUST NOT: hostname, proxy_ip, processpolicy (omit keys entirely)
    * Notes: proxy endpoints (IPs) live on the Device object itself.

- uses_proxy:
    * MUST: processpolicy, proxy_ip, parser, charset
    * Optional: hostname (kept if present)
    * Creation is SKIPPED if each proxy_ip is not found among known proxy
      endpoints on the node (derived from Devices + use_as_proxy collectors).

- direct (None):
    * MUST: processpolicy, parser, charset
    * MUST NOT: hostname, proxy_ip (omit keys entirely)

Stable comparison subset (order-insensitive lists):
  proxy_condition, processpolicy, proxy_ip[], hostname[], charset, parser

Discovery of existing collectors:
- Prefer walking Devices → plugins and filtering app == "SyslogCollector"
  because some Director versions return 405 on GET list(SyslogCollector).
- We build caches per node:
    • device id ↔ name
    • device id → IPs/hostnames
    • proxy IP set (from devices that have a use_as_proxy collector)

Monitoring is delegated to DirectorClient (URL/job-id branches).
"""

import logging
from typing import Any, Dict, Iterable, List, Tuple, Optional, Set

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
    """Split multi-valued cells and return trimmed parts (empty if none)."""
    raw = _to_str(cell)
    if not raw:
        return []
    canon = raw
    for s in seps[1:]:
        canon = canon.replace(s, seps[0])
    return [p.strip() for p in canon.split(seps[0]) if p.strip()]


_ALLOWED_PROXY = {"use_as_proxy", "uses_proxy"}


def _norm_proxy_condition(v: Any) -> Optional[str]:
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
    """Importer for **SyslogCollector** resources.

    Sheet: "DeviceFetcher" (filtered to rows where app == "SyslogCollector").

    We compare a stable subset and rely on :class:`BaseImporter` for the pipeline.
    """

    resource_name: str = "syslog_collectors"
    sheet_names = ("DeviceFetcher",)
    required_columns = tuple()  # custom validation below

    # Stable subset for diffing (order-insensitive fields must be normalized):
    compare_keys = (
        "proxy_condition",
        "processpolicy",
        "proxy_ip",
        "hostname",
        "charset",
        "parser",
    )

    # Director API resource segment (adjust if your Director version differs)
    RESOURCE = "SyslogCollector"
    DEVICES_RESOURCE = "Devices"

    # per-node caches
    _dev_name_to_id: Dict[str, Dict[str, str]]            # node_id -> {device_name -> device_id}
    _dev_id_to_name: Dict[str, Dict[str, str]]            # node_id -> {device_id -> device_name}
    _dev_id_to_ips: Dict[str, Dict[str, List[str]]]       # node_id -> {device_id -> [ips/hostnames]}
    _proxy_ips: Dict[str, Set[str]]                       # node_id -> {proxy_ip,...}

    def __init__(self) -> None:
        self._dev_name_to_id = {}
        self._dev_id_to_name = {}
        self._dev_id_to_ips = {}
        self._proxy_ips = {}

    # ---------------------------- validation ---------------------------------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        if "DeviceFetcher" not in sheets:
            raise ValidationError("Missing required sheet: DeviceFetcher")
        df = sheets["DeviceFetcher"].copy()
        cols = {str(c).strip().lower(): str(c) for c in df.columns}

        def col(*names: str) -> Optional[str]:
            for n in names:
                k = n.strip().lower()
                if k in cols:
                    return cols[k]
            return None

        required_soft = {
            "device_name": col("device_name", "name"),
            "charset": col("charset"),
            "parser": col("parser"),
            "app": col("app"),
        }
        missing = [k for k, v in required_soft.items() if not v]
        if missing:
            raise ValidationError(
                "DeviceFetcher: missing required column(s): " + ", ".join(missing)
            )

        # Soft validation: ensure at least one row targets SyslogCollector
        app_col = required_soft["app"]
        mask = df[app_col].astype(str).str.strip().str.lower() == "syslogcollector"
        if not mask.any():
            raise ValidationError("DeviceFetcher: no rows with app == 'SyslogCollector'")

    # ------------------------- XLSX → desired rows ---------------------------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets["DeviceFetcher"].copy()
        cols = {str(c).strip().lower(): str(c) for c in df.columns}

        def col(*names: str) -> Optional[str]:
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

        if not all([c_name, c_app, c_parser, c_charset]):
            raise ValidationError(
                "DeviceFetcher: missing one of required columns (device_name, charset, parser, app)"
            )

        for _, row in df.iterrows():
            # filter
            if _to_str(row[c_app]).lower() != "syslogcollector":
                continue

            device_name = _to_str(row[c_name])
            if not device_name:
                continue

            desired: Dict[str, Any] = {
                "device_name": device_name,
                "hostname": _split_multi(row[c_hostname]) if c_hostname else [],
                "parser": _to_str(row[c_parser]),
                "charset": _to_str(row[c_charset]),
                "processpolicy": _to_str(row[c_pp]) if c_pp else "",
                "proxy_condition": _norm_proxy_condition(row[c_pc]) if c_pc else None,
                "proxy_ip": _split_multi(row[c_pip]) if c_pip else [],
            }

            # Row-level validation according to proxy_condition
            pc = desired["proxy_condition"]
            if pc == "use_as_proxy":
                # MUST: parser, charset; MUST NOT: hostname, proxy_ip, processpolicy
                if desired["hostname"]:
                    raise ValidationError(
                        f"{device_name}: 'hostname' must be empty for use_as_proxy (IPs live on Device)"
                    )
                if desired["proxy_ip"]:
                    raise ValidationError(f"{device_name}: 'proxy_ip' must be empty for use_as_proxy")
                if desired["processpolicy"]:
                    raise ValidationError(f"{device_name}: 'processpolicy' must be empty for use_as_proxy")
                if not desired["parser"] or not desired["charset"]:
                    raise ValidationError(f"{device_name}: 'parser' and 'charset' are required")
            elif pc == "uses_proxy":
                # MUST: proxy_ip, processpolicy, parser, charset
                if not desired["proxy_ip"]:
                    raise ValidationError(f"{device_name}: 'proxy_ip' is required for uses_proxy")
                if not desired["processpolicy"]:
                    raise ValidationError(f"{device_name}: 'processpolicy' is required for uses_proxy")
                if not desired["parser"] or not desired["charset"]:
                    raise ValidationError(f"{device_name}: 'parser' and 'charset' are required")
            else:
                # direct (None)
                if not desired["processpolicy"] or not desired["parser"] or not desired["charset"]:
                    raise ValidationError(
                        f"{device_name}: 'processpolicy', 'parser', 'charset' are required for direct collectors"
                    )
                if desired["proxy_ip"]:
                    raise ValidationError(f"{device_name}: 'proxy_ip' must be empty for direct collectors")
                if desired["hostname"]:
                    # Per API message: hostname must NOT be present when proxy_condition is None
                    raise ValidationError(f"{device_name}: 'hostname' must be empty for direct collectors")

            yield desired

    # ------------------------ canonicalization (diff) ------------------------

    @staticmethod
    def key_fn(desired_row: Dict[str, Any]) -> str:
        return _to_str(desired_row.get("device_name"))

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "proxy_condition": desired_row.get("proxy_condition"),
            "processpolicy": _to_str(desired_row.get("processpolicy")),
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

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Optional[Dict[str, Any]]:
        if not existing_obj:
            return None

        # Normalize lists
        def _as_list(v: Any) -> List[str]:
            if v is None:
                return []
            if isinstance(v, list):
                return [_to_str(x) for x in v if _to_str(x)]
            s = _to_str(v)
            return [s] if s else []

        proxy_ip = _as_list(self._g(existing_obj, "proxy_ip"))
        hostname = _as_list(self._g(existing_obj, "hostname"))
        # Some payloads expose hosts as ip/ips/hostnames: include them if present
        hostname = sorted(set(hostname or _as_list(self._g(existing_obj, "hostnames")) or _as_list(self._g(existing_obj, "ip")) or _as_list(self._g(existing_obj, "ips"))))

        return {
            "proxy_condition": _to_str(self._g(existing_obj, "proxy_condition")) or None,
            "processpolicy": _to_str(self._g(existing_obj, "processpolicy")),
            "proxy_ip": sorted([_to_str(x) for x in proxy_ip]),
            "hostname": hostname,
            "charset": _to_str(self._g(existing_obj, "charset")),
            "parser": _to_str(self._g(existing_obj, "parser")),
        }

    # ----------------------------- read existing -----------------------------

    def _ensure_device_maps(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        """Populate per-node device name↔id and device id→IPs caches."""
        if (
            node.id in self._dev_name_to_id
            and node.id in self._dev_id_to_name
            and node.id in self._dev_id_to_ips
        ):
            return

        raw = client.list_resource(pool_uuid, node.id, self.DEVICES_RESOURCE) or []

        id_to_name: Dict[str, str] = {}
        name_to_id: Dict[str, str] = {}
        id_to_ips: Dict[str, List[str]] = {}

        def _add(dev: Dict[str, Any]) -> None:
            gid = _to_str(dev.get("id") or dev.get("device_id"))
            gname = _to_str(dev.get("name") or dev.get("device_name"))
            ips_raw = dev.get("ip") or dev.get("ips") or dev.get("hostnames") or []
            ips: List[str]
            if isinstance(ips_raw, list):
                ips = [_to_str(x) for x in ips_raw if _to_str(x)]
            else:
                s = _to_str(ips_raw)
                ips = [s] if s else []
            if gid and gname:
                id_to_name[gid] = gname
                name_to_id[gname] = gid
                id_to_ips[gid] = ips

        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    _add(item)
        elif isinstance(raw, dict):
            items = raw.get("items") or raw.get("data") or raw.get("devices") or raw.get("results") or []
            for item in items or []:
                if isinstance(item, dict):
                    _add(item)

        self._dev_id_to_name[node.id] = id_to_name
        self._dev_name_to_id[node.id] = name_to_id
        self._dev_id_to_ips[node.id] = id_to_ips
        log.debug(
            "Device cache built: %d devices [node=%s]",
            len(id_to_name),
            node.name,
        )

    def _build_proxy_cache_from_items(self, node: NodeRef, items: List[Dict[str, Any]]) -> None:
        """Derive the set of proxy endpoints (IPs/hostnames) for this node."""
        id_to_ips = self._dev_id_to_ips.get(node.id, {})
        proxies: Set[str] = set()

        for it in items:
            pc = _to_str(it.get("proxy_condition") or self._g(it, "proxy_condition")).lower()
            if pc != "use_as_proxy":
                continue
            dev_id = _to_str(it.get("device_id") or self._g(it, "device_id"))
            for ip in id_to_ips.get(dev_id, []):
                if ip:
                    proxies.add(ip)

        self._proxy_ips[node.id] = proxies
        if proxies:
            log.debug("Proxy cache: %d endpoints [node=%s]", len(proxies), node.name)
        else:
            log.debug("Proxy cache: empty [node=%s]", node.name)

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        """Discover existing Syslog Collectors by walking **Devices -> plugins**.

        1) Ensure device maps (id↔name, id→IPs)
        2) For each device: GET Devices/{id}/plugins
        3) Filter items where app == "SyslogCollector"
        """
        self._ensure_device_maps(client, pool_uuid, node)

        out: Dict[str, Dict[str, Any]] = {}
        id_to_name = self._dev_id_to_name.get(node.id, {})

        all_items: List[Dict[str, Any]] = []

        for dev_id, dev_name in id_to_name.items():
            try:
                path = DirectorClient.configapi(pool_uuid, node.id, f"Devices/{dev_id}/plugins")
                data = client.get_json(path) or []
            except Exception:
                log.exception(
                    "Failed to list plugins for device=%s [node=%s]", dev_name, node.name
                )
                continue

            if isinstance(data, list):
                items = [x for x in data if isinstance(x, dict)]
            elif isinstance(data, dict):
                maybe = data.get("plugins") or data.get("items") or data.get("data") or []
                items = [x for x in (maybe or []) if isinstance(x, dict)]
            else:  # pragma: no cover
                items = []

            for it in items:
                app = _to_str(it.get("app")).lower()
                if app != "syslogcollector":
                    continue

                pid = _to_str(it.get("uuid") or it.get("id"))
                obj = dict(it)
                if pid:
                    obj["id"] = pid
                obj["device_id"] = dev_id
                obj["device_name"] = dev_name
                out[dev_name or dev_id] = obj
                all_items.append(obj)

        # Build proxy-IP cache from discovered collectors
        self._build_proxy_cache_from_items(node, all_items)

        log.debug(
            "Discovered %d syslog collectors via Devices->plugins [node=%s]",
            len(out),
            node.name,
        )
        return out

    # --------------------------- payload builders ----------------------------

    def _device_id_for_name(self, node: NodeRef, name: str) -> Optional[str]:
        name_to_id = self._dev_name_to_id.get(node.id, {})
        return name_to_id.get(name) or name_to_id.get(name.strip())

    def _validate_proxy_combo(self, desired: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        pc = desired.get("proxy_condition")
        proc = _to_str(desired.get("processpolicy"))
        pips: List[str] = desired.get("proxy_ip", []) or []

        if pc == "use_as_proxy":
            if proc or pips or desired.get("hostname"):
                return False, "For use_as_proxy, omit processpolicy/hostname/proxy_ip"
            if not desired.get("charset") or not desired.get("parser"):
                return False, "Missing charset or parser"
            return True, None

        if pc == "uses_proxy":
            if not proc or not pips:
                return False, "Missing processpolicy or proxy_ip"
            if not desired.get("charset") or not desired.get("parser"):
                return False, "Missing charset or parser"
            return True, None

        # direct (None)
        if not proc or not desired.get("charset") or not desired.get("parser"):
            return False, "Missing processpolicy, charset, or parser"
        if pips or desired.get("hostname"):
            return False, "For direct collectors, omit hostname/proxy_ip"
        return True, None

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        node = getattr(self, "_current_node", None)
        if not node:
            raise RuntimeError("Internal error: current node not set")

        dev_name = _to_str(desired_row.get("device_name"))
        dev_id = self._device_id_for_name(node, dev_name)
        if not dev_id:
            raise ValidationError(f"Unknown device_name on node '{node.name}': {dev_name}")

        ok, err = self._validate_proxy_combo(desired_row)
        if not ok:
            raise ValidationError(f"{dev_name}: {err}")

        pc = desired_row.get("proxy_condition")
        proc = _to_str(desired_row.get("processpolicy"))
        pips = [x for x in desired_row.get("proxy_ip", []) if _to_str(x)]
        hosts = [x for x in desired_row.get("hostname", []) if _to_str(x)]

        payload: Dict[str, Any] = {
            "device_id": dev_id,
            "charset": _to_str(desired_row.get("charset")),
            "parser": _to_str(desired_row.get("parser")),
            "proxy_condition": pc,
        }

        if pc == "use_as_proxy":
            # API requirement: strictly omit these keys
            pass
        elif pc == "uses_proxy":
            payload["processpolicy"] = proc
            payload["proxy_ip"] = pips
            if hosts:
                payload["hostname"] = hosts
        else:  # direct
            payload["processpolicy"] = proc
            # API requirement: strictly omit hostname/proxy_ip

        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        p = self.build_payload_create(desired_row)
        if existing_obj and existing_obj.get("id"):
            p["id"] = _to_str(existing_obj["id"])
        return p

    # -------------------------------- apply ----------------------------------

    def _ensure_proxy_cache(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        """Make sure _proxy_ips for this node is available."""
        if node.id in self._proxy_ips:
            return
        # Trigger a discovery pass which also fills the proxy cache
        _ = self.fetch_existing(client, pool_uuid, node)

    def _all_proxy_ips_exist(self, node: NodeRef, pips: List[str]) -> tuple[bool, List[str]]:
        known = self._proxy_ips.get(node.id, set())
        missing = [ip for ip in pips if ip not in known]
        return (len(missing) == 0, missing)

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        # Remember node for device name→id resolution during payload build
        self._current_node = node  # type: ignore[attr-defined]

        desired = decision.desired or {}
        dev_name = _to_str(desired.get("device_name")) or "(unnamed)"
        pc = desired.get("proxy_condition")

        # Ensure proxy cache before any apply
        self._ensure_device_maps(client, pool_uuid, node)
        self._ensure_proxy_cache(client, pool_uuid, node)

        try:
            # Guard: skip uses_proxy if proxies not available yet
            if pc == "uses_proxy":
                pips = [x for x in desired.get("proxy_ip", []) if _to_str(x)]
                ok, missing = self._all_proxy_ips_exist(node, pips)
                if not ok:
                    msg = (
                        f"Skipped: proxy_ip not found on node '{node.name}': {', '.join(missing)}. "
                        f"Create the corresponding 'use_as_proxy' collectors first."
                    )
                    log.warning(
                        "SKIP uses_proxy collector for device=%s [node=%s]: %s",
                        dev_name,
                        node.name,
                        msg,
                    )
                    return {"status": "Skipped", "reason": msg}

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
                return client.update_resource(
                    pool_uuid, node.id, self.RESOURCE, existing_id, payload
                )

            # NOOP / SKIP
            log.info("NOOP syslog_collector device=%s [node=%s]", dev_name, node.name)
            return {"status": "Success"}
        except Exception:  # pragma: no cover — defensive
            log.exception("API error for syslog_collector device=%s [node=%s]", dev_name, node.name)
            raise
