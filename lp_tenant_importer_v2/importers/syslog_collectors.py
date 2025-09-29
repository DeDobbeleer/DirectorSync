from __future__ import annotations

"""
Syslog Collectors importer (DirectorSync v2)

Idempotent algorithm using the common v2 pipeline:
  load → validate → fetch → diff → plan → apply → report

Spreadsheet contract (sheet "DeviceFetcher"): rows where app == "SyslogCollector".
Required fields depend on proxy_condition (see validate()).

Stable comparison subset (order-insensitive for lists):
  proxy_condition, processpolicy, proxy_ip[], hostname[], charset, parser

Notes
-----
• We resolve device_id by device_name via the per-node "Devices" list.
• We fetch existing Syslog Collectors by walking Devices → plugins (filter app == "SyslogCollector")
  and remap device_id → device_name so the diff/report use human-friendly keys.
• Monitoring is delegated to DirectorClient (URL/job-id branches).
"""

import logging
from typing import Any, Dict, Iterable, List, Tuple

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
        # pd.isna handles NaN/NaT etc
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
    """Importer for **SyslogCollector** resources.

    Sheet: "DeviceFetcher" (filtered to rows where app == "SyslogCollector").

    Required columns (case/alias tolerant):
      • device_name
      • hostname (multi: "a|b|c" or comma-separated)
      • charset
      • parser
      • app (must be "SyslogCollector")

    Conditionally required:
      • processpolicy (required when proxy_condition ∈ {uses_proxy, None})
      • proxy_ip (required when proxy_condition == uses_proxy; multi like hostname)

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

    # per-node caches: device name↔id
    _dev_name_to_id: Dict[str, Dict[str, str]]  # node_id -> {name -> id}
    _dev_id_to_name: Dict[str, Dict[str, str]]  # node_id -> {id -> name}
    # per-node: known proxy endpoints (IPs/hostnames) from existing "use_as_proxy" collectors
    _known_proxy_endpoints: Dict[str, set[str]]  # node_id -> {ip_or_hostname}

    def __init__(self) -> None:
        self._dev_name_to_id = {}
        self._dev_id_to_name = {}
        self._known_proxy_endpoints = {}

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

        required = {
            "device_name": col("device_name", "name"),
            "hostname": col("hostname", "hostnames"),
            "charset": col("charset"),
            "parser": col("parser"),
            "app": col("app"),
        }
        missing = [k for k, v in required.items() if not v]
        if missing:
            raise ValidationError(
                "DeviceFetcher: missing required column(s): " + ", ".join(missing)
            )

        # Soft validation: ensure at least one row targets SyslogCollector
        app_col = required["app"]
        mask = df[app_col].astype(str).str.strip().str.lower() == "syslogcollector"
        if not mask.any():
            raise ValidationError(
                "DeviceFetcher: no rows with app == 'SyslogCollector'"
            )

    # ------------------------- XLSX → desired rows ---------------------------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets["DeviceFetcher"].copy()
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

        if not all([c_name, c_app, c_hostname, c_parser, c_charset]):
            raise ValidationError(
                "DeviceFetcher: missing one of required columns (device_name, hostname, charset, parser, app)"
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
                "hostname": _split_multi(row[c_hostname]),
                "parser": _to_str(row[c_parser]),
                "charset": _to_str(row[c_charset]),
                "processpolicy": _to_str(row[c_pp]) if c_pp else "",
                "proxy_condition": _norm_proxy_condition(row[c_pc]) if c_pc else None,
                "proxy_ip": _split_multi(row[c_pip]) if c_pip else [],
            }

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

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if not existing_obj:
            return None
        # Extract possibly nested fields; normalize lists and strings
        # Hosts can appear as 'hostname', 'hostnames', 'ip', or 'ips'
        hosts = (
            self._g(existing_obj, "hostname")
            or self._g(existing_obj, "hostnames")
            or self._g(existing_obj, "ip")
            or self._g(existing_obj, "ips")
            or []
        )
        if not isinstance(hosts, list):
            hosts = [hosts] if _to_str(hosts) else []

        # Proxy IPs may be 'proxy_ip', 'proxy_ips'
        proxy_ip = self._g(existing_obj, "proxy_ip") or self._g(existing_obj, "proxy_ips") or []
        if not isinstance(proxy_ip, list):
            proxy_ip = [proxy_ip] if _to_str(proxy_ip) else []

        # Proxy condition may be a string, or booleans like uses_proxy/use_as_proxy
        pc = self._g(existing_obj, "proxy_condition")
        if not pc:
            if existing_obj.get("use_as_proxy") is True:
                pc = "use_as_proxy"
            elif existing_obj.get("uses_proxy") is True or (proxy_ip and not pc):
                pc = "uses_proxy"
            else:
                pc = None

        return {
            "proxy_condition": _to_str(pc) or None,
            "processpolicy": _to_str(
                self._g(existing_obj, "processpolicy")
                or self._g(existing_obj, "process_policy")
                or self._g(existing_obj, "processingpolicy")
            ),
            "proxy_ip": sorted([_to_str(x) for x in proxy_ip]),
            "hostname": sorted([_to_str(x) for x in hosts]),
            "charset": _to_str(self._g(existing_obj, "charset")),
            "parser": _to_str(self._g(existing_obj, "parser")),
        }

    # ----------------------------- read existing -----------------------------

    def _ensure_device_maps(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        """Populate per-node device name↔id caches."""
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
            for item in raw:
                if not isinstance(item, dict):
                    continue
                gid = _to_str(item.get("id")) or _to_str(item.get("device_id"))
                gname = _to_str(item.get("name")) or _to_str(item.get("device_name"))
                _add(gid, gname)
        elif isinstance(raw, dict):
            items = raw.get("items") or raw.get("data") or raw.get("devices") or raw.get("results") or []
            for item in items or []:
                if not isinstance(item, dict):
                    continue
                gid = _to_str(item.get("id")) or _to_str(item.get("device_id"))
                gname = _to_str(item.get("name")) or _to_str(item.get("device_name"))
                _add(gid, gname)

        self._dev_id_to_name[node.id] = id_to_name
        self._dev_name_to_id[node.id] = name_to_id
        log.debug("Device cache built: %d devices [node=%s]", len(id_to_name), node.name)

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        """Discover existing Syslog Collectors by walking **Devices -> plugins**.

        Some Director builds don't expose a list endpoint for `SyslogCollector`.
        The supported and documented way to *read* collectors is:
          1) GET Devices (name↔id map)
          2) For each device: GET Devices/{id}/plugins
          3) Filter items where app == "SyslogCollector"

        Returns a dict keyed by **device_name** with objects containing at least
        an `id` (uuid) when available so the pipeline can perform UPDATEs.
        """
        self._ensure_device_maps(client, pool_uuid, node)

        out: Dict[str, Dict[str, Any]] = {}
        id_to_name = self._dev_id_to_name.get(node.id, {})

        # Build the device list from the map we already have
        for dev_id, dev_name in id_to_name.items():
            try:
                path = DirectorClient.configapi(pool_uuid, node.id, f"Devices/{dev_id}/plugins")
                data = client.get_json(path) or []
            except Exception:
                log.exception("Failed to list plugins for device=%s [node=%s]", dev_name, node.name)
                continue

            # Normalize payload into a list of dicts
            items: List[Dict[str, Any]]
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

                # Try to expose a stable id for UPDATE
                pid = _to_str(it.get("uuid")) or _to_str(it.get("id"))

                # Pass through the plugin fields; canon_existing() will normalize
                obj = dict(it)
                if pid:
                    obj["id"] = pid
                obj["device_id"] = dev_id
                obj["device_name"] = dev_name

                # Some builds expose hosts under different keys; keep raw and let canon map
                out[dev_name] = obj

        # Build known proxy endpoints for this node (used for pre-apply skip)
        proxies: set[str] = set()
        for obj in out.values():
            pc = (
                _to_str(self._g(obj, "proxy_condition")).lower()
                or ("use_as_proxy" if obj.get("use_as_proxy") is True else "")
            )
            if pc == "use_as_proxy":
                hosts = (
                    self._g(obj, "hostname")
                    or self._g(obj, "hostnames")
                    or self._g(obj, "ip")
                    or self._g(obj, "ips")
                    or []
                )
                if not isinstance(hosts, list):
                    hosts = [hosts] if _to_str(hosts) else []
                for h in hosts:
                    s = _to_str(h)
                    if s:
                        proxies.add(s)
        self._known_proxy_endpoints[node.id] = proxies
        log.debug("Discovered %d syslog collectors via Devices->plugins [node=%s]", len(out), node.name)
        log.debug("Known proxy endpoints on node=%s: %s", node.name, sorted(proxies))
        return out

    # --------------------------- payload builders ----------------------------

    def _device_id_for_name(self, node: NodeRef, name: str) -> str | None:
        name_to_id = self._dev_name_to_id.get(node.id, {})
        return name_to_id.get(name) or name_to_id.get(name.strip())

    def _validate_proxy_combo(self, desired: Dict[str, Any]) -> tuple[bool, str | None]:
        pc = desired.get("proxy_condition")
        proc = _to_str(desired.get("processpolicy"))
        pips: List[str] = desired.get("proxy_ip", []) or []
        if pc == "use_as_proxy":
            if proc or pips:
                return False, "Unexpected processpolicy/proxy_ip for use_as_proxy"
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
        if pips:
            return False, "Unexpected proxy_ip for direct collector"
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

        payload: Dict[str, Any] = {
            "device_id": dev_id,
            "hostname": [x for x in desired_row.get("hostname", []) if _to_str(x)],
            "charset": _to_str(desired_row.get("charset")),
            "parser": _to_str(desired_row.get("parser")),
            "proxy_condition": desired_row.get("proxy_condition"),
        }

        pc = desired_row.get("proxy_condition")
        proc = _to_str(desired_row.get("processpolicy"))
        pips = [x for x in desired_row.get("proxy_ip", []) if _to_str(x)]

        if pc == "use_as_proxy":
            payload["processpolicy"] = None
        elif pc == "uses_proxy":
            payload["processpolicy"] = proc
            payload["proxy_ip"] = pips
        else:  # direct
            payload["processpolicy"] = proc

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
        # Remember node for device name→id resolution during payload build
        self._current_node = node  # type: ignore[attr-defined]

        desired = decision.desired or {}
        dev_name = _to_str(desired.get("device_name")) or "(unnamed)"
        pc = (desired.get("proxy_condition") or "").lower()

        # Business rule:
        # 1) use_as_proxy: no dependency → proceed
        # 2) uses_proxy: if any proxy_ip is unknown in cache, SKIP (no API call)
        if decision.op in {"CREATE", "UPDATE"} and pc == "uses_proxy":
            known = self._known_proxy_endpoints.get(node.id, set())
            pips = [x for x in desired.get("proxy_ip", []) if _to_str(x)]
            missing = [ip for ip in pips if _to_str(ip) not in known]
            if missing:
                reason = (
                    f"Skipped: proxy_ip not found on node '{node.name}': {', '.join(missing)}. "
                    f"Create the corresponding 'use_as_proxy' collectors first."
                )
                log.warning("SKIP uses_proxy collector for device=%s [node=%s]: %s", dev_name, node.name, reason)
                return {"status": "Skipped", "message": reason}

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
                return client.update_resource(
                    pool_uuid, node.id, self.RESOURCE, existing_id, payload
                )

            # NOOP / SKIP (diff said equal)
            log.info("NOOP syslog_collector device=%s [node=%s]", dev_name, node.name)
            return {"status": "Success"}
        except Exception:  # pragma: no cover — defensive
            log.exception("API error for syslog_collector device=%s [node=%s]", dev_name, node.name)
            raise
