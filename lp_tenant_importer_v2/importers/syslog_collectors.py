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
• We fetch existing Syslog Collectors and remap device_id → device_name so the
  diff/report use human-friendly keys.
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

    def __init__(self) -> None:
        self._dev_name_to_id = {}
        self._dev_id_to_name = {}

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
        proxy_ip = self._g(existing_obj, "proxy_ip") or []
        if not isinstance(proxy_ip, list):
            proxy_ip = [proxy_ip] if _to_str(proxy_ip) else []
        hostname = self._g(existing_obj, "hostname") or []
        if not isinstance(hostname, list):
            hostname = [hostname] if _to_str(hostname) else []

        return {
            "proxy_condition": _to_str(self._g(existing_obj, "proxy_condition")) or None,
            "processpolicy": _to_str(self._g(existing_obj, "processpolicy")),
            "proxy_ip": sorted([_to_str(x) for x in proxy_ip]),
            "hostname": sorted([_to_str(x) for x in hostname]),
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
        self._ensure_device_maps(client, pool_uuid, node)
        data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []

        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            items_any = (
                data.get("items") or data.get("data") or data.get("collectors") or data.get("results") or []
            )
            items = [x for x in items_any if isinstance(x, dict)]
        else:  # pragma: no cover — defensive
            items = []

        id_to_name = self._dev_id_to_name.get(node.id, {})
        out: Dict[str, Dict[str, Any]] = {}

        for it in items:
            # Name reports the device_name for user-friendliness
            dev_id = _to_str(it.get("device_id")) or _to_str(self._g(it, "device_id"))
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

            # NOOP / SKIP
            log.info("NOOP syslog_collector device=%s [node=%s]", dev_name, node.name)
            return {"status": "Success"}
        except Exception:  # pragma: no cover — defensive
            log.exception("API error for syslog_collector device=%s [node=%s]", dev_name, node.name)
            raise