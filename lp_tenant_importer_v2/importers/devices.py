from __future__ import annotations

"""Devices importer (DirectorSync v2)

Algorithm (idempotent):
- Load → validate → fetch → diff → plan → apply (handled by BaseImporter pipeline).
- We compare a stable subset: ip[], timezone, availability, confidentiality, integrity, dg_names[]
  (device group *names* are used only for diff readability; payloads use *IDs*).
- Create/Edit payloads follow Director API 2.7.0 for `Devices`:
  required: name, ip[], availability, confidentiality, integrity
  optional: timezone, devicegroup[] (IDs), distributed_collector[] (IDs), logpolicy[] (IDs)
- Unknown Device Group names in the spreadsheet are ignored with a WARNING; we do not block the run.

This importer intentionally *does not* touch distributed collectors or log policies unless
explicitly provided as columns in the spreadsheet (defensive default).
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


_ALLOWED_RISKS = {"Minimal", "Minor", "Major", "Critical"}


def _norm_risk(v: Any) -> str:
    s = _to_str(v)
    if not s:
        return s
    low = s.lower()
    mapping = {"minimal": "Minimal", "minor": "Minor", "major": "Major", "critical": "Critical"}
    return mapping.get(low, s)


# ----------------------------- importer --------------------------------------


class DevicesImporter(BaseImporter):
    """Importer for **Devices** (Director API 2.7.0).

    Sheet: "Device"
    Required columns (case/alias tolerant): name, ip, availability, confidentiality, integrity
    Optional columns: timezone, device_groups, distributed_collectors, log_policies
    """

    resource_name: str = "devices"
    sheet_names = ("Device",)
    # BaseImporter.validate is overridden to allow alias/case tolerance.
    required_columns = tuple()  # unused; we implement custom validation

    # Stable subset for diffing (order-insensitive fields must be normalized in canon_*):
    compare_keys = (
        "ip",
        "timezone",
        "availability",
        "confidentiality",
        "integrity",
        "dg_names",
        # We *could* add dc_names/logpol_names later if we decide to manage them now.
    )

    RESOURCE = "Devices"
    DG_RESOURCE = "DeviceGroups"

    # per-node caches
    _dg_name_to_id: Dict[str, Dict[str, str]]  # node_id -> {name -> id}
    _dg_id_to_name: Dict[str, Dict[str, str]]  # node_id -> {id -> name}

    def __init__(self) -> None:
        self._dg_name_to_id = {}
        self._dg_id_to_name = {}

    # ---------------------------- validation ---------------------------------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        """Custom validation with *alias* and *case* tolerance for columns."""
        if "Device" not in sheets:
            raise ValidationError("Missing required sheet: Device")
        df = sheets["Device"]
        # Normalize header names to lowercase for detection, but we keep original for access
        lower_to_orig = {str(c).strip().lower(): str(c) for c in df.columns}

        def need_one_of(*names: str) -> str:
            for n in names:
                if n.lower() in lower_to_orig:
                    return lower_to_orig[n.lower()]
            raise ValidationError(
                f"Device: missing required column ({' / '.join(names)})"
            )

        # required
        need_one_of("name")
        need_one_of("ip", "ips", "device address(es)")
        need_one_of("availability")
        need_one_of("confidentiality")
        need_one_of("integrity")
        # optional are not enforced

    # ------------------------- XLSX → desired rows ---------------------------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets["Device"].copy()
        # Map columns case-insensitively and accept common aliases
        cols = {str(c).strip().lower(): str(c) for c in df.columns}

        def col(*names: str) -> str | None:
            for n in names:
                k = n.strip().lower()
                if k in cols:
                    return cols[k]
            return None

        c_name = col("name")
        c_ip = col("ip", "ips", "device address(es)")
        c_av = col("availability")
        c_co = col("confidentiality")
        c_in = col("integrity")
        if not all([c_name, c_ip, c_av, c_co, c_in]):
            raise ValidationError(
                "Device: missing one of required columns (name, ip, availability, confidentiality, integrity)"
            )

        c_tz = col("timezone", "time_zone")
        c_dg = col("device_groups", "devicegroup", "device group", "groups")
        c_dc = col("distributed_collectors", "distributed collector(s)", "distributed_collector")
        c_lp = col("log_policies", "logpolicy", "log policies")

        for _, row in df.iterrows():
            name = _to_str(row[c_name])
            if not name:
                continue
            desired: Dict[str, Any] = {
                "name": name,
                "ip": [_to_str(x) for x in _split_multi(row[c_ip])],
                "availability": _norm_risk(row[c_av]),
                "confidentiality": _norm_risk(row[c_co]),
                "integrity": _norm_risk(row[c_in]),
            }
            if c_tz and _to_str(row[c_tz]):
                desired["timezone"] = _to_str(row[c_tz])
            if c_dg and _to_str(row[c_dg]):
                desired["dg_names"] = _split_multi(row[c_dg])
            else:
                desired["dg_names"] = []
            # Optional extras — only included if present in columns
            if c_dc and _to_str(row[c_dc]):
                desired["dc_names"] = _split_multi(row[c_dc])
            if c_lp and _to_str(row[c_lp]):
                desired["logpol_names"] = _split_multi(row[c_lp])
            yield desired

    # ------------------------ canonicalization (diff) ------------------------

    @staticmethod
    def key_fn(desired_row: Dict[str, Any]) -> str:
        return _to_str(desired_row.get("name"))

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ip": sorted([_to_str(x) for x in desired_row.get("ip", [])]),
            "timezone": _to_str(desired_row.get("timezone")),
            "availability": _norm_risk(desired_row.get("availability")),
            "confidentiality": _norm_risk(desired_row.get("confidentiality")),
            "integrity": _norm_risk(desired_row.get("integrity")),
            "dg_names": sorted([_to_str(x) for x in desired_row.get("dg_names", [])]),
        }

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if not existing_obj:
            return None
        # risks may be at top-level or nested under risk_values
        rv = existing_obj.get("risk_values") or {}
        availability = _to_str(rv.get("availability") or existing_obj.get("availability"))
        confidentiality = _to_str(rv.get("confidentiality") or existing_obj.get("confidentiality"))
        integrity = _to_str(rv.get("integrity") or existing_obj.get("integrity"))
        ips_raw = existing_obj.get("ip")
        if isinstance(ips_raw, list):
            ip_list = [_to_str(x) for x in ips_raw]
        else:
            ip_list = [_to_str(ips_raw)] if _to_str(ips_raw) else []
        return {
            "ip": sorted(ip_list),
            "timezone": _to_str(existing_obj.get("timezone")),
            "availability": availability,
            "confidentiality": confidentiality,
            "integrity": integrity,
            # added by fetch_existing (IDs → names)
            "dg_names": sorted([_to_str(x) for x in (existing_obj.get("dg_names") or [])]),
        }

    # ----------------------------- read existing -----------------------------

    def _ensure_dg_maps(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        """Populate per-node DeviceGroup name↔id caches."""
        if node.id in self._dg_name_to_id and node.id in self._dg_id_to_name:
            return
        raw = client.list_resource(pool_uuid, node.id, self.DG_RESOURCE) or []
        id_to_name: Dict[str, str] = {}
        name_to_id: Dict[str, str] = {}
        if isinstance(raw, list):
            for item in raw:
                if not isinstance(item, dict):
                    continue
                gid = _to_str(item.get("id"))
                gname = _to_str(item.get("name"))
                if gid and gname:
                    id_to_name[gid] = gname
                    name_to_id[gname] = gid
        elif isinstance(raw, dict):
            # Accept common shapes like {"data": [...]} or {"items": [...]}.
            items = raw.get("data") or raw.get("items") or raw.get("device_groups") or []
            for item in items or []:
                if not isinstance(item, dict):
                    continue
                gid = _to_str(item.get("id"))
                gname = _to_str(item.get("name"))
                if gid and gname:
                    id_to_name[gid] = gname
                    name_to_id[gname] = gid
        self._dg_id_to_name[node.id] = id_to_name
        self._dg_name_to_id[node.id] = name_to_id
        log.debug("DG cache built: %d groups [node=%s]", len(id_to_name), node.name)

    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        self._ensure_dg_maps(client, pool_uuid, node)
        # List devices; payload may be list or a dict with `data`/`items`/`devices`.
        data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []
        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            items_any = (
                data.get("items")
                or data.get("data")
                or data.get("devices")
                or data.get("results")
                or []
            )
            items = [x for x in items_any if isinstance(x, dict)]
        else:  # pragma: no cover — defensive
            items = []

        id_to_name = self._dg_id_to_name.get(node.id, {})
        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            name = _to_str(it.get("name"))
            if not name:
                continue
            # Convert device_groups (IDs) → dg_names (names) for diff readability
            dg_ids = it.get("device_groups") or it.get("devicegroup") or []
            dg_names = []
            for gid in dg_ids or []:
                n = id_to_name.get(_to_str(gid))
                if n:
                    dg_names.append(n)
            obj = dict(it)
            obj["dg_names"] = dg_names
            out[name] = obj
        return out

    # --------------------------- payload builders ----------------------------

    def _dg_ids_for_names(self, node: NodeRef, names: List[str]) -> Tuple[List[str], List[str]]:
        name_to_id = self._dg_name_to_id.get(node.id, {})
        ids: List[str] = []
        missing: List[str] = []
        for n in names or []:
            key = _to_str(n)
            gid = name_to_id.get(key) or name_to_id.get(key.strip())
            if gid:
                ids.append(gid)
            else:
                missing.append(key)
        return ids, missing

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "name": _to_str(desired_row.get("name")),
            "ip": [_to_str(x) for x in desired_row.get("ip", []) if _to_str(x)],
            "availability": _norm_risk(desired_row.get("availability")),
            "confidentiality": _norm_risk(desired_row.get("confidentiality")),
            "integrity": _norm_risk(desired_row.get("integrity")),
        }
        tz = _to_str(desired_row.get("timezone"))
        if tz:
            payload["timezone"] = tz
        # Device Groups (IDs)
        dg_names = [
            _to_str(x) for x in desired_row.get("dg_names", []) if _to_str(x)
        ]
        if getattr(self, "_current_node", None) is not None and dg_names:
            ids, missing = self._dg_ids_for_names(self._current_node, dg_names)  # type: ignore[arg-type]
            if ids:
                payload["devicegroup"] = ids
            if missing:
                log.warning(
                    "Device '%s': unknown Device Groups ignored: %s [node=%s]",
                    payload.get("name"),
                    ", ".join(missing),
                    getattr(self._current_node, "name", "?"),
                )
        # We *do not* inject empty lists for distributed_collector/logpolicy by default.
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        p = self.build_payload_create(desired_row)
        if existing_obj and existing_obj.get("id"):
            p["id"] = _to_str(existing_obj["id"])
        return p

    # ---------------------------------DeviceGrouos ---------------------------
    
    def reconcile_devicegroup_membership(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> dict:
        """
        Rebuild DeviceGroup membership from *current* devices on the target node.

        Logic:
        1) List devices → read `device_groups` (IDs) → build target mapping:
            group_id -> set(device_id).
        2) List device groups → resolve {id -> (name, description, current_members)}.
        3) For each known group_id in the target mapping:
            - If desired == current  -> NOOP
            - Else PUT DeviceGroups/{id} with {name, description, devices=[...]}.
        4) Best-effort & idempotent; logs a compact summary.

        Returns:
            dict stats: {"updated": int, "noop": int, "missing": int, "errors": int}
        """
        from collections import defaultdict
        from typing import DefaultDict, Set, Dict, Any, List

        log.info("device_groups: reconciling memberships [node=%s]", node.name)

        stats = {"updated": 0, "noop": 0, "missing": 0, "errors": 0}

        # Build maps for DeviceGroups (id <-> name) if not already done.
        self._ensure_dg_maps(client, pool_uuid, node)
        dg_id_to_name = self._dg_id_to_name.get(node.id, {})  # id -> name

        # -------------------------
        # 1) Collect desired state
        # -------------------------
        dev_payload = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []
        if isinstance(dev_payload, list):
            dev_items = [x for x in dev_payload if isinstance(x, dict)]
        elif isinstance(dev_payload, dict):
            dev_items_any = (
                dev_payload.get("items")
                or dev_payload.get("data")
                or dev_payload.get("devices")
                or dev_payload.get("results")
                or []
            )
            dev_items = [x for x in dev_items_any if isinstance(x, dict)]
        else:
            dev_items = []

        target: DefaultDict[str, Set[str]] = defaultdict(set)  # group_id -> {device_id}
        for it in dev_items:
            dev_id = _to_str(it.get("id"))
            if not dev_id:
                continue
            grp_ids = it.get("device_groups") or it.get("devicegroup") or []
            if isinstance(grp_ids, dict):
                grp_ids = grp_ids.get("ids") or []  # tolerate odd shapes defensively
            for gid in grp_ids or []:
                g = _to_str(gid)
                if g:
                    target[g].add(dev_id)

        # Quick exit if nothing to do
        if not target:
            log.info("device_groups: no memberships detected from devices [node=%s]", node.name)
            return stats

        # -------------------------
        # 2) Read current DG state
        # -------------------------
        dg_payload = client.list_resource(pool_uuid, node.id, self.DG_RESOURCE) or []
        if isinstance(dg_payload, list):
            dg_items = [x for x in dg_payload if isinstance(x, dict)]
        elif isinstance(dg_payload, dict):
            dg_items_any = (
                dg_payload.get("data")
                or dg_payload.get("items")
                or dg_payload.get("device_groups")
                or []
            )
            dg_items = [x for x in dg_items_any if isinstance(x, dict)]
        else:
            dg_items = []

        # id -> {"name": str, "description": str, "devices": set(str)}
        current_by_id: Dict[str, Dict[str, Any]] = {}
        for g in dg_items:
            gid = _to_str(g.get("id"))
            if not gid:
                continue
            name = _to_str(g.get("name"))
            desc = _to_str(g.get("description"))
            cur = g.get("devices") or []
            if isinstance(cur, dict):
                cur = cur.get("ids") or []
            cur_ids = { _to_str(x) for x in (cur or []) if _to_str(x) }
            current_by_id[gid] = {"name": name, "description": desc, "devices": cur_ids}

        # ----------------------------------------
        # 3) Diff & apply (PUT) on DeviceGroups/*
        # ----------------------------------------
        for gid, desired_set in target.items():
            meta = current_by_id.get(gid)
            if not meta:
                stats["missing"] += 1
                log.warning(
                    "device_groups: target references unknown group id=%s name=%s [node=%s]",
                    gid, dg_id_to_name.get(gid, "?"), node.name
                )
                continue

            current_set = meta.get("devices") or set()
            if current_set == desired_set:
                stats["noop"] += 1
                log.debug(
                    "device_groups: NOOP id=%s name=%s members=%d [node=%s]",
                    gid, meta.get("name"), len(desired_set), node.name
                )
                continue

            payload = {
                # API requires name + (optionally) description to be sent back
                "name": meta.get("name") or dg_id_to_name.get(gid) or "",
                "description": meta.get("description") or "",
                "devices": sorted({x for x in desired_set if x}),
            }

            try:
                res = client.update_resource(
                    pool_uuid, node.id, self.DG_RESOURCE, gid, payload
                )
                ok = res.get("monitor_ok")
                status = res.get("status")
                if ok is False or status == "Failed":
                    stats["errors"] += 1
                    log.error(
                        "device_groups: UPDATE failed id=%s name=%s status=%s branch=%s [node=%s]",
                        gid, payload["name"], status, res.get("monitor_branch"), node.name
                    )
                else:
                    stats["updated"] += 1
                    log.info(
                        "device_groups: UPDATE id=%s name=%s members=%d [node=%s]",
                        gid, payload["name"], len(payload["devices"]), node.name
                    )
            except Exception:
                stats["errors"] += 1
                log.exception(
                    "device_groups: UPDATE threw exception id=%s name=%s [node=%s]",
                    gid, payload.get("name"), node.name
                )

        log.info(
            "device_groups: reconcile summary updated=%d noop=%d missing=%d errors=%d [node=%s]",
            stats["updated"], stats["noop"], stats["missing"], stats["errors"], node.name
        )
        return stats

    # ---------------------------------Post Actions ---------------------------
    
    def post_actions(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> dict:
        """Performs post actions: rebuild Device Groups membership"""
        # Respect dry-run if BaseImporter set it
        if getattr(self, "_dry_run", False):
            log.info("device_groups: reconcile skipped (dry-run) [node=%s]", node.name)
            return {"skipped": "dry_run"}

        try:
            stats = self.reconcile_devicegroup_membership(client, pool_uuid, node)
            return stats or {}
        except Exception:
            log.warning("device_groups: reconcile failed [node=%s]", node.name, exc_info=True)
            return {"error": "reconcile_failed"}
        
    # -------------------------------- apply ----------------------------------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        # Remember node for DG name→id resolution during payload build
        self._current_node = node  # type: ignore[attr-defined]
        desired = decision.desired or {}
        dev_name = _to_str(desired.get("name")) or "(unnamed)"
        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                log.info("CREATE device=%s [node=%s]", dev_name, node.name)
                log.debug("CREATE payload=%s", payload)
                return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id})
                log.info("UPDATE device=%s id=%s [node=%s]", dev_name, existing_id, node.name)
                log.debug("UPDATE payload=%s", payload)
                return client.update_resource(
                    pool_uuid, node.id, self.RESOURCE, existing_id, payload
                )
            # NOOP / SKIP
            log.info("NOOP device=%s [node=%s]", dev_name, node.name)
            return {"status": "Success"}
        except Exception:  # pragma: no cover — defensive
            log.exception("API error for device=%s [node=%s]", dev_name, node.name)
            raise
