# File: lp_tenant_importer_v2/importers/user_defined_lists.py
"""
UserDefinedLists importer (DirectorSync v2)

Scope
-----
Sync **User Defined Lists** (static & dynamic) on Logpoint Search Heads, aligned with the
existing v2 pipeline (BaseImporter, DirectorClient, DiffEngine, validators).

API contracts (Logpoint Director Config API)
-------------------------------------------
- List all lists:      GET   configapi/{pool}/{node}/Lists
- Create static:       POST  configapi/{pool}/{node}/Lists/static
- Edit   static:       PUT   configapi/{pool}/{node}/Lists/static/{id}
- Create dynamic:      POST  configapi/{pool}/{node}/Lists/dynamic
- Edit   dynamic:      PUT   configapi/{pool}/{node}/Lists/dynamic/{id}
- Refresh cache:       POST  configapi/{pool}/{node}/Lists/refreshlist
- Delete (optional):   DELETE configapi/{pool}/{node}/Lists/{id}

Sheet
-----
Expected sheet name:  "UserDefinedList"

Columns (MVP)
-------------
Required
- name:   str, list name (will be uppercased by API; treated case-insensitively)
- type:   str, one of {"static", "dynamic"}

Static-only
- values_csv / values_json / values: the list values (CSV/pipe/semicolon/newlines, JSON array,
  or Python-like list). Order is ignored for comparisons.

Dynamic-only (age limit)
- agelimit_day:    int (>=0), default 0
- agelimit_hour:   int (>=0), default 0
- agelimit_minute: int (>=0), default 0

Optional
- state: "present" (default) or "absent" (delete requested) — delete path is implemented but
  only executed when explicitly enabled in your tenants' process policies.

Compare keys (idempotence)
--------------------------
- type
- values_set (static lists only; order-insensitive)
- age_limit (dynamic lists only; integer minutes, derived from D/H/M)

Notes
-----
- Target nodes are the tenant Search Heads (configure `defaults.target.user_defined_lists`
  to include `search_heads` in tenants.yml).
- After create/update operations per node, a `Lists/refreshlist` action is invoked to
  synchronize internal list caches (best-effort; failures are logged and do not fail the run).

"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple
import ast
import json
import logging

import pandas as pd

from .base import BaseImporter, NodeRef, ValidationError, TenantConfig  # re-exported via base
from ..core.director_client import DirectorClient

log = logging.getLogger(__name__)

# API resource constants
RESOURCE_BASE = "Lists"
RESOURCE_STATIC = "Lists/static"
RESOURCE_DYNAMIC = "Lists/dynamic"


# ------------------------ helpers ------------------------

def _s(v: Any) -> str:
    """Return trimmed string (or empty string)."""
    return str(v).strip() if v is not None else ""


def _to_int(v: Any) -> int:
    """Coerce common spreadsheet values to int (>=0)."""

    if v is None or v == "":
        return 0
    try:
        return int(float(str(v).strip()))
    except Exception as exc:  # noqa: BLE001
        return 0



def _parse_list_field(raw: Any) -> List[str]:
    """
    Parse a cell value into a clean list[str].

    Accepts:
    - JSON arrays: ["a","b"]
    - Python-like arrays: ['a', 'b']
    - CSV-ish: "a,b" or "a; b | c" (comma/semicolon/pipe/newlines)

    Trims stray quotes/brackets, dedupes while preserving order.
    """

    def _soft_clean(s: str) -> str:
        s = (s or "").strip()
        s = s.strip().lstrip("[").rstrip("]").strip()
        if s.startswith(("'", '"')):
            s = s[1:].lstrip()
        if s.endswith(("'", '"')):
            s = s[:-1].rstrip()
        return s.strip()

    # Already a Python list
    if isinstance(raw, list):
        vals = [_soft_clean(str(x)) for x in raw]
    elif isinstance(raw, str):
        s = raw.strip()
        parsed = None
        if s:
            # JSON
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
            tmp = (
                s.replace("\n", ",")
                .replace(";", ",")
                .replace("|", ",")
            )
            parts = [p for p in tmp.split(",")]
            vals = [_soft_clean(p) for p in parts]
    else:
        vals = []

    # Dedup while preserving order and remove empties
    seen, out = set(), []
    for v in vals:
        if not v:
            continue
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out

def split_seconds(total_seconds: int) -> Tuple[int, int, int, int]:
    """
    Split an integer number of seconds into days, hours, minutes, seconds.
    Uses step-by-step 'defalqué' (deduct remainder) logic.
    """
    if total_seconds < 0:
        raise ValueError("total_seconds must be >= 0")

    # 1) Take out full days
    days, rem_after_days = divmod(total_seconds, 86_400)  # 24 * 3600

    # 2) From the remainder, take out full hours
    hours, rem_after_hours = divmod(rem_after_days, 3_600)

    # 3) From the remainder, take out full minutes
    minutes, seconds = divmod(rem_after_hours, 60)

    return days, hours, minutes, seconds


def split_seconds_dhm(total_seconds: int) -> Tuple[int, int, int]:
    """
    Same as above but returns only (days, hours, minutes),
    ignoring leftover seconds.
    """
    d, h, m, _s = split_seconds(total_seconds)
    return d, h, m
# ------------------------ importer ------------------------


class UserDefinedListsImporter(BaseImporter):
    """Importer for User Defined Lists (static & dynamic).

    Expected sheet: 'UserDefinedList'
    """

    resource_name: str = "user_defined_lists"
    sheet_names: Tuple[str, ...] = ("UserDefinedList",)
    # Only absolute minimum here; conditional validation is done in `iter_desired`.
    required_columns: Tuple[str, ...] = ("name", "list_type", "lists")

    # Compare keys (subset) used by DiffEngine
    compare_keys: Tuple[str, ...] = (
        "name",
        "lists",
        "age_limit",
        "list_type"
    )

    # ------------------------ Base hooks ------------------------

    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """Return name -> existing list object mapping for a node.

        Uses: GET configapi/{pool}/{node}/Lists
        """
        try:
            rows = client.list_resource(pool_uuid, node.id, RESOURCE_BASE) or []
        except Exception as exc:  # noqa: BLE001
            log.error("fetch_existing failed [node=%s]: %s", node.name, exc)
            raise
        idx: Dict[str, Dict[str, Any]] = {}
        for it in rows or []:
            nm = _s(it.get("name"))  # API returns 'name' in UPPER
            if not nm:
                continue
            idx[nm.upper()] = it
        log.info("fetch_existing: %d lists [node=%s]", len(idx), node.name)
        return idx

    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        """Yield canonical desired rows parsed from Excel.

        Column set:
          name, type (static|dynamic)
          For static: values_csv | values_json | values
          For dynamic: agelimit_day, agelimit_hour, agelimit_minute (defaults 0)
          Optional: state (present|absent) — not acted upon unless delete flow is enabled
        """
        df = sheets.get(self.sheet_names[0])
        if df is None:
            return []

        cols = {c.lower(): c for c in df.columns}
        def has(col: str) -> bool:  # case-insensitive check
            return col.lower() in cols
        def col(col: str) -> str:
            return cols[col.lower()]

        required = ["name", "list_type", "lists"]
        missing = [c for c in required if not has(c)]
        if missing:
            raise ValidationError(
                f"Missing required columns in sheet '{self.sheet_names[0]}': {', '.join(missing)}"
            )

        for _, row in df.iterrows():
            name = _s(row[col("name")])
            list_type = _s(row[col("list_type")])
            if not name:
                raise ValidationError("List 'name' cannot be empty")
            if list_type not in {"static_list", "dynamic_list"}:
                raise ValidationError(f"Invalid list 'type': {list_type!r}")

            desired: Dict[str, Any] = {
                "name": name,
                "list_type": list_type,
                "values": [],
                "values_set": [],
                "age_limit": 0,  
                "last_updated": "",
                "state": _s(row[col("state")]) if has("state") else "present",
            }

            if list_type == "static":
                # Prefer *_json, then *_csv, then a generic 'values'
                values_raw = None
                for k in ("lists"):
                    if has(k):
                        values_raw = row[col(k)]
                        if values_raw is not None and _s(values_raw) != "":
                            break
                values = _parse_list_field(values_raw)
                if not values:
                    raise ValidationError(
                        f"Static list '{name}': no values provided in values_* column"
                    )
                desired["values"] = values
                # For diff: set semantics (order-insensitive)
                desired["values_set"] = sorted(set(values))

            else:  # dynamic
                d = _to_int(row[col("age_limit")])
                l = _to_int(row[col("last_updated")])

                desired.update(
                    {
                        "age_limit": d,
                        "last_updated": str(l),
                    }
                )

            yield desired

    def key_fn(self, desired_row: Dict[str, Any]) -> str:  # noqa: D401
        """Return unique key — the list name (uppercased)."""
        return _s(desired_row.get("name")).upper()

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:  # noqa: D401
        """Comparable subset for a desired row."""
        return {
            "list_type": desired_row.get("list_type"),
            "values_set": tuple(desired_row.get("values_set") or []),
            "age_limit": int(desired_row.get("age_limit") or 0),
            "last_updated": int(desired_row.get("last_updated") or ""),
        }

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any]:  # noqa: D401
        """Comparable subset for an existing object returned by GET Lists."""
        if not isinstance(existing_obj, dict):
            return {}
        list_type = _s(existing_obj.get("list_type")).lower()  # e.g., 'static_list' | 'dynamic_list'
        if list_type.startswith("static_list"):
            values = existing_obj.get("lists") or []
            # List values may already be deduped; normalize to set semantics for diff
            values_set = sorted({str(v).strip() for v in values if _s(v)})
            return {"type": "static_list", "values_set": tuple(values_set), "age_limit": 0, "last_updated": ""}
        # dynamic
        age_limit = int(existing_obj.get("age_limit") or 0)
        last_update = str(existing_obj.get("last_update") or "")
        return {"type": "dynamic_list", "values_set": tuple(), "age_limit": age_limit, "last_update": last_update}

    # ------------------------ API payloads ------------------------

    @staticmethod
    def _resource_for_type(typ: str) -> str:
        return RESOURCE_STATIC if typ == "static_list" else RESOURCE_DYNAMIC

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        typ = _s(desired_row.get("type_list"))
        name = _s(desired_row.get("name"))
        if typ == "static_list":
            d = {"s_name": name, "lists": list(desired_row.get("values") or [])}
            log.debug(f"Static list payload for: {d.get("s_name")} ")
            return d
        # dynamic
        d, h, m = split_seconds_dhm(int(desired_row.get("age_limit") or 0))
        d = {
            "d_name": name,
            "agelimit_day" : d,
            "agelimit_hour" : h,
            "agelimit_minute": m,
        }
        log.debug(f"Static list payload for: {d.get("d_name")} ")
        return d

    def build_payload_update(
        self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        return self.build_payload_create(desired_row)
    
    # ------------------------ apply ------------------------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,  # DiffEngine.Decision
        existing_id: str | None,
    ) -> Dict[str, Any]:
        """
        Execute CREATE/UPDATE/NOOP based on decision.
        Delete is intentionally **opt-in** and should be wired by policy before use.
        """
        desired = decision.desired or {}
        typ = _s(desired.get("list_type"))
        resource = self._resource_for_type(typ)

        # Optional delete flow (only if explicitly requested and existing present)
        if _s(desired.get("state")).lower() == "absent" and existing_id:
            log.info(
                "DELETE list name=%s id=%s [node=%s]",
                desired.get("name"),
                existing_id,
                node.name,
            )
            return client.delete_resource(pool_uuid, node.id, RESOURCE_BASE, existing_id)

        if decision.op == "CREATE":
            payload = self.build_payload_create(desired)
            
            log.info("CREATE list type=%s name=%s [node=%s]", typ, desired.get("name"), node.name)
            return client.create_resource(pool_uuid, node.id, resource, payload)
            
        if decision.op == "UPDATE":
            if not existing_id:
                raise RuntimeError("UPDATE selected but no existing id present")
            payload = self.build_payload_update(desired, decision.existing or {})
            log.info(
                "UPDATE list type=%s name=%s id=%s [node=%s]",
                typ,
                desired.get("name"),
                existing_id,
                node.name,
            )
            return client.update_resource(pool_uuid, node.id, resource, existing_id, payload)

        # NOOP/SKIP handled by BaseImporter — return a minimal OK dict if ever hit
        return {"status": "OK", "monitor_ok": None, "monitor_branch": "noop"}

    # ------------------------ post actions ------------------------

    def post_actions(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> dict:
        """Best-effort refresh to sync Lists after changes on a node."""
        try:
            res = client.invoke_action(pool_uuid, node.id, RESOURCE_BASE, "refreshlist")
            ok = res.get("monitor_ok")
            if ok is False:
                log.warning("Lists/refreshlist failed [node=%s]: %s", node.name, res)
            else:
                log.debug("Lists/refreshlist ok [node=%s]: %s", node.name, res)
            return res
        except Exception as exc:  # noqa: BLE001
            log.warning("Lists/refreshlist error [node=%s]: %s", node.name, exc)
            return {"status": "Failed", "error": str(exc)}
