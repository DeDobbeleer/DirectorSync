# lp_tenant_importer_v2/importers/device_groups.py
"""
DeviceGroups importer (DirectorSync v2)

MVP scope:
- Input from XLSX sheet "DeviceGroups" with columns:
  - name (required, unique per node)
  - description (optional)
- Create / Update based on a subset comparison driven by `description` only.
- No device membership handling in MVP (future extension).

Design:
- Follows the BaseImporter contract: load → validate → fetch → diff → plan → apply → report.
- Uses DirectorClient configapi helpers; monitors async jobs when monitor hints are present.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd

from lp_tenant_importer_v2.importers.base import BaseImporter
from lp_tenant_importer_v2.core.config import NodeRef
from lp_tenant_importer_v2.core.director_client import DirectorClient
from lp_tenant_importer_v2.utils.validators import ValidationError, require_columns

log = logging.getLogger(__name__)


class DeviceGroupsImporter(BaseImporter):
    """Importer for DeviceGroups (MVP: name + description)."""

    resource_name: str = "device_groups"
    sheet_names: Tuple[str, ...] = ("DeviceGroups",)
    required_columns: Tuple[str, ...] = ("name",)  # description is optional
    # Diff only on "description" (key is implicit via BaseImporter)
    compare_keys: Tuple[str, ...] = ("description",)

    # ------------------------------------------------------------------
    # Existing state
    # ------------------------------------------------------------------
    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """Return name -> existing object for this node."""
        path = client.configapi(pool_uuid, node.id, "DeviceGroups")
        data = client.get_json(path) or []
        if isinstance(data, dict) and "data" in data:
            data = data.get("data") or []

        out: Dict[str, Dict[str, Any]] = {}
        if not isinstance(data, list):
            log.warning(
                "DeviceGroups.fetch_existing: unexpected payload type from %s: %s",
                path,
                type(data),
            )
            return out

        for item in data:
            try:
                name = str(item.get("name") or "").strip()
                if name:
                    out[name] = item
            except Exception as exc:
                log.debug(
                    "DeviceGroups.fetch_existing: skipping malformed item: %s (err=%s)",
                    item,
                    exc,
                )
        log.debug("DeviceGroups.fetch_existing: found %d groups on node=%s", len(out), node.name)
        return out

    # ------------------------------------------------------------------
    # Desired state from XLSX
    # ------------------------------------------------------------------
    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        df = sheets["DeviceGroups"].copy()
        # normalize headers and enforce required columns
        df.columns = [str(c).strip() for c in df.columns]
        require_columns(df, self.required_columns, context="DeviceGroups")

        # trim and type-normalize
        def _norm_str(val: Any) -> str:
            if pd.isna(val):
                return ""
            return str(val).strip()

        # detect duplicates by 'name'
        names: List[str] = []
        for _, row in df.iterrows():
            name = _norm_str(row.get("name"))
            if not name:
                # we treat empty names as invalid input
                raise ValidationError("DeviceGroups: 'name' cannot be empty")
            names.append(name)
        dups = {n for n in names if names.count(n) > 1}
        if dups:
            raise ValidationError(f"DeviceGroups: duplicate name(s): {', '.join(sorted(dups))}")

        # yield canonical desired rows
        for _, row in df.iterrows():
            name = _norm_str(row.get("name"))
            description = _norm_str(row.get("description"))
            desired: Dict[str, Any] = {"name": name}
            if description:
                desired["description"] = description
            yield desired

    # ------------------------------------------------------------------
    # Canonicalization for diff
    # ------------------------------------------------------------------
    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return str(desired_row.get("name") or "").strip()

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        # Always include 'description' for consistent subset comparison
        desc = str(desired_row.get("description") or "")
        return {"description": desc}

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any] | None:
        if not existing_obj:
            return None
        desc = str(existing_obj.get("description") or "")
        return {"description": desc}

    # ------------------------------------------------------------------
    # Payload builders
    # ------------------------------------------------------------------
    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        payload = {"name": desired_row["name"]}
        if desired_row.get("description"):
            payload["description"] = desired_row["description"]
        return payload

    def build_payload_update(
        self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        # MVP: allow updating description only (no rename)
        payload: Dict[str, Any] = {}
        if desired_row.get("description") is not None:
            payload["description"] = desired_row.get("description") or ""
            payload["name"] = desired_row.get("name") or ""
        return payload

    # ------------------------------------------------------------------
    # Apply plan
    # ------------------------------------------------------------------
    def _monitor_if_any(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef, response: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Best-effort monitoring:
        - Try job-id based (monitorapi/{pool}/{node}/orders/{job})
        - Fallback to monitor URL if a 'monitorapi/...' path is present
        - If nothing is present, return as-is (sync or no-monitor APIs)
        """
        # Private helpers exist on DirectorClient; use guarded access
        job_id = getattr(client, "_extract_job_id", lambda r: None)(response)
        monitor_path = getattr(client, "_extract_monitor_path", lambda r: None)(response)

        if job_id:
            ok, last = client.monitor_job(pool_uuid, node.id, job_id)
            return {
                "status": "Success" if ok else "Failed",
                "monitor_ok": ok,
                "monitor_branch": f"job:{job_id}",
                "details": last or response,
            }
        if monitor_path:
            ok, last = client.monitor_job_url(monitor_path)
            return {
                "status": "Success" if ok else "Failed",
                "monitor_ok": ok,
                "monitor_branch": monitor_path,
                "details": last or response,
            }

        # No monitor hints → rely on API status (if any)
        return {
            "status": response.get("status") or "—",
            "monitor_ok": None,
            "monitor_branch": None,
            "details": response,
        }

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        resource = "DeviceGroups"

        # --- CREATE ---
        if decision.op == "CREATE":
            path = client.configapi(pool_uuid, node.id, resource)
            payload = self.build_payload_create(decision.desired or {})
            # IMPORTANT: wrap under "data"
            res = client.post_json(path, {"data": payload}) or {}
            out = self._monitor_if_any(client, pool_uuid, node, res)
            return out

        # --- UPDATE ---
        if decision.op == "UPDATE":
            if not existing_id:
                raise RuntimeError("UPDATE requested but no existing_id provided")
            path = client.configapi(pool_uuid, node.id, f"{resource}/{existing_id}")
            payload = self.build_payload_update(decision.desired or {}, decision.existing or {})
            # IMPORTANT: include id + wrap under "data"
            body = {"data": {"id": existing_id, **payload}}
            res = client.put_json(path, body) or {}
            out = self._monitor_if_any(client, pool_uuid, node, res)
            return out



        # BaseImporter won't call apply() for NOOP/SKIP in non-dry runs,
        # but we keep a defensive fallback.
        return {"status": "—", "monitor_ok": None, "monitor_branch": None}
