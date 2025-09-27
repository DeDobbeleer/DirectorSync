"""
Repositories importer (reference implementation).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError
from .base import BaseImporter


class ReposImporter(BaseImporter):
    resource_name = "repos"
    sheet_names = ("Repo",)
    required_columns = ("name", "retention_days", "storage_paths")
    compare_keys = ("name", "retention_days", "storage_paths")

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets["Repo"]
        for _, row in df.iterrows():
            storage_paths = [p.strip() for p in str(row.get("storage_paths", "")).split(",") if p and str(p).strip()]
            yield {
                "name": str(row.get("name")).strip(),
                "retention_days": int(row.get("retention_days")) if pd.notna(row.get("retention_days")) else 0,
                "storage_paths": storage_paths,
            }

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row["name"]

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": desired_row["name"],
            "retention_days": desired_row["retention_days"],
            "storage_paths": list(desired_row["storage_paths"]),
        }

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if not existing_obj:
            return None
        return {
            "name": existing_obj.get("name"),
            "retention_days": existing_obj.get("retention_days"),
            "storage_paths": existing_obj.get("storage_paths", []),
        }

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        data = client.list_repositories(pool_uuid, node.id) or {}
        items = data.get("repos") or data.get("data") or data  # accept multiple shapes
        result: Dict[str, Dict[str, Any]] = {}
        if isinstance(items, list):
            for it in items:
                name = str(it.get("name", "")).strip()
                if name:
                    result[name] = it
        return result

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": desired_row["name"],
            "retention_days": desired_row["retention_days"],
            "storage_paths": desired_row["storage_paths"],
        }

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        payload = self.build_payload_create(desired_row)
        payload["id"] = existing_obj.get("id")
        return payload

    def _verify_paths(self, client: DirectorClient, pool_uuid: str, node: NodeRef, storage_paths: List[str]) -> None:
        avail = client.list_repository_paths(pool_uuid, node.id) or {}
        paths = set(avail.get("paths") or avail.get("data") or [])
        missing = [p for p in storage_paths if p not in paths]
        if missing:
            raise ValidationError(f"Missing storage paths: {', '.join(missing)}")

    def apply(self, client: DirectorClient, pool_uuid: str, node: NodeRef, decision, existing_id: str | None) -> Dict[str, Any]:
        # decision.desired comes from canon_desired; add id for update
        desired = decision.desired or {}
        # verify paths for both create and update
        self._verify_paths(client, pool_uuid, node, desired.get("storage_paths", []))

        if decision.op == "CREATE":
            return client.create_repository(pool_uuid, node.id, self.build_payload_create(desired))
        elif decision.op == "UPDATE" and existing_id:
            payload = self.build_payload_update(desired, {"id": existing_id})
            return client.update_repository(pool_uuid, node.id, existing_id, payload)
        else:
            return {"status": "Success"}
