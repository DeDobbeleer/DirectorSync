"""
Repos importer (profile-driven).

Behavior:
- Parses the "Repo" sheet (aliases supported) with multi-value cells (| or ,).
- All parsed values are normalized to strings.
- Builds payloads using only documented API fields (Director 2.7).
- Canonicalizes GET responses for order-insensitive equality (NOOP vs UPDATE).
- Verifies RepoPaths before applying; if missing, returns 'Skipped' status.

Note:
- No '--force-create': the Director API enforces path integrity.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError
from ..utils.resource_profiles import REPOS_PROFILE
from .base import BaseImporter


class ReposImporter(BaseImporter):
    resource_name = "repos"
    sheet_names = (REPOS_PROFILE.sheet,)
    required_columns = (REPOS_PROFILE.col_storage_paths, REPOS_PROFILE.col_retention_days)
    compare_keys = ("hiddenrepopath", "repoha")

    RESOURCE = REPOS_PROFILE.api_resource
    SUB_REPO_PATHS = REPOS_PROFILE.sub_repo_paths

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets[REPOS_PROFILE.sheet]
        # Ensure 'name' or alias exists in the sheet header set (runtime check)
        cols = set(df.columns.str.lower())
        if (REPOS_PROFILE.col_name not in cols) and not any(a in cols for a in REPOS_PROFILE.col_name_aliases):
            raise ValidationError(f"Missing required column: '{REPOS_PROFILE.col_name}' (or one of aliases {REPOS_PROFILE.col_name_aliases})")

        for _, row in df.iterrows():
            try:
                desired = REPOS_PROFILE.parse_row(row)
            except Exception as exc:
                raise ValidationError(str(exc)) from exc
            yield desired

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row["name"]

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return REPOS_PROFILE.canon_for_compare(desired_row)

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if not existing_obj:
            return None
        return REPOS_PROFILE.canon_for_compare(existing_obj)

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or {}
        items = data.get("repos") or data.get("data") or data
        result: Dict[str, Dict[str, Any]] = {}
        if isinstance(items, list):
            for it in items:
                name = str(it.get("name") or "").strip()
                if name:
                    result[name] = it
        return result

    # ---------------- verification ----------------

    def _verify_paths(self, client: DirectorClient, pool_uuid: str, node: NodeRef, desired_paths: List[str]) -> List[str]:
        raw = client.list_subresource(pool_uuid, node.id, self.RESOURCE, self.SUB_REPO_PATHS) or {}
        valid = REPOS_PROFILE.extract_repo_paths(raw)
        valid_set = set(valid)
        missing = [p for p in desired_paths if p not in valid_set]
        return missing

    # ---------------- payloads & apply ----------------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return REPOS_PROFILE.build_post_payload(desired_row)

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        return REPOS_PROFILE.build_put_payload(existing_obj.get("id", ""), desired_row)

    def apply(self, client: DirectorClient, pool_uuid: str, node: NodeRef, decision, existing_id: str | None) -> Dict[str, Any]:
        desired = decision.desired or {}
        desired_paths = [p["path"] for p in (desired.get("hiddenrepopath") or [])]
        missing = self._verify_paths(client, pool_uuid, node, desired_paths)
        if missing:
            # Skip (do not attempt to create/update invalid repo paths)
            return {"status": "Skipped", "result": {"missing_paths": missing}}

        if decision.op == "CREATE":
            payload = self.build_payload_create(desired)
            return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
        elif decision.op == "UPDATE" and existing_id:
            payload = self.build_payload_update(desired, {"id": existing_id})
            return client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)
        else:
            return {"status": "Success"}
