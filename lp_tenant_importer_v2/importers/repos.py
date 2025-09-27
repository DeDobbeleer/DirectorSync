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

from typing import Any, Dict, Iterable, List, Set, Union

import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError
from ..utils.resource_profiles import REPOS_PROFILE
from .base import BaseImporter

JSON = Union[Dict[str, Any], List[Any]]

def _normalize_path_str(path: str) -> str:
    """
    Normalize a repository path string for consistent comparison.
    Adjust here if a trailing slash policy is required.
    """
    return path.strip()

def _collect_paths_any(shape: Any, out: Set[str]) -> None:
        """
        Recursively collect path strings from any JSON shape:
        - str directly
        - dict with 'paths' (list) or 'path' (str)
        - list/tuple containing str/dict/list/tuple (nested-friendly)
        - arbitrary dict: traverse values
        """
        if shape is None:
            return

        if isinstance(shape, str):
            out.add(_normalize_path_str(shape))
            return

        if isinstance(shape, dict):
            if "paths" in shape:
                _collect_paths_any(shape.get("paths"), out)
                return
            if "path" in shape:
                v = shape.get("path")
                if isinstance(v, str):
                    out.add(_normalize_path_str(v))
                    return
            for v in shape.values():
                _collect_paths_any(v, out)
            return

        if isinstance(shape, (list, tuple)):
            for v in shape:
                _collect_paths_any(v, out)
            return

def _extract_paths(avail: JSON) -> Set[str]:
    paths: Set[str] = set()
    _collect_paths_any(avail, paths)
    return paths

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

    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """
        Fetch existing repos from Director, tolerating list/dict payloads and
        common key shapes. Returns a mapping: repo_name -> repo_object.
        """
        payload: JSON = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []

        # Normalize to a list of dicts named `items`
        items: List[Dict[str, Any]] = []

        if isinstance(payload, list):
            items = [x for x in payload if isinstance(x, dict)]
        elif isinstance(payload, dict):
            def get_ci(d: Dict[str, Any], key: str) -> Any:
                for k, v in d.items():
                    if str(k).lower() == key.lower():
                        return v
                return None

            candidates = (
                get_ci(payload, "repos")
                or get_ci(payload, "items")
                or get_ci(payload, "data")
                or get_ci(payload, "results")
                or payload  # fallback: treat whole dict as a single object
            )

            if isinstance(candidates, list):
                items = [x for x in candidates if isinstance(x, dict)]
            elif isinstance(candidates, dict):
                nested = (
                    get_ci(candidates, "items")
                    or get_ci(candidates, "repos")
                    or get_ci(candidates, "results")
                    or get_ci(candidates, "data")
                )
                if isinstance(nested, list):
                    items = [x for x in nested if isinstance(x, dict)]
                else:
                    items = [candidates]
            else:
                items = []
        else:
            raise TypeError(f"Unexpected payload type: {type(payload).__name__}")

        # Build name -> object map (support name/label/RepoName)
        result: Dict[str, Dict[str, Any]] = {}
        for it in items:
            if not isinstance(it, dict):
                continue
            name = it.get("name") or it.get("label") or it.get("RepoName")
            if isinstance(name, str):
                key = name.strip()
                if key:
                    if key in result and hasattr(self, "logger"):
                        self.logger.warning(
                            "Duplicate repo name encountered: %s (overwriting)", key
                        )
                    result[key] = it

        return result

    # ---------------- verification ----------------
  
    def _verify_paths(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        storage_paths: List[str]
    ) -> None:
        """
        Validate that all desired storage paths exist on the node.
        Tolerates all RepoPaths JSON shapes (dict/list/tuple; nested).
        """
        avail = client.list_subresource(
            pool_uuid, node.id, self.RESOURCE, self.SUB_REPO_PATHS
        ) or {}
        available_paths = _extract_paths(avail)

        desired = {_normalize_path_str(p) for p in storage_paths}
        missing = sorted(p for p in desired if p not in available_paths)

        if missing:
            raise ValidationError(f"Missing storage paths: {', '.join(missing)}")

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
