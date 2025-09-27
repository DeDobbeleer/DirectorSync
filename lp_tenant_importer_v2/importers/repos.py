from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple, Union
import logging

from lp_tenant_importer_v2.core.director_client import DirectorClient
from lp_tenant_importer_v2.utils.validators import ValidationError  # if you prefer, you can remove this import
from lp_tenant_importer_v2.importers.base import BaseImporter, NodeRef

JSON = Union[Dict[str, Any], List[Any]]
log = logging.getLogger(__name__)


class ReposImporter(BaseImporter):
    """Minimal, straightforward implementation for Repos."""

    RESOURCE = "Repos"
    SUB_REPO_PATHS = "RepoPaths"

    # Keep your compare keys as defined in your project (example below).
    # The decide() in BaseImporter still uses canonical shapes; apply() receives RAW desired.
    compare_keys: Tuple[str, ...] = (
        "name",
        "hiddenrepopath",
        "repoha",
        "description",
        "type",
        "hiddenrepo",
    )

    # ---------- Fetch existing ----------

    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Return existing repos as a map: repo_name -> repo_object.
        Tolerates Director APIs returning either a list or a dict wrapper.
        """
        data: JSON = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []

        # Normalize to a list of dicts
        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            items_any = (
                data.get("repos")
                or data.get("items")
                or data.get("data")
                or []
            )
            items = [x for x in items_any if isinstance(x, dict)]
        else:
            items = []

        result: Dict[str, Dict[str, Any]] = {}
        for it in items:
            name = (it.get("name") or it.get("label") or "").strip()
            if name:
                result[name] = it
        return result

    # ---------- Path verification (simple) ----------

    def _extract_paths(self, obj: Any, out: Set[str]) -> None:
        """Collect path strings from any RepoPaths JSON shape."""
        if obj is None:
            return
        if isinstance(obj, str):
            out.add(obj.strip())
            return
        if isinstance(obj, dict):
            # common keys first
            if "paths" in obj:
                self._extract_paths(obj.get("paths"), out)
                return
            if "path" in obj and isinstance(obj["path"], str):
                out.add(obj["path"].strip())
                return
            # otherwise scan values
            for v in obj.values():
                self._extract_paths(v, out)
            return
        if isinstance(obj, (list, tuple)):
            for v in obj:
                self._extract_paths(v, out)

    def _verify_paths(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        storage_paths: List[str],
    ) -> List[str]:
        """
        Return missing storage paths for this node.
        No exception is raised; caller decides what to do (usually: Skipped).
        """
        if not storage_paths:
            return []
        avail = client.list_subresource(
            pool_uuid, node.id, self.RESOURCE, self.SUB_REPO_PATHS
        ) or {}
        available: Set[str] = set()
        self._extract_paths(avail, available)

        desired = {p.strip() for p in storage_paths if isinstance(p, str) and p.strip()}
        missing = sorted(p for p in desired if p not in available)

        if missing:
            log.debug("RepoPaths missing on %s/%s: %s", pool_uuid, node.name, missing)
        return missing

    # ---------- Payload builders (pass-through minimal) ----------

    def build_payload_create(self, desired: Dict[str, Any]) -> Dict[str, Any]:
        """
        Keep it simple: pass through only known/needed keys.
        Add/remove keys here to match your Director version if needed.
        """
        keep = {
            "name",
            "hiddenrepopath",
            "repoha",
            "description",
            "type",
            "hiddenrepo",
        }
        return {k: v for k, v in desired.items() if k in keep}

    def build_payload_update(
        self, desired: Dict[str, Any], existing: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Same philosophy as create; include only fields you want to update.
        """
        return self.build_payload_create(desired)

    # ---------- Apply (RAW desired expected) ----------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        """
        decision.desired is RAW (payload shape), not canonical.
        We only:
          1) verify RepoPaths,
          2) create or update using minimal payloads,
          3) return a compact status dict.
        """
        desired: Dict[str, Any] = (decision.desired or {}).copy()

        # 1) Verify storage paths (from hiddenrepopath)
        desired_paths = [
            p.get("path", "").strip()
            for p in (desired.get("hiddenrepopath") or [])
            if isinstance(p, dict)
        ]
        missing = self._verify_paths(client, pool_uuid, node, desired_paths)
        if missing:
            return {"status": "Skipped", "result": {"missing_paths": missing}}

        # 2) Apply
        if decision.op == "CREATE":
            payload = self.build_payload_create(desired)
            res = client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
            return res

        if decision.op == "UPDATE" and existing_id:
            payload = self.build_payload_update(desired, {"id": existing_id})
            res = client.update_resource(
                pool_uuid, node.id, self.RESOURCE, existing_id, payload
            )
            return res

        # NOOP or nothing to change
        return {"status": "Success"}
