from __future__ import annotations

from typing import Any, Dict, Iterable, List, Set, Tuple, Union
import logging
import pandas as pd

from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError
from ..utils.resource_profiles import REPOS_PROFILE
from .base import BaseImporter, NodeRef

JSON = Union[Dict[str, Any], List[Any]]
log = logging.getLogger(__name__)


class ReposImporter(BaseImporter):
    """Minimal importer for Repos (profils + payloads whitelistés)."""

    resource_name = "repos"
    sheet_names = (REPOS_PROFILE.sheet,)
    required_columns = (REPOS_PROFILE.col_storage_paths, REPOS_PROFILE.col_retention_days)
    compare_keys = REPOS_PROFILE.compare_fields

    RESOURCE = REPOS_PROFILE.api_resource
    SUB_REPO_PATHS = REPOS_PROFILE.sub_repo_paths

    # ------------ XLSX parsing / canonicalisation ------------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets[REPOS_PROFILE.sheet]
        cols = set(df.columns.str.lower())
        if (REPOS_PROFILE.col_name not in cols) and not any(a in cols for a in REPOS_PROFILE.col_name_aliases):
            raise ValidationError(
                f"Missing required column: '{REPOS_PROFILE.col_name}' "
                f"(or one of aliases {REPOS_PROFILE.col_name_aliases})"
            )
        for _, row in df.iterrows():
            yield REPOS_PROFILE.parse_row(row)

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row["name"]

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return REPOS_PROFILE.canon_for_compare(desired_row)

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Dict[str, Any] | None:
        return REPOS_PROFILE.canon_for_compare(existing_obj) if existing_obj else None

    # -------------------- Lecture existant --------------------

    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        """Retourne {name -> objet} en tolérant list/dict côté API."""
        data: JSON = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []

        if isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict):
            items_any = data.get("repos") or data.get("items") or data.get("data") or data.get("results") or []
            items = [x for x in items_any if isinstance(x, dict)]
        else:
            items = []

        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            name = (it.get("name") or it.get("label") or "").strip()
            if name:
                out[name] = it
        return out

    # -------------------- Vérification paths --------------------

    def _extract_paths(self, raw: Any) -> Set[str]:
        """Récupère les RepoPaths valides depuis n’importe quelle forme courante."""
        paths: Set[str] = set()
        if raw is None:
            return paths

        # cas standard: {"paths":[...]} ou [{"paths":[...]}]
        if isinstance(raw, dict) and isinstance(raw.get("paths"), list):
            src = raw["paths"]
        elif isinstance(raw, list) and raw and isinstance(raw[0], dict) and isinstance(raw[0].get("paths"), list):
            src = raw[0]["paths"]
        else:
            src = None

        if isinstance(src, list):
            for p in src:
                if isinstance(p, str) and p:
                    paths.add(p if p.endswith("/") else p + "/")
            return paths

        # fallback: scan récursif très simple
        def _walk(o: Any):
            if isinstance(o, str) and o:
                s = o if o.endswith("/") else o + "/"
                paths.add(s)
            elif isinstance(o, dict):
                for v in o.values():
                    _walk(v)
            elif isinstance(o, (list, tuple)):
                for v in o:
                    _walk(v)

        _walk(raw)
        return paths

    def _verify_paths(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        storage_paths: List[str],
    ) -> List[str]:
        if not storage_paths:
            return []
        avail_raw = client.list_subresource(pool_uuid, node.id, self.RESOURCE, self.SUB_REPO_PATHS) or {}
        available = self._extract_paths(avail_raw)

        desired = {
            (p.strip() if p.strip().endswith("/") else p.strip() + "/")
            for p in storage_paths
            if isinstance(p, str) and p.strip()
        }
        missing = sorted(p for p in desired if p not in available)
        if missing:
            log.debug("RepoPaths missing on %s/%s: %s", pool_uuid, node.name, missing)
        return missing

    # -------------------- Payloads & apply --------------------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return REPOS_PROFILE.build_post_payload(desired_row)

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        return REPOS_PROFILE.build_put_payload(existing_obj.get("id", ""), desired_row)

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        # decision.desired est **payload** (pas canonique)
        desired = decision.desired or {}

        # 1) vérif RepoPaths
        desired_paths = [
            p.get("path", "").strip()
            for p in (desired.get("hiddenrepopath") or [])
            if isinstance(p, dict)
        ]
        missing = self._verify_paths(client, pool_uuid, node, desired_paths)
        if missing:
            return {"status": "Skipped", "result": {"missing_paths": missing}}

        # 2) apply
        if decision.op == "CREATE":
            payload = self.build_payload_create(desired)
            return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)

        if decision.op == "UPDATE" and existing_id:
            payload = self.build_payload_update(desired, {"id": existing_id})
            return client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)

        return {"status": "Success"}
