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


def _node_tag(node: NodeRef) -> str:
    """Printable node tag 'name|id' for logs."""
    name = getattr(node, "name", None) or getattr(node, "id", "")
    nid = getattr(node, "id", "")
    return f"{name}|{nid}"


class ReposImporter(BaseImporter):
    """Minimal importer for Repos (profiles + whitelisted payloads)."""

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

    # -------------------- Read existing --------------------

    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        """Return {name -> object}, tolerating list/dict from the API."""
        node_t = _node_tag(node)
        log.info("fetch_existing: start [node=%s]", node_t)
        data: JSON = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []

        log.debug(
            "fetch_existing: payload type=%s len=%s [node=%s]",
            type(data).__name__,
            (len(data) if hasattr(data, "__len__") else "n/a"),
            node_t,
        )

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

        log.info("fetch_existing: found %d repos [node=%s]", len(out), node_t)
        return out

    # -------------------- RepoPaths verification --------------------

    def _extract_paths(self, raw: Any) -> Set[str]:
        """Collect valid RepoPaths from common shapes."""
        paths: Set[str] = set()
        if raw is None:
            return paths

        # Standard common shapes first
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

        # Fallback: simple recursive scan
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
        node_t = _node_tag(node)
        if not storage_paths:
            log.info("verify_paths: nothing to verify (empty) [node=%s]", node_t)
            return []

        log.info("verify_paths: desired=%d [node=%s]", len(storage_paths), node_t)
        avail_raw = client.list_subresource(pool_uuid, node.id, self.RESOURCE, self.SUB_REPO_PATHS) or {}
        available = self._extract_paths(avail_raw)

        log.debug(
            "verify_paths: available=%d sample=%s [node=%s]",
            len(available), list(sorted(available))[:5], node_t
        )

        desired = {
            (p.strip() if p.strip().endswith("/") else p.strip() + "/")
            for p in storage_paths
            if isinstance(p, str) and p.strip()
        }
        missing = sorted(p for p in desired if p not in available)
        if missing:
            log.warning("verify_paths: missing=%s [node=%s]", missing, node_t)
        else:
            log.info("verify_paths: all ok (%d paths) [node=%s]", len(desired), node_t)
        return missing

    # -------------------- Payloads --------------------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return REPOS_PROFILE.build_post_payload(desired_row)

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        return REPOS_PROFILE.build_put_payload(existing_obj.get("id", ""), desired_row)

    # -------------------- Apply (RAW desired) --------------------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        node_t = _node_tag(node)
        desired = (decision.desired or {}).copy()
        repo_name = desired.get("name") or "(unnamed)"

        log.info("apply: op=%s repo=%s [node=%s]", getattr(decision, "op", "?"), repo_name, node_t)
        log.debug("apply: desired keys=%s [node=%s]", list(desired.keys()), node_t)

        # 1) verify paths
        desired_paths = [
            p.get("path", "").strip()
            for p in (desired.get("hiddenrepopath") or [])
            if isinstance(p, dict) and p.get("path")
        ]
        missing = self._verify_paths(client, pool_uuid, node, desired_paths)
        if missing:
            log.warning(
                "apply: skipping repo %s due to missing paths=%s [node=%s]",
                repo_name, missing, node_t
            )
            return {"status": "Skipped", "result": {"missing_paths": missing}}

        # 2) create or update
        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                log.info("apply: CREATE repo=%s [node=%s]", repo_name, node_t)
                log.debug("apply: CREATE payload=%s [node=%s]", payload, node_t)
                res = client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
                log.debug("apply: CREATE result=%s [node=%s]", res, node_t)
                return res

            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id})
                log.info("apply: UPDATE repo=%s id=%s [node=%s]", repo_name, existing_id, node_t)
                log.debug("apply: UPDATE payload=%s [node=%s]", payload, node_t)
                res = client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)
                log.debug("apply: UPDATE result=%s [node=%s]", res, node_t)
                return res

            log.info("apply: NOOP repo=%s [node=%s]", repo_name, node_t)
            return {"status": "Success"}

        except Exception:
            log.exception("apply: API call failed for repo=%s [node=%s]", repo_name, node_t)
            raise
