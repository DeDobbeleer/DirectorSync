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
import json
import logging
import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError
from ..utils.resource_profiles import REPOS_PROFILE
from .base import BaseImporter

JSON = Union[Dict[str, Any], List[Any]]

def _short(obj: Any, limit: int = 400) -> str:
    """Safe, short preview for logs."""
    try:
        if isinstance(obj, (dict, list)):
            s = json.dumps(obj)[:limit]
        else:
            s = repr(obj)[:limit]
        return s
    except Exception:
        return f"<unrepr {type(obj).__name__}>"

def _normalize_path_str(path: Any) -> str:
    """
    Normalize a repository path for comparison.
    Logs non-string inputs to reveal offenders (e.g., tuple/list).
    """
    logger = logging.getLogger(__name__)
    if isinstance(path, str):
        s = path.strip()
        logger.debug("normalize_path: input=str len=%d -> %r", len(path), s)
        return s

    logger.warning(
        "normalize_path: non-string input type=%s value=%s (coercing to str)",
        type(path).__name__, _short(path)
    )
    try:
        s = str(path).strip()
        logger.debug("normalize_path: coerced -> %r", s)
        return s
    except Exception:
        logger.exception("normalize_path: failed to coerce input to str")
        raise

def _collect_paths_any(shape: Any, out: Set[str]) -> None:
    """
    Recursively collect path strings from any JSON shape.
    Emits DEBUG for each branch type encountered.
    """
    logger = logging.getLogger(__name__)

    if shape is None:
        logger.debug("_collect_paths_any: None")
        return

    if isinstance(shape, str):
        p = _normalize_path_str(shape)
        out.add(p)
        logger.debug("_collect_paths_any: str -> %r", p)
        return

    if isinstance(shape, dict):
        if "paths" in shape:
            logger.debug("_collect_paths_any: dict with 'paths' -> recurse")
            _collect_paths_any(shape.get("paths"), out)
            return
        if "path" in shape:
            v = shape.get("path")
            logger.debug("_collect_paths_any: dict with 'path' -> %s", type(v).__name__)
            if isinstance(v, str):
                out.add(_normalize_path_str(v))
                return
        logger.debug("_collect_paths_any: dict (scan values); keys=%s", list(shape.keys())[:10])
        for v in shape.values():
            _collect_paths_any(v, out)
        return

    if isinstance(shape, (list, tuple)):
        logger.debug("_collect_paths_any: %s of len=%d", type(shape).__name__, len(shape))
        for v in shape:
            _collect_paths_any(v, out)
        return

    logger.debug("_collect_paths_any: ignore type=%s", type(shape).__name__)

def _extract_paths(avail: JSON) -> Set[str]:
    logger = logging.getLogger(__name__)
    logger.debug("_extract_paths: avail type=%s preview=%s", type(avail).__name__, _short(avail))
    paths: Set[str] = set()
    _collect_paths_any(avail, paths)
    logger.debug("_extract_paths: collected paths=%d sample=%s",
                 len(paths), list(sorted(paths))[:5])
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

    def _decannonize_hiddenrepopath(hrp: Any) -> List[Dict[str, str]]:
        """
        Accepts either a list[dict] (payload shape) or a canonical list of tuples:
        [ ((path_val, ...), (("retention", val), ...)), ... ]
        Returns a payload-friendly list[{"path": "...", "retention": "..."}].
        """
        if not hrp:
            return []
        if isinstance(hrp, list) and hrp and isinstance(hrp[0], dict):
            # Already in payload shape
            return [
                {
                    "path": str(x.get("path", "")).strip(),
                    "retention": str(x.get("retention", "")).strip(),
                }
                for x in hrp
            ]

        # Canonical tuple shape produced by _canon_list_of_dict_unordered
        out: List[Dict[str, str]] = []
        for item in hrp or []:
            # item is expected to be a 2-tuple: (key_tuple, val_tuple)
            # key_tuple: tuple of key field values -> first is 'path'
            # val_tuple: tuple of (field_name, value) pairs -> contains ('retention', value)
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            key_tuple, val_tuple = item
            path_val = ""
            if isinstance(key_tuple, tuple) and key_tuple:
                path_val = str(key_tuple[0]).strip()
            retention_val = ""
            if isinstance(val_tuple, tuple):
                try:
                    retention_val = str(dict(val_tuple).get("retention", "")).strip()
                except Exception:
                    # Be defensive if val_tuple is malformed
                    retention_val = ""
            out.append({"path": path_val, "retention": retention_val})
        return out

    def _decannonize_repoha(rha: Any) -> List[Dict[str, str]]:
        """
        Accepts either a list[dict] (payload shape) or canonical list of tuples:
        [ ((ha_li_val,), (("ha_day", val),)), ... ]
        Returns a payload-friendly list[{"ha_li": "...", "ha_day": "..."}].
        """
        if not rha:
            return []
        if isinstance(rha, list) and rha and isinstance(rha[0], dict):
            return [
                {"ha_li": str(x.get("ha_li", "")).strip(), "ha_day": str(x.get("ha_day", "")).strip()}
                for x in rha
            ]

        out: List[Dict[str, str]] = []
        for item in rha or []:
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            key_tuple, val_tuple = item
            ha_li = ""
            if isinstance(key_tuple, tuple) and key_tuple:
                ha_li = str(key_tuple[0]).strip()
            ha_day = ""
            if isinstance(val_tuple, tuple):
                try:
                    ha_day = str(dict(val_tuple).get("ha_day", "")).strip()
                except Exception:
                    ha_day = ""
            out.append({"ha_li": ha_li, "ha_day": ha_day})
        return out

    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """
        Fetch existing repos from Director, tolerating list/dict payloads.
        Logs the payload shape to help diagnose structure mismatches.
        """
        logger = getattr(self, "logger", logging.getLogger(__name__))
        payload: JSON = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []

        logger.debug(
            "fetch_existing: payload type=%s preview=%s",
            type(payload).__name__, _short(payload)
        )

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
                or payload
            )
            logger.debug(
                "fetch_existing: candidates type=%s preview=%s",
                type(candidates).__name__, _short(candidates)
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
                logger.debug(
                    "fetch_existing: nested type=%s preview=%s",
                    type(nested).__name__, _short(nested)
                )
                if isinstance(nested, list):
                    items = [x for x in nested if isinstance(x, dict)]
                else:
                    items = [candidates]
            else:
                items = []
        else:
            logger.error(
                "fetch_existing: unexpected payload type=%s preview=%s",
                type(payload).__name__, _short(payload)
            )
            raise TypeError(f"Unexpected payload type: {type(payload).__name__}")

        result: Dict[str, Dict[str, Any]] = {}
        for it in items:
            if not isinstance(it, dict):
                logger.warning("fetch_existing: skipping non-dict item type=%s", type(it).__name__)
                continue
            name = it.get("name") or it.get("label") or it.get("RepoName")
            if isinstance(name, str):
                key = name.strip()
                if key:
                    if key in result:
                        logger.warning("fetch_existing: duplicate repo name: %s (overwriting)", key)
                    result[key] = it
            else:
                logger.warning(
                    "fetch_existing: item without string name: keys=%s",
                    list(it.keys())[:10]
                )

        logger.debug("fetch_existing: collected repos=%d", len(result))
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
        Tolerant to dict/list/tuple shapes returned by Repos/RepoPaths.
        """
        logger = getattr(self, "logger", logging.getLogger(__name__))
        try:
            avail = client.list_subresource(
                pool_uuid, node.id, self.RESOURCE, self.SUB_REPO_PATHS
            ) or {}
            logger.debug(
                "_verify_paths: RepoPaths type=%s preview=%s",
                type(avail).__name__, _short(avail)
            )

            available_paths = _extract_paths(avail)
            desired = {_normalize_path_str(p) for p in storage_paths}
            missing = sorted(p for p in desired if p not in available_paths)

            logger.debug(
                "_verify_paths: available=%d desired=%d missing=%d",
                len(available_paths), len(desired), len(missing)
            )
            if missing:
                logger.error("_verify_paths: missing=%s", missing)
                raise ValidationError(f"Missing storage paths: {', '.join(missing)}")

        except Exception:
            # This will include function/line thanks to the formatter and stack trace
            logger.exception(
                "_verify_paths: unhandled exception (pool=%s node=%s)",
                pool_uuid, getattr(node, "name", node.id)
            )
            raise

    # ---------------- payloads & apply ----------------

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
        existing_id: str | None
    ) -> Dict[str, Any]:
        # decision.desired is CANONICAL -> convert back to payload shape
        desired_canon = decision.desired or {}
        desired: Dict[str, Any] = {
            "name": str(desired_canon.get("name", "")).strip(),  # may be absent in canon
            "hiddenrepopath": self._decannonize_hiddenrepopath(desired_canon.get("hiddenrepopath")),
            "repoha": self._decannonize_repoha(desired_canon.get("repoha")),
        }

        # 1) Verify repo paths
        desired_paths = [p["path"] for p in (desired.get("hiddenrepopath") or [])]
        missing = self._verify_paths(client, pool_uuid, node, desired_paths)
        if missing:
            return {"status": "Skipped", "result": {"missing_paths": missing}}

        # 2) Apply
        if decision.op == "CREATE":
            payload = self.build_payload_create(desired)
            return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)

        if decision.op == "UPDATE" and existing_id:
            payload = self.build_payload_update(desired, {"id": existing_id})
            return client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)

        return {"status": "Success"}
