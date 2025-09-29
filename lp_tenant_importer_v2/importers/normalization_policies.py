# lp_tenant_importer_v2/importers/normalization_policies.py
from __future__ import annotations

"""
Normalization Policies importer (v2) — CSV payloads for Director API.

API contract (Director ≥ 2.7, as observed)
------------------------------------------
- POST configapi/{pool}/{node}/NormalizationPolicy
  payload: { "name": "<policy>", "norm_packages": "ID1,ID2" | "", "compiled_normalizer": "C1,C2" | "" }
- PUT  configapi/{pool}/{node}/NormalizationPolicy/{id}
  payload: { "norm_packages": "ID1,ID2" | "", "compiled_normalizer": "C1,C2" | "" }

Notes
-----
- Diff/comparison is done on **names as lists** for stability.
- Payload uses **CSV strings**; the server fails on JSON arrays.
- If both lists are empty, we SKIP the row.
- If any package/compiled is missing on the node, we SKIP with reason.
"""

import logging
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import pandas as pd

from .base import BaseImporter, NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import require_columns

log = logging.getLogger(__name__)

_EMPTY = {"", "nan", "none", "null", "-"}


def _is_blank(x: Any) -> bool:
    if x is None:
        return True
    if isinstance(x, float) and pd.isna(x):
        return True
    s = str(x).strip()
    return s == "" or s.lower() in _EMPTY


def _norm(x: Any) -> str:
    return "" if _is_blank(x) else str(x).strip()


def _split_any(cell: Any, seps: Tuple[str, ...] = ("|", ",")) -> List[str]:
    s = _norm(cell)
    if not s:
        return []
    parts: List[str] = [s]
    for sep in seps:
        next_parts: List[str] = []
        for chunk in parts:
            next_parts.extend(chunk.split(sep))
        parts = next_parts
    out: List[str] = []
    seen: Set[str] = set()
    for p in (x.strip() for x in parts):
        if p and p not in seen:
            out.append(p)
            seen.add(p)
    return out


def _csv(values: Iterable[str]) -> str:
    vals = [v for v in (str(x).strip() for x in values) if v]
    return ",".join(vals)


def _node_tag(node: NodeRef) -> str:
    name = getattr(node, "name", None) or getattr(node, "id", "")
    return f"{name}|{node.id}"


class NormalizationPoliciesImporter(BaseImporter):
    """Importer for Normalization Policies (NP)."""

    resource_name = "normalization_policies"
    sheet_names = ("NormalizationPolicy",)
    required_columns = ("policy_name", "normalization_packages", "compiled_normalizer")
    compare_keys = ("normalization_packages", "compiled_normalizer")

    # Director resource names
    RESOURCE = "NormalizationPolicy"
    PACKAGES_RESOURCE = "NormalizationPackage"
    COMPILED_SUBPATH = "CompiledNormalizers"

    def __init__(self) -> None:
        super().__init__()
        self._pkg_name_to_id: Dict[str, Dict[str, str]] = {}  # node.id -> {name:id}
        self._pkg_id_to_name: Dict[str, Dict[str, str]] = {}  # node.id -> {id:name}
        self._compiled_names: Dict[str, Set[str]] = {}        # node.id -> {name}

    # ---------- validation ----------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        sheet = self.sheet_names[0]
        require_columns(sheets[sheet], self.required_columns, context=f"sheet '{sheet}'")
        log.info("normalization_policies: using sheet '%s'", sheet)
        log.debug("normalization_policies: columns=%s rows=%d", list(sheets[sheet].columns), len(sheets[sheet].index))

    # ---------- desired ----------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets[self.sheet_names[0]]
        cols = {c.lower(): c for c in df.columns}

        def col(name: str) -> str:
            return cols.get(name.lower(), name)

        for _, row in df.iterrows():
            name = _norm(row.get(col("policy_name")))
            if not name:
                continue
            pkgs = _split_any(row.get(col("normalization_packages")))
            compiled = _split_any(row.get(col("compiled_normalizer")))
            yield {
                "name": name,
                "normalization_packages": pkgs,
                "compiled_normalizer": compiled,
                "skip_empty": (not pkgs and not compiled),
            }

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row["name"]

    # ---------- canonicalization for diff ----------

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": desired_row.get("name", ""),
            "normalization_packages": sorted(desired_row.get("normalization_packages") or []),
            "compiled_normalizer": sorted(desired_row.get("compiled_normalizer") or []),
        }

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not existing_obj:
            return None
        node_id = existing_obj.get("_node_id_for_cache") or ""
        id2name = self._pkg_id_to_name.get(node_id, {})
        # packages: API returns list of IDs
        raw_ids = existing_obj.get("normalization_packages") or []
        if isinstance(raw_ids, list):
            pkg_names = [id2name.get(str(i), str(i)) for i in raw_ids if _norm(i)]
        else:
            pkg_names = []
        # compiled: can be list or CSV string
        raw_comp = existing_obj.get("compiled_normalizer") or []
        if isinstance(raw_comp, list):
            comp = [str(x).strip() for x in raw_comp if _norm(x)]
        else:
            comp = _split_any(raw_comp, seps=(",", "|"))
        return {
            "name": _norm(existing_obj.get("name")),
            "normalization_packages": sorted(pkg_names),
            "compiled_normalizer": sorted(comp),
        }

    # ---------- fetch existing & caches ----------

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        node_t = _node_tag(node)
        log.info("fetch_existing: start [node=%s]", node_t)

        # packages cache
        name2id, id2name = self._list_packages(client, pool_uuid, node)
        self._pkg_name_to_id[node.id] = name2id
        self._pkg_id_to_name[node.id] = id2name

        # compiled cache
        self._compiled_names[node.id] = self._list_compiled_normalizers(client, pool_uuid, node)

        # policies list
        data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []
        items = []
        if isinstance(data, dict):
            items = [x for x in (data.get("data") or data.get("items") or data.get("results") or []) if isinstance(x, dict)]
        elif isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]

        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            name = _norm(it.get("name"))
            if not name:
                continue
            it["_node_id_for_cache"] = node.id
            out[name] = it

        log.info("fetch_existing: found %d normalization policies [node=%s]", len(out), node_t)
        return out

    # ---------- payload builders (CSV) ----------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        node_id = desired_row.get("_node_id") or ""
        pkg_ids, _missing = self._map_pkg_names_to_ids(desired_row, node_id)
        return {
            "name": desired_row["name"],
            "norm_packages": _csv(pkg_ids),                       # CSV string
            "compiled_normalizer": _csv(desired_row.get("compiled_normalizer") or []),
        }

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        node_id = desired_row.get("_node_id") or ""
        pkg_ids, _missing = self._map_pkg_names_to_ids(desired_row, node_id)
        return {
            # name not required for PUT
            "norm_packages": _csv(pkg_ids),                       # CSV string
            "compiled_normalizer": _csv(desired_row.get("compiled_normalizer") or []),
        }

    # ---------- apply ----------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        node_t = _node_tag(node)
        desired = dict(decision.desired or {})
        desired["_node_id"] = node.id

        pol_name = desired.get("name") or "(unnamed)"
        log.info("apply: op=%s policy=%s [node=%s]", getattr(decision, "op", "?"), pol_name, node_t)

        if desired.get("skip_empty"):
            reason = "both 'normalization_packages' and 'compiled_normalizer' are empty"
            log.warning("apply: SKIP policy=%s: %s [node=%s]", pol_name, reason, node_t)
            return {"status": "Skipped", "error": reason}

        missing_pkgs, missing_comp = self._verify_dependencies(node.id, desired)
        if missing_pkgs or missing_comp:
            reason_parts = []
            if missing_pkgs:
                reason_parts.append(f"missing packages: {', '.join(sorted(missing_pkgs))}")
            if missing_comp:
                reason_parts.append(f"missing compiled: {', '.join(sorted(missing_comp))}")
            reason = "; ".join(reason_parts)
            log.warning("apply: SKIP policy=%s due to %s [node=%s]", pol_name, reason, node_t)
            return {
                "status": "Skipped",
                "result": {"missing_packages": sorted(missing_pkgs), "missing_compiled": sorted(missing_comp)},
                "error": reason,
            }

        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id})
                return client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)
            log.info("apply: NOOP policy=%s [node=%s]", pol_name, node_t)
            return {"status": "Success"}
        except Exception:
            log.exception("apply: API call failed for policy=%s [node=%s]", pol_name, node_t)
            raise

    # ---------- internals ----------

    def _list_packages(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Tuple[Dict[str, str], Dict[str, str]]:
        data = client.list_resource(pool_uuid, node.id, self.PACKAGES_RESOURCE) or []
        if isinstance(data, dict):
            items = [x for x in (data.get("data") or data.get("items") or data.get("results") or []) if isinstance(x, dict)]
        elif isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        else:
            items = []
        name_to_id: Dict[str, str] = {}
        id_to_name: Dict[str, str] = {}
        for it in items:
            nm = _norm(it.get("name"))
            pid = _norm(it.get("id"))
            if nm and pid:
                name_to_id[nm] = pid
                id_to_name[pid] = nm
        return name_to_id, id_to_name

    def _list_compiled_normalizers(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Set[str]:
        data = client.list_subresource(pool_uuid, node.id, self.PACKAGES_RESOURCE, self.COMPILED_SUBPATH) or []
        names: Set[str] = set()
        if isinstance(data, list):
            for it in data:
                if isinstance(it, dict):
                    nm = _norm(it.get("name"))
                else:
                    nm = _norm(it)
                if nm:
                    names.add(nm)
        elif isinstance(data, dict):
            for it in (data.get("data") or data.get("items") or data.get("results") or []):
                if isinstance(it, dict):
                    nm = _norm(it.get("name"))
                    if nm:
                        names.add(nm)
        return names

    def _map_pkg_names_to_ids(self, desired_row: Dict[str, Any], node_id: str) -> Tuple[List[str], List[str]]:
        name_to_id = self._pkg_name_to_id.get(node_id, {})
        ids: List[str] = []
        missing: List[str] = []
        for nm in (desired_row.get("normalization_packages") or []):
            key = _norm(nm)
            if not key:
                continue
            pid = name_to_id.get(key)
            if pid:
                ids.append(pid)
            else:
                missing.append(key)
        return ids, missing

    def _verify_dependencies(self, node_id: str, desired: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
        missing_pkgs: Set[str] = set()
        missing_comp: Set[str] = set()
        pkg_name_to_id = self._pkg_name_to_id.get(node_id, {})
        for nm in (desired.get("normalization_packages") or []):
            n = _norm(nm)
            if n and n not in pkg_name_to_id:
                missing_pkgs.add(n)
        compiled_available = self._compiled_names.get(node_id, set())
        for nm in (desired.get("compiled_normalizer") or []):
            n = _norm(nm)
            if n and n not in compiled_available:
                missing_comp.add(n)
        return missing_pkgs, missing_comp
