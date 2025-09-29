# lp_tenant_importer_v2/importers/normalization_policies.py
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter, NodeRef   # provides run_for_nodes()
from ..core.director_client import DirectorClient
from ..utils.validators import require_columns, ValidationError
from ..utils.resolvers import ResolverCache

log = logging.getLogger(__name__)


def _is_blank(x: Any) -> bool:
    if x is None:
        return True
    if isinstance(x, float) and pd.isna(x):
        return True
    return str(x).strip() == ""


def _split_multi(x: Any, sep: str = "|") -> List[str]:
    if _is_blank(x):
        return []
    out, seen = [], set()
    for part in str(x).split(sep):
        p = part.strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


@dataclass(frozen=True)
class _Desired:
    name: str
    package_names: List[str]
    compiled_names: List[str]
    skip_empty: bool = False


class NormalizationPoliciesImporter(BaseImporter):
    """
    V2 importer for Normalization Policies.

    Sheets & columns (case-sensitive):
      - Sheet: "NormalizationPolicy"
      - Columns: "policy_name", "normalization_packages", "compiled_normalizer"

    Diff model:
      - Compare on ("name", "normalization_packages") **by package NAMES**.
        (API List/Get returns package **IDs**; we map IDs -> names before comparing.)
      - 'compiled_normalizer' is treated as write-only (API doesn’t return it).
    """

    resource_name = "normalization_policies"
    sheet_names = ("NormalizationPolicy",)
    required_columns = ("policy_name", "normalization_packages", "compiled_normalizer")
    compare_keys = ("name", "normalization_packages")

    # Director API resource segment
    RESOURCE = "NormalizationPolicy"

    def __init__(self) -> None:
        super().__init__()
        self._cache = ResolverCache()
        # per-node caches
        self._pkg_name_to_id: Dict[str, Dict[str, str]] = {}  # node.id -> {name:id}
        self._pkg_id_to_name: Dict[str, Dict[str, str]] = {}  # node.id -> {id:name}
        self._compiled_set: Dict[str, set] = {}               # node.id -> {compiled_name}

    # ---------- Validation ----------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        if self.sheet_names[0] not in sheets:
            raise ValidationError(f"Missing required sheet: {self.sheet_names[0]}")
        require_columns(sheets[self.sheet_names[0]], self.required_columns, context=self.sheet_names[0])

    # ---------- Parse desired ----------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        df = sheets[self.sheet_names[0]]
        for idx, row in df.iterrows():
            name = str(row.get("policy_name", "")).strip()
            if not name:
                log.warning("NormalizationPolicy row %d: empty policy_name, skipping", idx + 2)
                continue

            package_names = _split_multi(row.get("normalization_packages"))
            compiled_names = _split_multi(row.get("compiled_normalizer"))

            if not package_names and not compiled_names:
                # UX parity with v1: skip empty lines
                log.warning("NormalizationPolicy row %d (%s): both fields empty, skipping", idx + 2, name)
                yield {"name": name, "skip_empty": True}
                continue

            yield {"name": name, "package_names": package_names, "compiled_names": compiled_names}

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row.get("name", "")

    # ---------- Canonical (diff) ----------

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        if desired_row.get("skip_empty"):
            return {"name": desired_row["name"], "normalization_packages": []}
        # Compare on **names** for stability across nodes
        pk_names = sorted(desired_row.get("package_names") or [])
        return {"name": desired_row["name"], "normalization_packages": pk_names}

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not existing_obj:
            return None
        # Map returned IDs -> names using per-node cache filled in fetch_existing()
        node_id = existing_obj.get("_node_id")  # injected in fetch_existing()
        ids = existing_obj.get("normalization_packages") or []
        names = []
        if node_id and isinstance(ids, list):
            id2name = self._pkg_id_to_name.get(node_id, {})
            names = sorted([id2name.get(i, i) for i in ids])
        return {"name": str(existing_obj.get("name") or ""), "normalization_packages": names}

    # ---------- Fetch existing + warm caches ----------

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        node_id = node.id

        # 1) List packages (name<->id maps)
        pkgs = client.list_resource(pool_uuid, node_id, "NormalizationPackage") or []
        name2id, id2name = {}, {}
        if isinstance(pkgs, list):
            for it in pkgs:
                pid = it.get("id")
                pname = str(it.get("name", "")).strip()
                if pid and pname:
                    name2id[pname] = pid
                    id2name[pid] = pname
        self._pkg_name_to_id[node_id] = name2id
        self._pkg_id_to_name[node_id] = id2name

        # 2) Compiled normalizers inventory (optional validation)
        compiled = client.list_subresource(pool_uuid, node_id, "NormalizationPackage", "CompiledNormalizers") or []
        self._compiled_set[node_id] = {str(it.get("name", "")).strip() for it in compiled if isinstance(it, dict)}

        # 3) List existing policies and attach node_id for canon_existing()
        data = client.list_resource(pool_uuid, node_id, self.RESOURCE) or []
        out: Dict[str, Dict[str, Any]] = {}
        for it in (data if isinstance(data, list) else []):
            nm = str(it.get("name", "")).strip()
            if nm:
                it["_node_id"] = node_id
                out[nm] = it
        log.info("normalization_policies: found %d existing on node=%s", len(out), node_id)
        return out

    # ---------- Payload builders ----------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        # name is required on CREATE (per API)
        return {"name": desired_row["name"], **self._payload_common(desired_row)}

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        # name is *not* required on UPDATE (per API), but harmless if present
        return self._payload_common(desired_row)

    def _payload_common(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        # Filled later in apply() when we know the node -> convert names to IDs
        return {
            "_package_names": list(desired_row.get("package_names") or []),
            "_compiled_names": list(desired_row.get("compiled_names") or []),
        }

    # ---------- Apply ----------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        desired = dict(decision.desired or {})
        name = desired.get("name", "(unnamed)")

        if desired.get("skip_empty"):
            log.warning("Skipping NormalizationPolicy %s: both fields empty", name)
            return {"status": "Skipped", "monitor_ok": None}

        # Resolve package names -> IDs for this node
        pkg_names: List[str] = desired.get("package_names") or desired.get("_package_names") or []
        compiled_names: List[str] = desired.get("compiled_names") or desired.get("_compiled_names") or []

        name2id = self._pkg_name_to_id.get(node.id, {})
        missing = [n for n in pkg_names if n not in name2id]
        if missing:
            msg = f"missing NormalizationPackage(s) on node {node.name}: {', '.join(sorted(missing))}"
            log.error(msg)
            return {"status": "Failed", "error": msg}

        pkg_ids = [name2id[n] for n in pkg_names]

        # Optional validation for compiled normalizers
        invalid_cn = [n for n in compiled_names if n and n not in self._compiled_set.get(node.id, set())]
        if invalid_cn:
            log.warning("Compiled normalizers not installed on node %s for policy %s: %s", node.name, name, ", ".join(invalid_cn))

        # Build API payload according to docs (CSV strings)
        data: Dict[str, Any] = {}
        if decision.op == "CREATE":
            data["name"] = name
        if pkg_ids:
            data["norm_packages"] = ",".join(pkg_ids)
        if compiled_names:
            data["compiled_normalizer"] = ",".join(compiled_names)

        if decision.op == "CREATE" and not pkg_ids and not compiled_names:
            msg = f"refusing to create empty NormalizationPolicy {name} on node {node.name}"
            log.error(msg)
            return {"status": "Failed", "error": msg}

        if decision.op == "CREATE":
            res = client.create_resource(pool_uuid, node.id, self.RESOURCE, data)
        elif decision.op == "UPDATE" and existing_id:
            res = client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, data)
        else:
            # NOOP (or unexpected)
            return {"status": "Success"}

        # Normalize return
        return {
            "status": res.get("status") or "Success",
            "monitor_ok": res.get("monitor_ok"),
            "monitor_branch": res.get("monitor_branch"),
            "result": res.get("result"),
        }
