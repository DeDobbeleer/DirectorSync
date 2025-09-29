# lp_tenant_importer_v2/importers/normalization_policies.py
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter, NodeRef  # run_for_nodes()
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

    Sheet: "NormalizationPolicy"
    Columns: "policy_name", "normalization_packages", "compiled_normalizer"

    Diff model:
      - Compare on ("name", "normalization_packages") by **package names**.
        (API List/Get returns package IDs → mapped back to names before comparing.)
      - 'compiled_normalizer' is write-only (not returned by List/Get).
    """

    resource_name = "normalization_policies"
    sheet_names = ("NormalizationPolicy",)
    required_columns = ("policy_name", "normalization_packages", "compiled_normalizer")
    compare_keys = ("name", "normalization_packages")
    RESOURCE = "NormalizationPolicy"

    def __init__(self) -> None:
        super().__init__()
        self._cache = ResolverCache()
        self._pkg_name_to_id: Dict[str, Dict[str, str]] = {}  # node.id -> {name:id}
        self._pkg_id_to_name: Dict[str, Dict[str, str]] = {}  # node.id -> {id:name}
        self._compiled_set: Dict[str, set] = {}               # node.id -> {compiled_name}

    # ---------- Validation ----------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        sheet = self.sheet_names[0]
        if sheet not in sheets:
            log.error("Missing required sheet: %s", sheet)
            raise ValidationError(f"Missing required sheet: {sheet}")
        require_columns(sheets[sheet], self.required_columns, context=sheet)
        log.info("Sheet '%s' validated with required columns %s", sheet, self.required_columns)

    # ---------- Parse desired ----------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        sheet = self.sheet_names[0]
        df = sheets[sheet]
        log.debug("Parsing desired rows from sheet '%s' with %d rows", sheet, len(df))

        for idx, row in df.iterrows():
            name = str(row.get("policy_name", "")).strip()
            if not name:
                log.warning("Row %d: empty policy_name → skip", idx + 2)
                continue

            package_names = _split_multi(row.get("normalization_packages"))
            compiled_names = _split_multi(row.get("compiled_normalizer"))
            log.debug(
                "Row %d (%s): packages=%s compiled=%s",
                idx + 2, name, package_names, compiled_names
            )

            if not package_names and not compiled_names:
                log.warning("Row %d (%s): both fields empty → SKIP", idx + 2, name)
                yield {"name": name, "skip_empty": True, "package_names": [], "compiled_names": []}
                continue

            yield {"name": name, "package_names": package_names, "compiled_names": compiled_names}

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row.get("name", "")

    # ---------- Canonical (diff) ----------

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        if desired_row.get("skip_empty"):
            return {"name": desired_row["name"], "normalization_packages": []}
        pk_names = sorted(desired_row.get("package_names") or [])
        return {"name": desired_row["name"], "normalization_packages": pk_names}

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not existing_obj:
            return None
        node_id = existing_obj.get("_node_id")
        ids = existing_obj.get("normalization_packages") or []
        names = []
        if node_id and isinstance(ids, list):
            id2name = self._pkg_id_to_name.get(node_id, {})
            names = sorted([id2name.get(i, i) for i in ids])
        out = {"name": str(existing_obj.get("name") or ""), "normalization_packages": names}
        log.debug("Existing canon for node=%s policy=%s → %s", node_id, out["name"], out)
        return out

    # ---------- Fetch existing + warm caches ----------

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        node_id = node.id
        log.info("Fetching caches & existing NormalizationPolicy on node=%s (%s)", node.name, node_id)

        # 1) List packages (name<->id maps)
        pkgs = client.list_resource(pool_uuid, node_id, "NormalizationPackage") or []
        name2id, id2name = {}, {}
        for it in (pkgs if isinstance(pkgs, list) else []):
            pid = it.get("id")
            pname = str(it.get("name", "")).strip()
            if pid and pname:
                name2id[pname] = pid
                id2name[pid] = pname
        self._pkg_name_to_id[node_id] = name2id
        self._pkg_id_to_name[node_id] = id2name
        log.info("Cached %d NormalizationPackage(s) on %s", len(name2id), node.name)
        log.debug("Package map %s: %s", node.name, name2id)

        # 2) Compiled normalizers inventory (optional validation)
        compiled = client.list_subresource(pool_uuid, node_id, "NormalizationPackage", "CompiledNormalizers") or []
        compiled_set = {str(it.get("name", "")).strip() for it in compiled if isinstance(it, dict)}
        self._compiled_set[node_id] = compiled_set
        log.info("Cached %d compiled normalizer(s) on %s", len(compiled_set), node.name)

        # 3) List existing policies and attach node_id for canon_existing()
        data = client.list_resource(pool_uuid, node_id, self.RESOURCE) or []
        out: Dict[str, Dict[str, Any]] = {}
        for it in (data if isinstance(data, list) else []):
            nm = str(it.get("name", "")).strip()
            if nm:
                it["_node_id"] = node_id
                out[nm] = it
        log.info("Found %d existing NormalizationPolicy on node %s", len(out), node.name)
        return out

    # ---------- Payload builders ----------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {"name": desired_row["name"], **self._payload_common(desired_row)}

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        return self._payload_common(desired_row)

    def _payload_common(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
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
        log.info("[%s|%s] %s → %s", pool_uuid, node.name, name, decision.op)

        if desired.get("skip_empty"):
            msg = "both fields empty"
            log.warning("[%s|%s] SKIP %s: %s", pool_uuid, node.name, name, msg)
            return {
                "status": "Skipped",
                "error": msg,
                "corr": "skip: empty fields; pk=[], compiled=[]",
                "monitor_ok": None,
            }

        # Resolve package names -> IDs for this node
        pkg_names: List[str] = desired.get("package_names") or desired.get("_package_names") or []
        compiled_names: List[str] = desired.get("compiled_names") or desired.get("_compiled_names") or []
        log.debug("[%s|%s] %s desired pk=%s compiled=%s", pool_uuid, node.name, name, pkg_names, compiled_names)

        name2id = self._pkg_name_to_id.get(node.id, {})
        missing = [n for n in pkg_names if n not in name2id]
        if missing:
            msg = f"missing NormalizationPackage(s) on node {node.name}: {', '.join(sorted(missing))}"
            log.error("[%s|%s] %s → SKIP: %s", pool_uuid, node.name, name, msg)
            return {
                "status": "Skipped",
                "error": msg,
                "corr": "pk=" + "|".join(pkg_names) + "; missing_pk=" + "|".join(missing),
                "monitor_ok": None,
            }

        pkg_ids = [name2id[n] for n in pkg_names]
        invalid_cn = [n for n in compiled_names if n and n not in self._compiled_set.get(node.id, set())]
        if invalid_cn:
            log.warning("[%s|%s] %s: compiled normalizers not installed: %s", pool_uuid, node.name, name, ", ".join(invalid_cn))

        # Build API payload according to docs (CSV strings)
        data: Dict[str, Any] = {}
        if decision.op == "CREATE":
            data["name"] = name
        if pkg_ids:
            data["norm_packages"] = ",".join(pkg_ids)
        if compiled_names:
            data["compiled_normalizer"] = ",".join(compiled_names)

        log.debug("[%s|%s] %s payload %s", pool_uuid, node.name, decision.op, data)

        if decision.op == "CREATE" and not pkg_ids and not compiled_names:
            msg = f"refusing to create empty NormalizationPolicy {name} on node {node.name}"
            log.error("[%s|%s] %s → FAIL: %s", pool_uuid, node.name, name, msg)
            return {"status": "Failed", "error": msg, "monitor_ok": None, "corr": "empty payload"}

        if decision.op == "CREATE":
            res = client.create_resource(pool_uuid, node.id, self.RESOURCE, data)
        elif decision.op == "UPDATE" and existing_id:
            res = client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, data)
        else:
            log.info("[%s|%s] %s: NOOP", pool_uuid, node.name, name)
            return {"status": "Success"}

        log.info("[%s|%s] %s → %s (monitor_ok=%s)", pool_uuid, node.name, name, res.get("status"), res.get("monitor_ok"))
        return {
            "status": res.get("status") or "Success",
            "monitor_ok": res.get("monitor_ok"),
            "monitor_branch": res.get("monitor_branch"),
            "result": res.get("result"),
            # carry diagnostics forward in the report too
            "corr": (
                "pk=" + "|".join(pkg_names)
                + (("; missing_compiled=" + "|".join(invalid_cn)) if invalid_cn else "")
                + (("; compiled=" + "|".join(compiled_names)) if compiled_names else "")
            ) if (pkg_names or compiled_names or invalid_cn) else None,
        }
