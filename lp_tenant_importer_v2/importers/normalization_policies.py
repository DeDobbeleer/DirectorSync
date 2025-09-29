# lp_tenant_importer_v2/importers/normalization_policies.py
"""
Normalization Policies importer (DirectorSync v2)
Strict payload comparison per user's spec.

Algorithm
---------
- Build SOURCE payload from Excel:
    name (policy_name: str)
    normalization_packages: list[str] of package *names* (sorted, may be [])
    compiled_normalizer:    list[str] of compiled names    (sorted, may be [])
  Constraint: both lists cannot be empty simultaneously (row is rejected/Skipped).

- Build DESTINATION payload from API (List NormalizationPolicy):
    name (str)
    normalization_packages: list[str] of package *names* (IDs mapped to names; sorted)
    compiled_normalizer:    list[str] of compiled names (if field absent → [])

- Decision rules:
    1) If any SOURCE package name is unknown on node OR any SOURCE compiled name
       is not installed on node → SKIP (with reason).
    2) Else if DESTINATION policy does not exist → CREATE.
    3) Else if SOURCE payload == DESTINATION payload → NOOP.
    4) Else → UPDATE.
  For UPDATE, empty lists in SOURCE explicitly clear the field on the node:
    - normalization_packages=[]  → send norm_packages=""  (clear)
    - compiled_normalizer=[]     → send compiled_normalizer="" (clear)

API (Director 2.7.0)
--------------------
- POST  configapi/{pool}/{node}/NormalizationPolicy
    data: { name, norm_packages: "ID1,ID2" or "", compiled_normalizer: "C1,C2" or "" }
- PUT   configapi/{pool}/{node}/NormalizationPolicy/{id}
    data: {        norm_packages: "ID1,ID2" or "", compiled_normalizer: "C1,C2" or "" }
- GET   .../NormalizationPackage                              (list packages)
- GET   .../NormalizationPackage/CompiledNormalizers          (inventory)
- GET   .../NormalizationPolicy                               (list policies)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter, NodeRef  # provides run_for_nodes()
from ..core.director_client import DirectorClient
from ..utils.validators import require_columns, ValidationError
from ..utils.resolvers import ResolverCache

log = logging.getLogger(__name__)


# ---------- Helpers ----------

def _is_blank(x: Any) -> bool:
    if x is None:
        return True
    if isinstance(x, float) and pd.isna(x):
        return True
    return str(x).strip() == ""


def _split_excel_list(x: Any, sep: str = "|") -> List[str]:
    """
    Excel side uses '|' separated values.
    Return a trimmed, unique, order-preserving list.
    """
    if _is_blank(x):
        return []
    out: List[str] = []
    seen = set()
    for part in str(x).split(sep):
        p = part.strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _split_any(val: Any, seps: Tuple[str, ...] = (",", "|")) -> List[str]:
    """
    Split a value coming from API (CSV string) or Excel.
    Accept both ',' and '|'; trim/unique/ordered.
    """
    if _is_blank(val):
        return []
    s = str(val)
    parts = [s]
    for sep in seps:
        new_parts: List[str] = []
        for chunk in parts:
            new_parts.extend(chunk.split(sep))
        parts = new_parts
    out: List[str] = []
    seen = set()
    for p in (x.strip() for x in parts):
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


# ---------- Importer ----------

class NormalizationPoliciesImporter(BaseImporter):
    """
    Import Normalization Policies with strict SOURCE vs DESTINATION payload comparison.
    """

    resource_name = "normalization_policies"
    sheet_names = ("NormalizationPolicy",)
    required_columns = ("policy_name", "normalization_packages", "compiled_normalizer")
    # Base diff engine will use these keys; we feed it canonical lists (sorted).
    compare_keys = ("name", "normalization_packages", "compiled_normalizer")
    RESOURCE = "NormalizationPolicy"

    def __init__(self) -> None:
        super().__init__()
        self._cache = ResolverCache()
        # per-node caches
        self._pkg_name_to_id: Dict[str, Dict[str, str]] = {}   # node.id -> {name:id}
        self._pkg_id_to_name: Dict[str, Dict[str, str]] = {}   # node.id -> {id:name}
        self._compiled_set: Dict[str, set] = {}                # node.id -> {compiled_name}

    # ---------- Validation ----------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        sheet = self.sheet_names[0]
        if sheet not in sheets:
            log.error("Missing required sheet: %s", sheet)
            raise ValidationError(f"Missing required sheet: {sheet}")
        require_columns(sheets[sheet], self.required_columns, context=sheet)
        log.info(
            "Sheet '%s' validated with required columns %s",
            sheet,
            self.required_columns,
        )

    # ---------- Parse desired (SOURCE) ----------

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        """
        Yield rows with raw SOURCE intent (names); canonicalization happens in canon_desired().
        Enforce: both lists cannot be empty together → row is skipped with a warning.
        """
        sheet = self.sheet_names[0]
        df = sheets[sheet]
        log.debug("Parsing rows from sheet '%s' (%d rows)", sheet, len(df))

        for idx, row in df.iterrows():
            line_no = idx + 2  # account for header
            name = str(row.get("policy_name", "")).strip()

            if not name:
                log.warning("Row %d: empty policy_name → skip", line_no)
                continue

            pkg_names = _split_excel_list(row.get("normalization_packages"))
            compiled_names = _split_excel_list(row.get("compiled_normalizer"))

            if not pkg_names and not compiled_names:
                log.error(
                    "Row %d (%s): normalization_packages and compiled_normalizer are both empty → SKIP",
                    line_no,
                    name,
                )
                yield {
                    "name": name,
                    "skip_empty": True,
                    "package_names": [],
                    "compiled_names": [],
                }
                continue

            log.debug(
                "Row %d (%s): pk=%s compiled=%s",
                line_no,
                name,
                pkg_names,
                compiled_names,
            )

            yield {
                "name": name,
                "package_names": pkg_names,
                "compiled_names": compiled_names,
            }

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row.get("name", "")

    # ---------- Canonical (for diff) ----------

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """
        SOURCE canonical view for comparison:
          - name: str
          - normalization_packages: sorted list[str] (names; [] allowed)
          - compiled_normalizer:    sorted list[str] (names; [] allowed)
        """
        name = desired_row.get("name", "")
        if desired_row.get("skip_empty"):
            # emit both lists empty; diff engine will not plan apply; we'll SKIP in apply()
            return {"name": name, "normalization_packages": [], "compiled_normalizer": []}

        pk_names = sorted(desired_row.get("package_names") or [])
        comp_names = sorted(desired_row.get("compiled_names") or [])
        out = {
            "name": name,
            "normalization_packages": pk_names,
            "compiled_normalizer": comp_names,
        }
        log.debug("Desired canon for %s → %s", name, out)
        return out

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        DESTINATION canonical view for comparison:
          - name: str
          - normalization_packages: IDs → names (sorted; [] if none)
          - compiled_normalizer: CSV/list → names (sorted; [] if field is missing/empty)
        """
        if not existing_obj:
            return None

        node_id = existing_obj.get("_node_id")
        name = str(existing_obj.get("name") or "").strip()

        # packages: IDs -> names
        id_list = existing_obj.get("normalization_packages") or []
        id2name = self._pkg_id_to_name.get(node_id, {})
        pk_names = sorted([id2name.get(i, i) for i in id_list]) if isinstance(id_list, list) else []

        # compiled: accept list or CSV string; if not present, treat as empty list
        compiled_field = existing_obj.get("compiled_normalizer")
        if isinstance(compiled_field, (list, str)):
            compiled_names = sorted(_split_any(compiled_field))
        else:
            compiled_names = []

        out = {
            "name": name,
            "normalization_packages": pk_names,
            "compiled_normalizer": compiled_names,
        }
        log.debug("Existing canon for node=%s policy=%s → %s", node_id, name, out)
        return out

    # ---------- Fetch caches + existing ----------

    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """
        Warm per-node caches and return map of existing policies by name.
        We only use the List endpoint for NormalizationPolicy (as specified).
        """
        node_id = node.id
        log.info(
            "Fetching caches & existing NormalizationPolicy on node=%s (%s)",
            node.name,
            node_id,
        )

        # 1) List packages (name<->id maps)
        pkgs = client.list_resource(pool_uuid, node_id, "NormalizationPackage") or []
        name2id: Dict[str, str] = {}
        id2name: Dict[str, str] = {}
        for it in (pkgs if isinstance(pkgs, list) else []):
            pid = it.get("id")
            pname = str(it.get("name", "")).strip()
            if pid and pname:
                name2id[pname] = pid
                id2name[pid] = pname
        self._pkg_name_to_id[node_id] = name2id
        self._pkg_id_to_name[node_id] = id2name
        log.info("Cached %d NormalizationPackage(s) on %s", len(name2id), node.name)

        # 2) Compiled normalizers inventory (for validation)
        compiled = client.list_subresource(
            pool_uuid, node_id, "NormalizationPackage", "CompiledNormalizers"
        ) or []
        compiled_set = {
            str(it.get("name", "")).strip() for it in compiled if isinstance(it, dict)
        }
        self._compiled_set[node_id] = compiled_set
        log.info("Cached %d compiled normalizer(s) on %s", len(compiled_set), node.name)

        # 3) List existing policies
        data = client.list_resource(pool_uuid, node_id, self.RESOURCE) or []
        out: Dict[str, Dict[str, Any]] = {}
        for it in (data if isinstance(data, list) else []):
            nm = str(it.get("name", "")).strip()
            if not nm:
                continue
            it["_node_id"] = node_id
            it["_pool_uuid"] = pool_uuid
            out[nm] = it

        log.info("Found %d existing NormalizationPolicy on node %s", len(out), node.name)
        return out

    # ---------- Dry-run hints (optional) ----------

    def plan_hints_for_node(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        planned_rows: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Enrich dry-run table with 'corr' and 'error' per row by pre-validating
        packages/compiled. Returns {policy_name: {"corr": "...", "error": "...", ...}}
        """
        hints: Dict[str, Dict[str, Any]] = {}
        name2id = self._pkg_name_to_id.get(node.id, {})
        compiled = self._compiled_set.get(node.id, set())

        for r in planned_rows:
            name = r.get("name")
            desired = r.get("_desired") or {}
            pk = desired.get("package_names") or []
            cn = desired.get("compiled_names") or []

            missing_pk = [x for x in pk if x not in name2id]
            missing_cn = [x for x in cn if x and x not in compiled]

            pieces = []
            if pk:
                pieces.append("pk=" + "|".join(pk))
            if cn:
                pieces.append("compiled=" + "|".join(cn))
            if missing_pk:
                pieces.append("missing_pk=" + "|".join(missing_pk))
            if missing_cn:
                pieces.append("missing_compiled=" + "|".join(missing_cn))

            if pieces:
                hints[name] = {"corr": "; ".join(pieces)}
                if missing_pk or missing_cn:
                    hints[name]["status"] = "Skipped"
                    if missing_pk and missing_cn:
                        hints[name]["error"] = (
                            "missing packages: " + ", ".join(missing_pk)
                            + "; missing compiled: " + ", ".join(missing_cn)
                        )
                    elif missing_pk:
                        hints[name]["error"] = "missing packages: " + ", ".join(missing_pk)
                    else:
                        hints[name]["error"] = "missing compiled: " + ", ".join(missing_cn)

        return hints

    # ---------- Payload builders ----------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        # keep raw names; IDs are resolved in apply()
        return {"name": desired_row["name"], **self._payload_common(desired_row)}

    def build_payload_update(
        self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
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
        """
        Apply CREATE/UPDATE with explicit clears when lists are empty.
        Also enforce SKIP rules for missing packages/compiled on node.
        """
        desired = dict(decision.desired or {})
        name = desired.get("name", "(unnamed)")
        log.info("[%s|%s] %s → %s", pool_uuid, node.name, name, decision.op)

        # Reject rows where both lists are empty (already flagged in parse path)
        if desired.get("skip_empty"):
            msg = "both normalization_packages and compiled_normalizer are empty"
            log.error("[%s|%s] SKIP %s: %s", pool_uuid, node.name, name, msg)
            return {"status": "Skipped", "error": msg, "monitor_ok": None, "corr": "empty payload"}

        # Resolve packages names -> IDs for this node
        pkg_names: List[str] = desired.get("package_names") or desired.get("_package_names") or []
        compiled_names: List[str] = desired.get("compiled_names") or desired.get("_compiled_names") or []

        log.debug(
            "[%s|%s] %s desired pk=%s compiled=%s",
            pool_uuid, node.name, name, pkg_names, compiled_names
        )

        name2id = self._pkg_name_to_id.get(node.id, {})
        compiled_inv = self._compiled_set.get(node.id, set())

        # Rule 1: SKIP if any requested package/compiled doesn't exist on node
        missing_pk = [n for n in pkg_names if n not in name2id]
        missing_cn = [n for n in compiled_names if n and n not in compiled_inv]
        if missing_pk or missing_cn:
            err = []
            if missing_pk:
                err.append("missing NormalizationPackage(s): " + ", ".join(sorted(missing_pk)))
            if missing_cn:
                err.append("missing CompiledNormalizer(s): " + ", ".join(sorted(missing_cn)))
            msg = f"on node {node.name}: " + " ; ".join(err)
            log.error("[%s|%s] %s → SKIP: %s", pool_uuid, node.name, name, msg)
            return {
                "status": "Skipped",
                "error": msg,
                "monitor_ok": None,
                "corr": (
                    ("pk=" + "|".join(pkg_names) if pkg_names else "")
                    + ("; " if pkg_names and compiled_names else "")
                    + ("compiled=" + "|".join(compiled_names) if compiled_names else "")
                ) or None,
            }

        # Build API payload according to docs (explicit clears when needed)
        pkg_ids = [name2id[n] for n in pkg_names]
        data: Dict[str, Any] = {}
        if decision.op == "CREATE":
            data["name"] = name

        # norm_packages: CSV of IDs; empty list → empty string to clear
        data["norm_packages"] = ",".join(pkg_ids) if pkg_ids else ""

        # compiled_normalizer: CSV of names; empty list → empty string to clear
        data["compiled_normalizer"] = ",".join(compiled_names) if compiled_names else ""

        log.debug("[%s|%s] %s payload %s", pool_uuid, node.name, decision.op, data)

        # Guard against illegal CREATE with both sides empty (shouldn't happen due to earlier check)
        if decision.op == "CREATE" and not data.get("norm_packages") and not data.get("compiled_normalizer"):
            msg = f"refusing to create empty NormalizationPolicy {name} on node {node.name}"
            log.error("[%s|%s] %s → FAIL: %s", pool_uuid, node.name, name, msg)
            return {"status": "Failed", "error": msg, "monitor_ok": None, "corr": "empty payload"}

        # Perform API call
        if decision.op == "CREATE":
            res = client.create_resource(pool_uuid, node.id, self.RESOURCE, data)
        elif decision.op == "UPDATE" and existing_id:
            res = client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, data)
        else:
            # NOOP or unexpected path
            log.info("[%s|%s] %s: NOOP", pool_uuid, node.name, name)
            return {"status": "Success"}

        log.info(
            "[%s|%s] %s → %s (monitor_ok=%s)",
            pool_uuid,
            node.name,
            name,
            res.get("status"),
            res.get("monitor_ok"),
        )

        # Corr/hints for the final table
        corr_fragments: List[str] = []
        if pkg_names:
            corr_fragments.append("pk=" + "|".join(pkg_names))
        else:
            corr_fragments.append("pk=(clear)")
        if compiled_names:
            corr_fragments.append("compiled=" + "|".join(compiled_names))
        else:
            corr_fragments.append("compiled=(clear)")

        return {
            "status": res.get("status") or "Success",
            "monitor_ok": res.get("monitor_ok"),
            "monitor_branch": res.get("monitor_branch"),
            "result": res.get("result"),
            "corr": "; ".join(corr_fragments),
        }
