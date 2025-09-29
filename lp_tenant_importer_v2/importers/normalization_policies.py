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
    Crucial: fetch detail per policy to get 'compiled_normalizer', which many
    list endpoints omit. Sans ça, on voit des UPDATE à chaque run.
    """
    node_id = node.id
    log.info(
        "Fetching caches & existing NormalizationPolicy on node=%s (%s)",
        node.name, node_id,
    )

    # --- 1) NormalizationPackage cache (name <-> id) ------------------------
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

    # --- 2) Compiled normalizers inventory (présence) -----------------------
    # V1 utilisait cette route directe, on la garde.
    compiled = client.list_resource(
        pool_uuid, node_id, "NormalizationPackage/CompiledNormalizers"
    ) or []
    compiled_set = {
        str(it.get("name", "")).strip() for it in compiled if isinstance(it, dict)
    }
    self._compiled_set[node_id] = compiled_set
    log.info("Cached %d compiled normalizer(s) on %s", len(compiled_set), node.name)

    # --- 3) Policies existantes + GET détail par policy ---------------------
    items = client.list_resource(pool_uuid, node_id, self.RESOURCE) or []
    out: Dict[str, Dict[str, Any]] = {}

    # détecte un getter dispo dans DirectorClient
    getters = []
    for cand in ("get_resource", "read_resource", "get", "read"):
        m = getattr(client, cand, None)
        if callable(m):
            getters.append((cand, m))

    def _get_policy_detail(rid: str) -> Dict[str, Any]:
        # essaie d'abord les getters "propres"
        for name, fn in getters:
            try:
                # signatures les plus probables: (pool, node, resource, id)
                return fn(pool_uuid, node_id, self.RESOURCE, rid) or {}
            except TypeError:
                # certains clients attendent (pool, node, f"NormalizationPolicy/{id}")
                try:
                    return fn(pool_uuid, node_id, f"{self.RESOURCE}/{rid}") or {}
                except Exception:
                    continue
            except Exception:
                continue

        # fallback générique HTTP si dispo
        path = f"configapi/{pool_uuid}/{node_id}/{self.RESOURCE}/{rid}"
        for cand in ("request_json", "request"):
            fn = getattr(client, cand, None)
            if callable(fn):
                try:
                    # request(_method, _path) ou request_json(_method, _path)
                    return fn("GET", path) or {}
                except Exception:
                    pass

        for cand in ("_request_json", "_request"):
            fn = getattr(client, cand, None)
            if callable(fn):
                try:
                    resp = fn("GET", path)
                    try:
                        return resp.json()  # si c’est un objet Response
                    except Exception:
                        return resp or {}
                except Exception:
                    pass

        log.warning(
            "No working getter for policy id=%s on node %s; detail unavailable",
            rid, node.name
        )
        return {}

    for it in (items if isinstance(items, list) else []):
        nm = str(it.get("name", "")).strip()
        rid = it.get("id")
        if not nm or not rid:
            continue

        detail = {}
        try:
            detail = _get_policy_detail(rid)
        except Exception as e:
            log.warning(
                "Failed to get details for NormalizationPolicy %s on %s: %s",
                nm, node.name, e
            )
            detail = {}

        # Normalisation: on tente de peupler compiled_normalizer depuis le détail
        compiled_field = (
            detail.get("compiled_normalizer")
            or detail.get("compiled_normalizers")
            or detail.get("compiled")
            or it.get("compiled_normalizer")  # au cas où la liste l'aurait fourni
        )

        if compiled_field is not None:
            it["compiled_normalizer"] = compiled_field  # laisser canon_* unifier en []
        # Idem: certaines versions renvoient les packages sous forme d’IDs
        # On laisse canon_existing convertir IDs -> noms via self._pkg_id_to_name

        it["_node_id"] = node_id
        it["_pool_uuid"] = pool_uuid
        out[nm] = it

    log.info("Found %d existing NormalizationPolicy on node %s", len(out), node.name)
    return out
