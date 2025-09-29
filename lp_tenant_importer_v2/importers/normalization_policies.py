# lp_tenant_importer_v2/importers/normalization_policies.py
from __future__ import annotations

"""
Normalization Policies importer (v2).

Goal
-----
Keep the user-facing behavior identical to v1 while plugging into the v2
common trunk (BaseImporter + DirectorClient). This module:

- Parses the **NormalizationPolicy** sheet from the XLSX:
  * required columns: policy_name, normalization_packages, compiled_normalizer
  * multi-value cells may be separated by "|" or ","
  * empties like "", "nan", "none", "-" are treated as empty

- Resolves dependencies against the node:
  * maps **normalization package names → package IDs** via
    GET configapi/{pool}/{node}/NormalizationPackage
  * validates **compiled normalizer names** via
    GET configapi/{pool}/{node}/NormalizationPackage/CompiledNormalizers

- Reads existing policies on the node:
  GET configapi/{pool}/{node}/NormalizationPolicy
  and (best-effort) details per policy:
  GET configapi/{pool}/{node}/NormalizationPolicy/{id}
  so that `compiled_normalizer` is available for comparison.

- Uses the diff engine to decide NOOP / CREATE / UPDATE.
  Compare keys are:
    - "normalization_packages"  (list of *names*)
    - "compiled_normalizer"     (list of *names*)

- Applies changes with the generic DirectorClient helpers:
  create_resource / update_resource on resource "NormalizationPolicy".

Payload shape (POST/PUT data)
-----------------------------
{
  "name": "<policy name>",
  "normalization_packages": ["<pkg-id-1>", "<pkg-id-2>", ...],
  "compiled_normalizer": ["<compiled-1>", "<compiled-2>", ...]
}

Notes
-----
* We compare **by names** (packages & compiled). For payloads we convert
  package names to **IDs** (compiled stays as names).
* If both lists in a row are empty, we SKIP that row with a warning.
* If any referenced package/compiled does not exist on the node, we SKIP.
"""

import logging
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import pandas as pd

from .base import BaseImporter, NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import require_columns

log = logging.getLogger(__name__)


# ------------------------- helpers (pure functions) ------------------------- #

_EMPTY_SENTINELS = {"", "nan", "none", "null", "-", "[]"}


def _is_blank(x: Any) -> bool:
    if x is None:
        return True
    if isinstance(x, float) and pd.isna(x):
        return True
    s = str(x).strip()
    return s == "" or s.lower() in _EMPTY_SENTINELS


def _norm_str(x: Any) -> str:
    return "" if _is_blank(x) else str(x).strip()


def _split_multi(cell: Any) -> List[str]:
    """
    Split a multi-value Excel cell by '|' or ','; normalize and de-duplicate
    while preserving order.
    """
    s = _norm_str(cell)
    if not s:
        return []
    # Accept both separators in one pass by replacing '|' with ','
    s = s.replace("|", ",")
    out: List[str] = []
    seen: Set[str] = set()
    for part in (p.strip() for p in s.split(",") if p.strip()):
        if part not in seen:
            out.append(part)
            seen.add(part)
    return out


def _node_tag(node: NodeRef) -> str:
    name = getattr(node, "name", None) or getattr(node, "id", "")
    return f"{name}|{node.id}"


# ------------------------------ importer class ----------------------------- #


class NormalizationPoliciesImporter(BaseImporter):
    """Importer for Normalization Policies (NP)."""

    # BaseImporter contract
    resource_name = "normalization_policies"
    sheet_names = ("NormalizationPolicy",)
    required_columns = ("policy_name", "normalization_packages", "compiled_normalizer")
    # Compare by NAMES (canonical); 'name' is implicit key but does not drive UPDATE
    compare_keys = ("normalization_packages", "compiled_normalizer")

    # Director API resource names
    RESOURCE = "NormalizationPolicy"
    PACKAGES_RESOURCE = "NormalizationPackage"
    COMPILED_SUBPATH = "CompiledNormalizers"

    # Caches (keyed by node.id)
    def __init__(self) -> None:
        super().__init__()
        self._pkg_name_to_id: Dict[str, Dict[str, str]] = {}  # node.id -> {name: id}
        self._pkg_id_to_name: Dict[str, Dict[str, str]] = {}  # node.id -> {id: name}
        self._compiled_names: Dict[str, Set[str]] = {}  # node.id -> set(names)

    # ------------------------------ validation ------------------------------ #

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        # Required sheet presence handled by BaseImporter in v2 trunk, but we keep explicit
        # column check here to provide consistent behavior if overridden.
        sheet = self.sheet_names[0]
        try:
            require_columns(sheets[sheet], self.required_columns, context=f"sheet '{sheet}'")  # type: ignore[arg-type]
        except TypeError:
            # validators.require_columns signature has no 'context' in the current trunk
            require_columns(sheets[sheet], self.required_columns)
        log.info("normalization_policies: using sheet '%s'", sheet)
        log.debug("normalization_policies: columns=%s rows=%d", list(sheets[sheet].columns), len(sheets[sheet].index))

    # ------------------------------- desired ------------------------------- #

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        """
        Yield desired rows with keys:
          - name: str
          - normalization_packages: List[str]  (package names)
          - compiled_normalizer: List[str]     (compiled names)
          - skip_empty: bool (internal hint for apply/skip)
        """
        df: pd.DataFrame = sheets[self.sheet_names[0]]
        cols = {c.lower(): c for c in df.columns}

        def col(name: str) -> str:
            return cols.get(name.lower(), name)

        for _, row in df.iterrows():
            name = _norm_str(row.get(col("policy_name")))
            if not name:
                # Silent skip: empty name is simply ignored (like v1 behavior)
                continue

            pkgs = _split_multi(row.get(col("normalization_packages")))
            compiled = _split_multi(row.get(col("compiled_normalizer")))

            # In the canonical comparison we sort later, but retain the original
            # order for payload convenience if needed.
            desired = {
                "name": name,
                "normalization_packages": pkgs,
                "compiled_normalizer": compiled,
                "skip_empty": (len(pkgs) == 0 and len(compiled) == 0),
            }

            log.debug(
                "parsed NP name=%s packages=%d compiled=%d",
                name,
                len(pkgs),
                len(compiled),
            )
            yield desired

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row["name"]

    # -------------------------- canonical for diff -------------------------- #

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """Compare by **names** (sorted) for stable diff behavior."""
        return {
            "name": desired_row.get("name", ""),
            "normalization_packages": sorted(str(x) for x in (desired_row.get("normalization_packages") or [])),
            "compiled_normalizer": sorted(str(x) for x in (desired_row.get("compiled_normalizer") or [])),
        }

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Canonicalize an existing object:
          - Map package **IDs → names** using the preloaded cache
          - Normalize compiled_normalizer whether list or comma-separated string
        """
        if not existing_obj:
            return None

        node_id = existing_obj.get("_node_id_for_cache") or ""  # injected in fetch_existing
        id2name = self._pkg_id_to_name.get(node_id, {})

        # Packages as names
        ids_raw = existing_obj.get("normalization_packages") or []
        if isinstance(ids_raw, list):
            pkg_names = [id2name.get(str(i), str(i)) for i in ids_raw if _norm_str(i)]
        else:
            # Tolerate odd shapes; treat as empty if unexpected
            pkg_names = []

        # Compiled normalizers may be list or csv string in API responses
        comp_raw = existing_obj.get("compiled_normalizer") or []
        if isinstance(comp_raw, list):
            comp_names = [str(x).strip() for x in comp_raw if _norm_str(x)]
        elif isinstance(comp_raw, str):
            comp_names = [x.strip() for x in comp_raw.split(",") if x.strip()]
        else:
            comp_names = []

        return {
            "name": _norm_str(existing_obj.get("name")),
            "normalization_packages": sorted(pkg_names),
            "compiled_normalizer": sorted(comp_names),
        }

    # ----------------------------- read existing ---------------------------- #

    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Preload dependencies and return {policy_name -> existing_obj}.

        Also inject `_node_id_for_cache` into each existing obj so `canon_existing`
        can translate package IDs -> names using the correct node cache.
        """
        node_t = _node_tag(node)
        log.info("fetch_existing: start [node=%s]", node_t)

        # 1) Load packages (name <-> id)
        pkg_name_to_id, pkg_id_to_name = self._list_packages(client, pool_uuid, node)
        self._pkg_name_to_id[node.id] = pkg_name_to_id
        self._pkg_id_to_name[node.id] = pkg_id_to_name
        log.debug(
            "packages: %d (names) / %d (ids) cached [node=%s]",
            len(pkg_name_to_id),
            len(pkg_id_to_name),
            node_t,
        )

        # 2) Load compiled normalizers (names)
        compiled_names = self._list_compiled_normalizers(client, pool_uuid, node)
        self._compiled_names[node.id] = compiled_names
        log.debug("compiled_normalizers: %d cached [node=%s]", len(compiled_names), node_t)

        # 3) List policies
        data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []
        if isinstance(data, dict):
            items_any = data.get("data") or data.get("items") or data.get("results") or []
            items = [x for x in items_any if isinstance(x, dict)]
        elif isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        else:
            items = []

        # 4) Best-effort enrich with details (compiled may be missing in list view)
        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            name = _norm_str(it.get("name"))
            if not name:
                continue
            # Inject for canon_existing()
            it["_node_id_for_cache"] = node.id

            pol_id = _norm_str(it.get("id"))
            if pol_id:
                try:
                    detail = client.get_json(
                        client.configapi(pool_uuid, node.id, f"{self.RESOURCE}/{pol_id}")
                    ) or {}
                    # Merge fields if present under typical shapes
                    merged = dict(it)
                    # Common places to look for fields
                    for src in (detail, detail.get("data") or {}, detail.get("policy") or {}):
                        if isinstance(src, dict):
                            if "compiled_normalizer" in src and src["compiled_normalizer"] is not None:
                                merged["compiled_normalizer"] = src["compiled_normalizer"]
                            if "normalization_packages" in src and src["normalization_packages"] is not None:
                                merged["normalization_packages"] = src["normalization_packages"]
                    it = merged
                except Exception:
                    # Non-fatal — we keep the list object as-is
                    log.debug("fetch_existing: detail read failed for id=%s [node=%s]", pol_id, node_t)

            out[name] = it

        log.info("fetch_existing: found %d normalization policies [node=%s]", len(out), node_t)
        return out

    # ------------------------------- payloads ------------------------------- #

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build POST payload from desired (names → IDs for packages).
        """
        name = desired_row["name"]
        pkg_ids, _ = self._map_pkg_names_to_ids(desired_row, desired_row.get("_node_id") or "")
        payload = {
            "name": name,
            "normalization_packages": pkg_ids,
            "compiled_normalizer": list(desired_row.get("compiled_normalizer") or []),
        }
        log.debug("payload.create name=%s -> %s", name, payload)
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build PUT payload. Same shape as POST (server owns the ID in the path).
        """
        name = desired_row["name"]
        pkg_ids, _ = self._map_pkg_names_to_ids(desired_row, desired_row.get("_node_id") or "")
        payload = {
            "name": name,
            "normalization_packages": pkg_ids,
            "compiled_normalizer": list(desired_row.get("compiled_normalizer") or []),
        }
        log.debug("payload.update name=%s -> %s", name, payload)
        return payload

    # -------------------------------- apply -------------------------------- #

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Execute CREATE/UPDATE, enforcing SKIP on validation failures:
          - both fields empty
          - missing packages or compiled names on node
        """
        node_t = _node_tag(node)
        desired = dict(decision.desired or {})
        desired["_node_id"] = node.id  # for payload builders

        pol_name = desired.get("name") or "(unnamed)"
        log.info("apply: op=%s policy=%s [node=%s]", getattr(decision, "op", "?"), pol_name, node_t)

        # 0) skip if both empty
        if desired.get("skip_empty"):
            reason = "both 'normalization_packages' and 'compiled_normalizer' are empty"
            log.warning("apply: SKIP policy=%s: %s [node=%s]", pol_name, reason, node_t)
            return {"status": "Skipped", "error": reason}

        # 1) verify dependencies on node
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

        # 2) perform API call
        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                res = client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
                return res
            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id})
                res = client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)
                return res

            log.info("apply: NOOP policy=%s [node=%s]", pol_name, node_t)
            return {"status": "Success"}
        except Exception:
            log.exception("apply: API call failed for policy=%s [node=%s]", pol_name, node_t)
            raise

    # ------------------------------- internals ------------------------------ #

    def _list_packages(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """
        Return ({name -> id}, {id -> name}) for NormalizationPackage on a node.
        Tolerates both list and dict shapes from the API.
        """
        data = client.list_resource(pool_uuid, node.id, self.PACKAGES_RESOURCE) or []
        if isinstance(data, dict):
            items_any = data.get("data") or data.get("items") or data.get("results") or []
            items = [x for x in items_any if isinstance(x, dict)]
        elif isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        else:
            items = []

        name_to_id: Dict[str, str] = {}
        id_to_name: Dict[str, str] = {}
        for it in items:
            nm = _norm_str(it.get("name"))
            pid = _norm_str(it.get("id"))
            if nm and pid:
                name_to_id[nm] = pid
                id_to_name[pid] = nm
        return name_to_id, id_to_name

    def _list_compiled_normalizers(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Set[str]:
        """
        Return {compiled normalizer names} present on the node.
        Accepts list of dicts or list of strings.
        """
        data = client.list_subresource(pool_uuid, node.id, self.PACKAGES_RESOURCE, self.COMPILED_SUBPATH) or []
        names: Set[str] = set()
        if isinstance(data, list):
            for it in data:
                if isinstance(it, dict):
                    nm = _norm_str(it.get("name"))
                    if nm:
                        names.add(nm)
                else:
                    nm = _norm_str(it)
                    if nm:
                        names.add(nm)
        elif isinstance(data, dict):
            # Some APIs return {"data": [...]}
            for it in (data.get("data") or data.get("items") or data.get("results") or []):
                if isinstance(it, dict):
                    nm = _norm_str(it.get("name"))
                    if nm:
                        names.add(nm)
        return names

    def _map_pkg_names_to_ids(self, desired_row: Dict[str, Any], node_id: str) -> Tuple[List[str], List[str]]:
        """
        Map desired package names -> IDs using cache.
        Returns (ids, missing_names).
        """
        name_to_id = self._pkg_name_to_id.get(node_id, {})
        ids: List[str] = []
        missing: List[str] = []
        for nm in (desired_row.get("normalization_packages") or []):
            key = _norm_str(nm)
            if not key:
                continue
            pid = name_to_id.get(key)
            if pid:
                ids.append(pid)
            else:
                missing.append(key)
        return ids, missing

    def _verify_dependencies(self, node_id: str, desired: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
        """
        Return (missing_packages_by_name, missing_compiled_by_name).
        """
        missing_pkgs: Set[str] = set()
        missing_comp: Set[str] = set()

        # Packages
        pkg_name_to_id = self._pkg_name_to_id.get(node_id, {})
        for nm in (desired.get("normalization_packages") or []):
            n = _norm_str(nm)
            if n and n not in pkg_name_to_id:
                missing_pkgs.add(n)

        # Compiled
        compiled_available = self._compiled_names.get(node_id, set())
        for nm in (desired.get("compiled_normalizer") or []):
            n = _norm_str(nm)
            if n and n not in compiled_available:
                missing_comp.add(n)

        return missing_pkgs, missing_comp
