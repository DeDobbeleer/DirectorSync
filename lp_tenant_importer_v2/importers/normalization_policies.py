# lp_tenant_importer_v2/importers/normalization_policies.py
"""
Normalization Policies importer (DirectorSync v2).

Reads sheet "NormalizationPolicy" from the XLSX input and creates/updates
Normalization Policies across target nodes.

API alignment (Director 2.7.0):
- POST  configapi/{pool}/{node}/NormalizationPolicy               (Create)
- PUT   configapi/{pool}/{node}/NormalizationPolicy/{id}           (Edit)
  Payload keys (inside {"data": {...}}):
    - name: string (CREATE only, mandatory)
    - norm_packages: CSV string of NormalizationPackage IDs (optional)
    - compiled_normalizer: CSV string of compiled normalizer names (optional)
- GET   configapi/{pool}/{node}/NormalizationPolicy                (List)
  Returns objects including:
    - id, name, normalization_packages [list of IDs], selected_signatures [...]
- GET   configapi/{pool}/{node}/NormalizationPackage               (List packages)
- GET   configapi/{pool}/{node}/NormalizationPackage/CompiledNormalizers
        (List compiled normalizers)
Docs: NormalizationPolicy (Create/Edit/List/Get) and
      NormalizationPackage (ListCompiledNormalizers).  # see citations in the PR/commit message
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

import logging
import math
import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.diff_engine import Decision, decide
from ..utils.validators import require_columns, ValidationError
from ..utils.resolvers import ResolverCache

log = logging.getLogger(__name__)


def _is_blank(val: Any) -> bool:
    # Treat NaN/None/empty string as blank.
    if val is None:
        return True
    if isinstance(val, float) and math.isnan(val):
        return True
    return str(val).strip() == ""


def _split_multi(val: Any, sep: str = "|") -> List[str]:
    """Split a cell value by separator, trimming and deduplicating while preserving order."""
    if _is_blank(val):
        return []
    seen = set()
    out: List[str] = []
    for part in str(val).split(sep):
        p = part.strip()
        if not p:
            continue
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


@dataclass(frozen=True)
class DesiredNP:
    name: str
    package_names: List[str]
    compiled_names: List[str]


class NormalizationPoliciesImporter:
    """
    V2 importer implementing the BaseImporter hook interface.

    Sheets & columns:
      - Sheet: "NormalizationPolicy" (exact)
      - Required columns: "policy_name", "normalization_packages", "compiled_normalizer"

    Diff model:
      - Compare only on ("name", "normalization_packages") using package **IDs**
        (the compiled normalizer list is *write-only* from API perspective and
        is NOT returned by List/Get; we still send it on create/update).
    """

    resource_name: str = "normalization_policies"
    sheet_names: Tuple[str, ...] = ("NormalizationPolicy",)
    required_columns: Tuple[str, ...] = (
        "policy_name",
        "normalization_packages",
        "compiled_normalizer",
    )
    compare_keys: Tuple[str, ...] = ("name", "normalization_packages")

    def __init__(self) -> None:
        self._cache = ResolverCache()

    # ---------- pipeline glue ----------

    def load_xlsx(self, xlsx_path: str) -> Dict[str, pd.DataFrame]:
        from pathlib import Path

        p = Path(xlsx_path)
        if not p.is_file():
            raise FileNotFoundError(xlsx_path)

        try:
            xl = pd.read_excel(xlsx_path, sheet_name=None, engine="openpyxl")
        except Exception as exc:
            raise RuntimeError(f"Failed to read {xlsx_path}: {exc}") from exc
        return xl

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:
        # Strict sheet and column validation.
        sheet = self.sheet_names[0]
        if sheet not in sheets:
            raise ValidationError(f"Missing required sheet: {sheet}")
        require_columns(sheets[sheet], self.required_columns, context=sheet)

    # ---------- hooks expected by BaseImporter ----------

    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """Return {name -> existing_obj} for the node; also warm caches."""
        node_id = node.id

        # 1) Existing Normalization Policies
        path_np = client.configapi(pool_uuid, node_id, "NormalizationPolicy")
        data = client.get_json(path_np)
        if not isinstance(data, list):
            log.warning("Unexpected NP List payload on %s: %r", node.name, data)
            data = []
        existing_map = {str(obj.get("name", "")).strip(): obj for obj in data if obj.get("name")}

        # 2) Cache packages (name -> id)
        pkg_key = "NormalizationPackage:list"
        cached = self._cache.get(pool_uuid, node_id, pkg_key)
        if cached is None:
            path_pkg = client.configapi(pool_uuid, node_id, "NormalizationPackage")
            pkg_data = client.get_json(path_pkg)
            packages = {}
            if isinstance(pkg_data, list):
                for pkg in pkg_data:
                    pid = pkg.get("id")
                    pname = str(pkg.get("name", "")).strip()
                    if pid and pname:
                        packages[pname] = pid
            self._cache.set(pool_uuid, node_id, pkg_key, packages)
            log.debug("Cached %d packages for %s", len(packages), node.name)

        # 3) Cache compiled normalizers (set of names) — optional validation
        cn_key = "NormalizationPackage:compiled"
        cached_cn = self._cache.get(pool_uuid, node_id, cn_key)
        if cached_cn is None:
            path_cn = client.configapi(
                pool_uuid, node_id, "NormalizationPackage/CompiledNormalizers"
            )
            cn_data = client.get_json(path_cn)
            compiled = set()
            if isinstance(cn_data, list):
                for item in cn_data:
                    nm = str(item.get("name", "")).strip()
                    if nm:
                        compiled.add(nm)
            self._cache.set(pool_uuid, node_id, cn_key, compiled)
            log.debug("Cached %d compiled normalizers for %s", len(compiled), node.name)

        return existing_map

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        """Yield raw desired rows (policy name + lists) as dicts consumed downstream."""
        sheet = self.sheet_names[0]
        df = sheets[sheet]

        for idx, row in df.iterrows():
            name = str(row.get("policy_name", "")).strip()
            if not name:
                log.warning("%s row %d: empty policy_name, skipping", sheet, idx + 2)
                continue

            package_names = _split_multi(row.get("normalization_packages"))
            compiled_names = _split_multi(row.get("compiled_normalizer"))

            # If both are empty, skip (UX parity with v1)
            if not package_names and not compiled_names:
                log.warning(
                    "%s row %d (%s): both fields empty, skipping",
                    sheet,
                    idx + 2,
                    name,
                )
                # We still yield a sentinel desired row with a marker for reporting NOOP.
                # The diff step will see no existing vs desired and plan a CREATE,
                # but apply() will detect empty payload and turn it into SKIP.
                yield {"_skip": True, "name": name}
                continue

            yield {
                "name": name,
                "package_names": package_names,
                "compiled_names": compiled_names,
            }

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row.get("name", "")

    def _packages_name_to_ids(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef, names: List[str]
    ) -> Tuple[List[str], List[str]]:
        """Convert package names to IDs using per-node cache. Returns (ids, missing_names)."""
        packages = self._cache.get(pool_uuid, node.id, "NormalizationPackage:list") or {}
        ids: List[str] = []
        missing: List[str] = []
        for n in names:
            pid = packages.get(n)
            if pid:
                ids.append(pid)
            else:
                missing.append(n)
        return ids, missing

    def _validate_compiled(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef, names: List[str]
    ) -> List[str]:
        """Return the list of invalid compiled normalizer names (if any)."""
        compiled = self._cache.get(pool_uuid, node.id, "NormalizationPackage:compiled") or set()
        return [n for n in names if n not in compiled]

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comparable desired subset:
        - name
        - normalization_packages (IDs, sorted for stable comparison)
        NOTE: compiled_normalizer is excluded from comparison as API does not return it
        in List/Get responses (treated as write-only parameter).
        """
        # In BaseImporter, canon_desired is only used to diff; we keep it simple here.
        if desired_row.get("_skip"):
            # Special comparable subset for "skip" rows -> empty package list (no change).
            return {"name": desired_row["name"], "normalization_packages": []}
        # Placeholder; actual ID mapping requires node context, so we map in apply().
        # For diff stability across nodes, we don't include IDs here (IDs are per-node).
        return {"name": desired_row["name"], "normalization_packages": ["<resolve-per-node>"]}

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        if not existing_obj:
            return None  # Signal "not found"
        pk = existing_obj.get("normalization_packages") or []
        if isinstance(pk, list):
            return {"name": existing_obj.get("name"), "normalization_packages": sorted(pk)}
        # Be defensive
        return {"name": existing_obj.get("name"), "normalization_packages": []}

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        # Actual payload is crafted in apply() with node-specific ID resolution.
        return desired_row

    def build_payload_update(
        self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        return desired_row

    def _post_or_put(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        *,
        method: str,
        existing_id: str | None,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute POST/PUT and monitor job if possible. Returns dict with status & monitor flag."""
        node_id = node.id
        if method == "POST":
            path = client.configapi(pool_uuid, node_id, "NormalizationPolicy")
            resp = client.post_json(path, {"data": data})
        else:
            assert existing_id
            path = client.configapi(pool_uuid, node_id, f"NormalizationPolicy/{existing_id}")
            resp = client.put_json(path, {"data": data})

        # Try modern/legacy monitor outcomes:
        monitor_ok = None
        try:
            # Prefer monitoring via 'message' url (legacy documented in API guide)
            mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
            if mon_path and getattr(client.options, "monitor_enabled", True):
                ok, payload = client.monitor_job_url(mon_path)  # type: ignore[attr-defined]
                monitor_ok = bool(ok)
                if not ok:
                    log.error("Monitor failed for %s: %s", data.get("name"), payload)
        except Exception as exc:
            log.debug("Monitor not available/failed: %s", exc)

        status = str(resp.get("status", "")).capitalize() or "Success"
        return {"status": status, "monitor_ok": monitor_ok}

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision: Decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        """
        Create or update the resource for a node.
        Validation/ID resolution is done *here* because it depends on the node.
        """
        desired = decision.desired or {}
        name = desired.get("name")

        # "Skip" sentinel → do not call API
        if desired.get("_skip"):
            log.warning("Skipping NormalizationPolicy %s (both fields empty)", name)
            return {"status": "Skipped", "monitor_ok": None}

        package_names = desired.get("package_names", [])
        compiled_names = desired.get("compiled_names", [])

        # Resolve package IDs per-node
        pkg_ids, missing_pk = self._packages_name_to_ids(client, pool_uuid, node, package_names)
        if missing_pk:
            log.error(
                "Node %s: missing NormalizationPackage(s) for policy %s: %s",
                node.name,
                name,
                ", ".join(missing_pk),
            )
            return {"status": "Failed (missing packages)", "monitor_ok": None}

        # Optional validation of compiled normalizers (we only warn; API treats as free-form names)
        invalid_cn = self._validate_compiled(client, pool_uuid, node, compiled_names)
        if invalid_cn:
            log.warning(
                "Node %s: compiled normalizer(s) not installed for policy %s: %s",
                node.name,
                name,
                ", ".join(invalid_cn),
            )

        # Build API data according to docs: CSV strings for norm_packages/compiled_normalizer
        data: Dict[str, Any] = {}
        if not existing_id:
            data["name"] = name  # required on CREATE

        if pkg_ids:
            data["norm_packages"] = ",".join(pkg_ids)
        if compiled_names:
            data["compiled_normalizer"] = ",".join(compiled_names)

        # If both are absent and we are updating an existing policy, we can still send empty
        # (no changes); however, for CREATE this would be a policy with no content. Guard it:
        if not existing_id and not pkg_ids and not compiled_names:
            log.error("Refusing to create empty NormalizationPolicy %s on node %s", name, node.name)
            return {"status": "Failed (empty payload)", "monitor_ok": None}

        method = "PUT" if existing_id else "POST"
        return self._post_or_put(
            client,
            pool_uuid,
            node,
            method=method,
            existing_id=existing_id,
            data=data,
        )
