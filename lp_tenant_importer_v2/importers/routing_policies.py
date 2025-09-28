# lp_tenant_importer_v2/importers/routing_policies.py
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter, NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import require_columns

log = logging.getLogger(__name__)

# ------------------------- Low-level helpers ------------------------- #
_EMPTY_SENTINELS = {"", "nan", "none", "null", "-"}


def _is_blank(x: Any) -> bool:
    """Return True if value is considered empty per project conventions."""
    if x is None:
        return True
    if isinstance(x, float) and pd.isna(x):
        return True
    s = str(x).strip()
    return s == "" or s.lower() in _EMPTY_SENTINELS


def _norm_str(x: Any) -> str:
    """Trim string and normalize empties to empty string."""
    if _is_blank(x):
        return ""
    return str(x).strip()


def _node_tag(node: NodeRef) -> str:
    name = getattr(node, "name", None) or getattr(node, "id", "")
    nid = getattr(node, "id", "")
    return f"{name}|{nid}"


# ------------------------ Importer definition ------------------------ #
class RoutingPoliciesImporter(BaseImporter):
    """
    Routing Policies importer (V2) implementing the final spec:

    - Sheet: first existing among 'RoutingPolicy' or 'RP'.
    - Required columns (case-insensitive): cleaned_policy_name, catch_all,
      rule_type, key, value, repo, drop. 'active' column in XLSX is ignored.
    - Optional 'Repo' sheet: original_repo_name -> cleaned_repo_name,
      mapping applied ONLY when the input value is non-empty.

    Line typing:
      * Type 1 ("catch-all only"): ALL rule columns empty
        (rule_type, key, value, repo, drop) -> no rule created for that row.
      * Type 2 ("catch-all + rules"): if ANY of (rule_type, key, value, drop)
        is present, row defines a rule. Valid IFF rule_type, key, value, drop
        are all non-empty. 'repo' is optional.
        - 'drop' is REQUIRED but has NO semantics in importer logic; it is
          passed through to the API as-is.

    API payload (create/update):
      {
        "policy_name": <name>,
        "active": true,                 # XLSX 'active' is ignored
        "catch_all": <mapped_or_empty>,
        "routing_criteria": [ ... in Excel order ... ]
      }

    SKIP decision (per policy):
      repos_to_check = [catch_all if non-empty] + [each rule.repo if non-empty]
      missing = repos_to_check - repos_available_on_node
      if missing != ∅ : SKIPPED (warning + explicit 'error' message).
    """

    # ---- BaseImporter contract ----
    resource_name = "routing_policies"
    sheet_names = ("RoutingPolicy", "RP")
    required_columns = (
        "cleaned_policy_name",
        "catch_all",
        "rule_type",
        "key",
        "value",
        "repo",
        "drop",  # required to validate a rule; no semantics in importer
    )
    # Diff keys (canonical form aligns with API fields)
    compare_keys = ("name", "catch_all", "routing_criteria")

    # Director API resource name
    RESOURCE = "RoutingPolicies"

    def __init__(self) -> None:
        super().__init__()
        self._active_sheet: Optional[str] = None
        self._repo_map: Dict[str, str] = {}
        self._repos_cache: Dict[str, set] = {}  # node.id -> set(repo names)
        self._first_catch_all: Dict[str, str] = {}  # warn if intra-policy change

    # ------------------------------ Validate ------------------------------ #
    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        sheet = self._select_sheet(sheets)
        self._active_sheet = sheet
        df = sheets[sheet]

        # Required columns (with optional context)
        try:
            require_columns(df, self.required_columns, context=f"sheet '{sheet}'")
        except TypeError:
            require_columns(df, self.required_columns)

        # Repo mapping if present
        self._repo_map = self._build_repo_name_map(sheets)
        if self._repo_map:
            log.info("repo-map: loaded %d entries from sheet 'Repo'", len(self._repo_map))

        log.info("routing_policies: using sheet '%s'", sheet)
        log.debug("routing_policies: columns=%s rows=%d", list(df.columns), len(df.index))

    # --------------------------- Parse desired ---------------------------- #
    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        """
        Yield desired policies as dicts:
          { "name": str, "catch_all": str, "rules": List[Dict[str,Any]] }
        (NB: we keep 'rules' internally; API conversion to 'routing_criteria'
         happens in build_payload_* and canon_desired)
        """
        sheet = self._active_sheet or self._select_sheet(sheets)
        df: pd.DataFrame = sheets[sheet]
        cols = {c.lower(): c for c in df.columns}

        def col(name: str) -> str:
            return cols.get(name.lower(), name)

        policies: Dict[str, Dict[str, Any]] = {}
        invalid_rows: List[Tuple[str, int, str]] = []

        for idx, row in df.iterrows():
            policy_name = _norm_str(row.get(col("cleaned_policy_name")))
            if not policy_name:
                continue

            # Init policy (first occurrence)
            if policy_name not in policies:
                catch_all_raw = _norm_str(row.get(col("catch_all")))
                catch_all_mapped = self._map_repo_if_non_empty(catch_all_raw)
                policies[policy_name] = {
                    "name": policy_name,
                    "catch_all": catch_all_mapped,
                    "rules": [],
                }
                self._first_catch_all[policy_name] = catch_all_mapped
            else:
                # Warn if catch_all changes (first wins)
                prev = self._first_catch_all.get(policy_name, "")
                now = self._map_repo_if_non_empty(_norm_str(row.get(col("catch_all"))))
                if now and now != prev:
                    log.warning(
                        "catch_all changed for policy=%s; first wins (prev=%s, new=%s)",
                        policy_name, prev, now
                    )

            # Read rule fields
            rule_type = _norm_str(row.get(col("rule_type")))
            key = _norm_str(row.get(col("key")))
            value = _norm_str(row.get(col("value")))
            repo_raw = _norm_str(row.get(col("repo")))
            repo_mapped = self._map_repo_if_non_empty(repo_raw)
            drop_val = _norm_str(row.get(col("drop")))

            # Type 1: no rule line
            is_no_rule_line = (
                rule_type == "" and key == "" and value == "" and repo_raw == "" and drop_val == ""
            )
            if is_no_rule_line:
                continue

            # Type 2: defined line
            core_present = any(x != "" for x in (rule_type, key, value, drop_val))
            if not core_present:
                continue

            # Validation: 4 required fields (repo optional)
            if not all(x != "" for x in (rule_type, key, value, drop_val)):
                invalid_rows.append(
                    (policy_name, idx + 2, "require rule_type, key, value, drop (repo optional)")
                )
                continue

            # Build rule (preserve 'drop' as-is, no semantics here)
            rule: Dict[str, Any] = {
                "type": rule_type,
                "key": key,
                "value": value,
                "drop": drop_val,
            }
            if repo_mapped:
                rule["repo"] = repo_mapped

            policies[policy_name]["rules"].append(rule)

        # Warnings for invalid lines
        for pol, rowno, reason in invalid_rows:
            log.warning("invalid rule at row %d for policy=%s: %s", rowno, pol, reason)

        # Deterministic yield (rules keep Excel order)
        for name in sorted(policies.keys()):
            desired = policies[name]
            log.debug(
                "parsed policy=%s catch_all=%s rules=%d",
                name, desired.get("catch_all", ""), len(desired.get("rules") or [])
            )
            yield desired

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row["name"]

    # ------------------------ Canonical for diff ------------------------ #
    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """Canonical shape used by the diff engine (aligned with API fields)."""
        return {
            "name": desired_row.get("name", ""),
            "catch_all": desired_row.get("catch_all") or "",
            "routing_criteria": [self._canon_rule(r) for r in (desired_row.get("rules") or [])],
        }

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Canonicalize an existing object from Director API."""
        if not existing_obj:
            return None

        # API may respond with fields at root or under 'policy'
        catch = (
            existing_obj.get("catch_all")
            or (existing_obj.get("policy") or {}).get("catch_all")
            or ""
        )
        criteria = (
            existing_obj.get("routing_criteria")
            or (existing_obj.get("policy") or {}).get("routing_criteria")
            or existing_obj.get("rules")
            or (existing_obj.get("policy") or {}).get("rules")
            or []
        )

        return {
            "name": _norm_str(existing_obj.get("name") or existing_obj.get("policy_name")),
            "catch_all": _norm_str(catch),
            "routing_criteria": [self._canon_rule_from_api(rr) for rr in criteria],
        }

    # ------------------------- Director API I/O ------------------------- #
    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Return {policy_name -> existing_obj} for the node.
        Also fill the repos cache for SKIP decisions.
        """
        node_t = _node_tag(node)
        log.info("fetch_existing: start [node=%s]", node_t)

        # Preload repo names present on this node (for SKIP decision)
        self._repos_cache[node.id] = self._list_repos(client, pool_uuid, node)
        log.debug("list_repos: %d repos present [node=%s]", len(self._repos_cache[node.id]), node_t)

        data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []
        if isinstance(data, dict):
            items_any = (
                data.get("data")
                or data.get("items")
                or data.get("results")
                or data.get("policies")
                or []
            )
            items = [x for x in items_any if isinstance(x, dict)]
        elif isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        else:
            items = []

        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            name = _norm_str(it.get("name") or it.get("policy_name") or "")
            if name:
                out[name] = it

        log.info("fetch_existing: found %d policies [node=%s]", len(out), node_t)
        log.debug("fetch_existing: names=%s [node=%s]", sorted(out.keys()), node_t)
        return out

    # --------------------------- Build payloads ------------------------- #
    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """API payload: catch_all & routing_criteria at root level (V1-compatible)."""
        payload = {
            "policy_name": desired_row["name"],
            "active": True,  # XLSX 'active' intentionally ignored
            "catch_all": desired_row.get("catch_all") or "",
            "routing_criteria": [self._rule_to_api(r) for r in (desired_row.get("rules") or [])],
        }
        log.debug("apply: payload.create=%s", payload)
        return payload

    def build_payload_update(
        self,
        desired_row: Dict[str, Any],
        existing_obj: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "policy_name": desired_row["name"],
            "active": True,
            "catch_all": desired_row.get("catch_all") or "",
            "routing_criteria": [self._rule_to_api(r) for r in (desired_row.get("rules") or [])],
        }
        log.debug("apply: payload.update=%s", payload)
        return payload

    # ----------------------------- Apply ops ---------------------------- #
    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Apply the decision (CREATE/UPDATE/NOOP). Before writing, enforce SKIP
        if required repos are missing on the node.
        """
        node_t = _node_tag(node)
        desired: Dict[str, Any] = dict(decision.desired or {})
        pol_name = desired.get("name") or "(unnamed)"

        log.info("apply: op=%s policy=%s [node=%s]", getattr(decision, "op", "?"), pol_name, node_t)

        # Repos to verify: catch_all + explicit rule repos
        missing = self._missing_repos(node.id, self._repos_to_check(desired))
        if missing:
            miss_sorted = sorted(missing)
            reason = f"missing repos: {', '.join(miss_sorted)}"
            log.warning("apply: skipping policy=%s due to %s [node=%s]", pol_name, reason, node_t)
            # return structured result + human-readable error for table
            return {
                "status": "Skipped",
                "result": {"missing_repos": miss_sorted},
                "error": reason,
            }

        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                res = client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
                return self._monitor_result(client, node, res, "create")

            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id})
                res = client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)
                return self._monitor_result(client, node, res, "update")

            log.info("apply: NOOP policy=%s [node=%s]", pol_name, node_t)
            return {"status": "Success"}

        except Exception:  # pragma: no cover (defensive)
            log.exception("apply: API call failed for policy=%s [node=%s]", pol_name, node_t)
            raise

    # ----------------------------- Internals ---------------------------- #
    def _select_sheet(self, sheets: Dict[str, pd.DataFrame]) -> str:
        for name in self.sheet_names:
            if name in sheets:
                if all(n in sheets for n in self.sheet_names) and name != self.sheet_names[0]:
                    log.warning("Both 'RoutingPolicy' and 'RP' sheets were found; using '%s'.", name)
                return name
        raise ValueError("Missing required sheets: RP or RoutingPolicy")

    def _build_repo_name_map(self, sheets: Dict[str, pd.DataFrame]) -> Dict[str, str]:
        """Build mapping {original_repo_name -> cleaned_repo_name} from optional 'Repo' sheet."""
        if "Repo" not in sheets:
            return {}
        df = sheets["Repo"]
        cols = {c.lower(): c for c in df.columns}
        src = cols.get("original_repo_name")
        dst = cols.get("cleaned_repo_name")
        if not src or not dst:
            return {}

        mapping: Dict[str, str] = {}
        for _, row in df.iterrows():
            k = _norm_str(row.get(src))
            v = _norm_str(row.get(dst))
            if k and v:
                mapping[k] = v
        return mapping

    def _map_repo_if_non_empty(self, repo_name: str) -> str:
        """Apply repo mapping only when the input name is non-empty; otherwise return ''."""
        nm = _norm_str(repo_name)
        if not nm:
            return ""
        return self._repo_map.get(nm, nm)

    def _list_repos(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> set:
        """Return the set of repo names available on a node (for SKIP decision)."""
        names: set = set()
        try:
            data = client.list_resource(pool_uuid, node.id, "Repos") or {}
            items = (data.get("data") if isinstance(data, dict) else data) or []
            for it in items:
                nm = _norm_str(it.get("name") or it.get("repo_name"))
                if nm:
                    names.add(nm)
        except Exception as exc:  # pragma: no cover (defensive)
            log.error("list_repos: failed [node=%s] err=%s", _node_tag(node), exc)
        return names

    @staticmethod
    def _canon_rule(r: Dict[str, Any]) -> Dict[str, Any]:
        """Canonicalize a desired rule (including 'drop' as-is)."""
        out = {
            "type": _norm_str(r.get("type")),
            "key": _norm_str(r.get("key")),
            "value": _norm_str(r.get("value")),
            "drop": _norm_str(r.get("drop")),
        }
        repo = _norm_str(r.get("repo"))
        if repo:
            out["repo"] = repo
        return out

    @staticmethod
    def _canon_rule_from_api(rr: Dict[str, Any]) -> Dict[str, Any]:
        """Canonicalize an existing rule from the API."""
        out = {
            "type": _norm_str(rr.get("type")),
            "key": _norm_str(rr.get("key")),
            "value": _norm_str(rr.get("value")),
            "drop": _norm_str(rr.get("drop")),
        }
        repo = _norm_str(rr.get("repo"))
        if repo:
            out["repo"] = repo
        return out

    @staticmethod
    def _rule_to_api(r: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a desired rule to the API shape.
        'drop' is required (no importer semantics); 'repo' optional.
        """
        out = {
            "type": _norm_str(r.get("type")) or "KeyPresent",
            "key": _norm_str(r.get("key")),
            "drop": _norm_str(r.get("drop")),   # literal value from Excel
        }
        val = _norm_str(r.get("value"))
        if val:
            out["value"] = val
        repo = _norm_str(r.get("repo"))
        if repo:
            out["repo"] = repo
        return out

    def _repos_to_check(self, desired: Dict[str, Any]) -> List[str]:
        """
        Repos to verify: catch_all (if non-empty) + all non-empty rule.repo values.
        """
        repos: List[str] = []
        catch = _norm_str(desired.get("catch_all"))
        if catch:
            repos.append(catch)
        for rr in (desired.get("rules") or []):
            repo = _norm_str(rr.get("repo"))
            if repo:
                repos.append(repo)

        # Preserve order but unique
        out, seen = [], set()
        for r in repos:
            if r not in seen:
                seen.add(r)
                out.append(r)
        return out

    def _missing_repos(self, node_id: str, required: Iterable[str]) -> set:
        have = self._repos_cache.get(node_id) or set()
        need = {r for r in required if r}
        return need - have

    @staticmethod
    def _monitor_result(
        client: DirectorClient,  # noqa: ARG002 (kept for parity with Repos importer)
        node: NodeRef,           # noqa: ARG002
        res: Dict[str, Any],
        action: str,             # noqa: ARG002
    ) -> Dict[str, Any]:
        """Normalize async monitor result (kept minimal and consistent)."""
        status = "Success"
        mon_ok = None
        branch = None
        if isinstance(res, dict):
            branch = res.get("monitor_branch")
            mon_ok = res.get("monitor_ok")
            status = res.get("status") or status
        return {"status": status, "monitor_ok": mon_ok, "monitor_branch": branch}
