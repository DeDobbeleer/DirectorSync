# lp_tenant_importer_v2/importers/routing_policies.py
"""
RoutingPolicies importer (v2).

Highlights
----------
- Reads routing policies from the "RoutingPolicy" sheet.
- Maps *source* repo names to *destination* repo names using the "Repo" sheet
  (columns: original_repo_name -> cleaned_repo_name).
- Skips creation/update when any referenced repo (catch_all or criteria) is
  missing on the target node.
- Caches existing Repos per node to avoid repeated GETs.
- Defensive handling of NaN/empty cells across the sheet.
- Logs at all levels with node context.

Expected sheets
---------------
- "RoutingPolicy":
    original_policy_name, cleaned_policy_name, active, catch_all,
    rule_type, key, value, repo, drop, policy_id  (policy_id optional)
- "Repo":
    original_repo_name, cleaned_repo_name
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.resolvers import ResolverCache
from ..utils.validators import require_columns, require_sheets

from .base import BaseImporter

LOG = logging.getLogger(__name__)


# --------- Helpers


def _is_blank(x: Any) -> bool:
    """True if x is None/NaN/empty/whitespace/'nan'/'none'/'-'."""
    if x is None:
        return True
    s = str(x).strip()
    if s == "":
        return True
    s_low = s.lower()
    return s_low in {"nan", "none", "-"}


def _norm_str(x: Any) -> Optional[str]:
    """Normalize a general string cell -> None or cleaned string."""
    if _is_blank(x):
        return None
    return str(x).strip()


def _norm_bool_drop(x: Any) -> bool:
    """
    Normalize drop/store column.
    Accepts: 'drop'/'store', booleans, 0/1, 'true'/'false' case-insensitive.
    Defaults to store=False.
    """
    if x is None:
        return False
    s = str(x).strip().lower()
    if s in {"1", "true", "yes", "y"}:
        return True
    if s in {"0", "false", "no", "n"}:
        return False
    if s == "drop":
        return True
    if s == "store":
        return False
    # Be conservative: anything else → not drop (store)
    return False


@dataclass(frozen=True)
class Rule:
    """Single routing rule (already normalized)."""
    type: str  # "KeyPresent" | "KeyPresentValueMatches"
    key: str
    value: Optional[str]
    repo: Optional[str]  # None allowed when action=drop
    drop: bool

    def to_payload(self) -> Dict[str, Any]:
        payload = {
            "criteria": {
                "type": self.type,
                "key": self.key,
            },
            "action": "drop" if self.drop else "store",
        }
        # value required only for KeyPresentValueMatches
        if self.type == "KeyPresentValueMatches" and self.value is not None:
            payload["criteria"]["value"] = self.value
        # repo required when storing
        if not self.drop and self.repo:
            payload["repo"] = self.repo
        return payload


@dataclass
class Policy:
    """Routing policy (desired state)."""
    name: str
    active: bool
    catch_all: Optional[str]
    rules: List[Rule]


# --------- Importer


class RoutingPoliciesImporter(BaseImporter[Policy]):
    """
    Importer for RoutingPolicies resource, aligned with the v2 framework.

    Resource name in Director API: "RoutingPolicies".
    """

    RESOURCE = "RoutingPolicies"
    # We support either "RoutingPolicy" (preferred) or "RP" as historical alias
    SHEET_CANDIDATES = ("RoutingPolicy", "RP")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Cache existing repos per node to avoid repeated GETs
        self._repos_cache = ResolverCache()
        # Repo name mapping (source -> destination) built once per workbook
        self._repo_name_map: Dict[str, str] = {}

    # ----- BaseImporter hooks

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> str:
        """Pick a valid sheet name and validate columns."""
        sheet = require_sheets(sheets, self.SHEET_CANDIDATES)
        df = sheets[sheet]

        require_columns(
            df,
            [
                "original_policy_name",
                "cleaned_policy_name",
                "active",
                "catch_all",
                "rule_type",
                "key",
                "value",
                "repo",
                "drop",
            ],
        )

        # Build repo name mapping from "Repo" sheet if present
        if "Repo" in sheets:
            r = sheets["Repo"]
            if {"original_repo_name", "cleaned_repo_name"}.issubset(r.columns):
                self._repo_name_map = _build_repo_map(r)
                LOG.info(
                    "routing_policies: loaded repo mapping (%d entries)",
                    len(self._repo_name_map),
                )
            else:
                LOG.warning(
                    "routing_policies: 'Repo' sheet present but required "
                    "columns missing; skipping repo mapping."
                )
        else:
            LOG.info("routing_policies: no 'Repo' sheet found (no repo mapping)")

        LOG.info("routing_policies: using sheet '%s'", sheet)
        return sheet

    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        nodes: Iterable[NodeRef],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Fetch existing policies on each node.

        Returns a dict keyed by node.id, each value being a mapping:
          name -> {"id": <policy_id>, "obj": <raw_obj>}
        """
        out: Dict[str, Dict[str, Any]] = {}
        for node in nodes:
            LOG.info(
                "fetch_existing: start [node=%s|%s]", node.name, node.id
            )
            try:
                items = client.list_resources(pool_uuid, node.id, self.RESOURCE)
            except Exception as e:  # requests.HTTPError already logged in client
                # Surface in the table as an "error/fetch" row
                self._append_error_row(
                    node,
                    action="fetch",
                    err=str(e),
                )
                out[node.id] = {}
                continue

            by_name: Dict[str, Dict[str, Any]] = {}
            for it in items or []:
                # Director commonly exposes "name" and "_id"/"id"
                name = it.get("name") or it.get("policy_name") or it.get("policyName")
                pid = it.get("_id") or it.get("id") or it.get("policy_id")
                if not name:
                    continue
                by_name[str(name)] = {"id": pid, "obj": it}

            LOG.info(
                "fetch_existing: found %d policies [node=%s|%s]",
                len(by_name),
                node.name,
                node.id,
            )
            out[node.id] = by_name
        return out

    def iter_desired(self, df: pd.DataFrame) -> Iterable[Tuple[str, Policy]]:
        """
        Yield (policy_name, Policy) built from the normalized dataframe.
        We group by cleaned_policy_name (destination name).
        """
        # Normalize a copy to avoid mutating original df
        work = df.copy()

        # Coerce booleans and strings
        work["cleaned_policy_name"] = work["cleaned_policy_name"].apply(_norm_str)
        work["original_policy_name"] = work["original_policy_name"].apply(_norm_str)
        work["active"] = work["active"].apply(lambda x: bool(x) if not _is_blank(x) else True)
        work["catch_all"] = work["catch_all"].apply(_norm_str)
        work["rule_type"] = work["rule_type"].apply(_norm_str)
        work["key"] = work["key"].apply(_norm_str)
        work["value"] = work["value"].apply(_norm_str)
        work["repo"] = work["repo"].apply(_norm_str)
        work["drop"] = work["drop"].apply(_norm_bool_drop)

        # Group rows by destination policy name
        for pol_name, g in work.groupby("cleaned_policy_name", dropna=True):
            if not pol_name:
                # skip rows without a destination policy name
                continue

            active = bool(g["active"].iloc[0]) if "active" in g else True

            # Map catch_all via repo mapping (if provided)
            catch_src = g["catch_all"].iloc[0] if "catch_all" in g else None
            catch_all = self._map_repo_name(catch_src)

            # Build rules list
            rules: List[Rule] = []
            invalid: List[str] = []

            # Keep original order (row index)
            for ridx, row in g.reset_index().iterrows():
                rtype = row.get("rule_type")
                key = row.get("key")
                val = row.get("value")
                repo_src = row.get("repo")
                drop = bool(row.get("drop", False))

                if _is_blank(rtype) or _is_blank(key):
                    # Totally empty rule line → ignore silently
                    continue

                rtype = str(rtype)
                if rtype not in ("KeyPresent", "KeyPresentValueMatches"):
                    invalid.append(f"row {int(row['index'])}: unsupported rule_type={rtype!r}")
                    continue

                # Map repo if present
                repo_mapped = self._map_repo_name(repo_src)

                # If action is store (drop=False), repo is required
                if not drop and not repo_mapped:
                    invalid.append(f"row {int(row['index'])}: missing repo when drop=False")
                    continue

                rules.append(
                    Rule(
                        type=rtype,
                        key=str(key),
                        value=None if _is_blank(val) else str(val),
                        repo=repo_mapped,
                        drop=drop,
                    )
                )

            if invalid:
                LOG.warning(
                    "apply: ignored %d invalid rule(s) for policy=%s: %s [node=%s]",
                    len(invalid),
                    pol_name,
                    invalid,
                    self.node_name or "—",
                )

            yield pol_name, Policy(
                name=pol_name, active=active, catch_all=catch_all, rules=rules
            )

    # ----- Apply operations

    def apply(
        self,
        op: str,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        desired: Policy,
        existing: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Apply a decision for one policy on one node.
        Returns an op_result dict consumed by main/reporting.
        """
        # Compute referenced repos (mapped) for presence checks
        referenced: Set[str] = set()
        if desired.catch_all:
            referenced.add(desired.catch_all)
        for r in desired.rules:
            if not r.drop and r.repo:
                referenced.add(r.repo)

        # Ensure all referenced repos exist on the node
        missing = self._missing_repos_on_node(client, pool_uuid, node, referenced)
        if missing:
            LOG.warning(
                "apply: skipping policy=%s due to missing repos=%s [node=%s|%s]",
                desired.name,
                sorted(missing),
                node.name,
                node.id,
            )
            return {
                "result": "create" if op == "CREATE" else op.lower(),
                "action": "Not found",
                "status": "Skipped",
                "monitor_ok": None,
                "error": None,
            }

        payload = self._to_payload(desired)

        if op == "NOOP":
            return {
                "result": "noop",
                "action": "Identical subset",
                "status": "—",
                "monitor_ok": None,
            }

        try:
            if op == "CREATE":
                LOG.info(
                    "apply: op=CREATE policy=%s [node=%s|%s]",
                    desired.name,
                    node.name,
                    node.id,
                )
                res = client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
            elif op == "UPDATE":
                LOG.info(
                    "apply: op=UPDATE policy=%s id=%s [node=%s|%s]",
                    desired.name,
                    existing.get("id") if existing else "—",
                    node.name,
                    node.id,
                )
                res = client.update_resource(
                    pool_uuid, node.id, self.RESOURCE, existing["id"], payload
                )
            elif op == "DELETE":
                LOG.info(
                    "apply: op=DELETE policy=%s id=%s [node=%s|%s]",
                    desired.name,
                    existing.get("id") if existing else "—",
                    node.name,
                    node.id,
                )
                res = client.delete_resource(pool_uuid, node.id, self.RESOURCE, existing["id"])
            else:
                return {
                    "result": op.lower(),
                    "action": "Unsupported",
                    "status": "Skipped",
                    "monitor_ok": None,
                    "error": f"unsupported op={op}",
                }

        except Exception as e:
            LOG.error(
                "apply: API call failed for policy=%s [node=%s|%s]",
                desired.name,
                node.name,
                node.id,
                exc_info=True,
            )
            return {
                "result": op.lower(),
                "action": "Not found" if op == "CREATE" else "API error",
                "status": "Failed",
                "monitor_ok": None,
                "error": str(e),
            }

        return res

    # ----- Internals

    def _to_payload(self, pol: Policy) -> Dict[str, Any]:
        """
        Build Director API payload from a Policy.
        We use the API naming that has proven compatible with 2.7+:
        - name
        - active
        - catchAllRepo
        - rules (list of {criteria:{type,key[,value]}, action, [repo]})
        """
        payload = {
            "name": pol.name,
            "active": bool(pol.active),
            "catchAllRepo": pol.catch_all,
            "rules": [r.to_payload() for r in pol.rules],
        }
        return payload

    def _map_repo_name(self, src: Optional[str]) -> Optional[str]:
        """Map a *source* repo name to destination cleaned name (if mapping exists)."""
        if not src or _is_blank(src):
            return None
        key = str(src).strip()
        mapped = self._repo_name_map.get(key)
        return mapped or key

    def _missing_repos_on_node(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        needed: Set[str],
    ) -> Set[str]:
        """Return the subset of `needed` repo names that are not present on `node`."""
        if not needed:
            return set()

        # Cache key per node and resource
        cache_key = (pool_uuid, node.id, "Repos")
        cached = self._repos_cache.get(cache_key)
        if cached is None:
            # Fetch once per node
            try:
                repos = client.list_resources(pool_uuid, node.id, "Repos")
            except Exception:
                LOG.error(
                    "apply: failed to list Repos for node=%s|%s",
                    node.name,
                    node.id,
                    exc_info=True,
                )
                # If we can't list, consider all missing to be safe
                return set(sorted(needed))

            names: Set[str] = set()
            for it in repos or []:
                # Common keys: "name" or "repoName"
                nm = it.get("name") or it.get("repoName")
                if nm:
                    names.add(str(nm))
            self._repos_cache.set(cache_key, names)
            node_repos = names
        else:
            node_repos = cached

        missing = {r for r in needed if r not in node_repos}
        return missing

    # Optional: compare desired vs. existing to decide UPDATE/NOOP precisely.
    # BaseImporter can drive diff externally; if not, everything not found → CREATE.


# Entry point factory required by main.py generic dispatcher
def get_importer(*args, **kwargs) -> RoutingPoliciesImporter:
    return RoutingPoliciesImporter(*args, **kwargs)
