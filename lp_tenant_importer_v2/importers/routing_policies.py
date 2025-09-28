# lp_tenant_importer_v2/importers/routing_policies.py
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import logging
import pandas as pd
import requests

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError
from .base import BaseImporter

log = logging.getLogger(__name__)


class RoutingPoliciesImporter(BaseImporter):
    """
    Importer for Routing Policies (harmonized with Repos v2).

    Excel input:
      - Sheet name: "RoutingPolicy" (preferred). "RP" is accepted for legacy.
      - Expected columns (one row per rule; rows grouped by policy):
          cleaned_policy_name : str (policy identifier)
          active              : bool-like
          catch_all           : str (repo name for default route, optional)
          rule_type           : str (ignored for API "type" – we derive it)
          key                 : str (normalized field name)
          value               : str (optional; if present -> ValueMatches)
          repo                : str (target repo when drop=False)
          drop                : bool-like ('store'/'drop', true/false, etc.)

    API payload (Director 2.7+):
      {
        "policy_name": "<string>",
        "active": <bool>,
        "catch_all": "<repo-name-or-empty>",
        "routing_criteria": [
          {
            "type": "KeyPresent" | "KeyPresentValueMatches",
            "key": "<str>",
            "value": "<str>",            # optional if type=KeyPresent
            "drop": <bool>,
            "repo": "<str>"              # only if drop=False
          },
          ...
        ]
      }

    Behavior:
      - Pre-validates *all* referenced repos on the target node:
        * catch_all if non-empty
        * every criterion with drop=False
        If any is missing -> SKIP the policy for that node (no POST/PUT).
      - Gracefully handles unsupported feature (400 "not supported"):
        mark node as unsupported and SKIP all policies on that node.
      - Canonicalizes criteria and compares desired vs existing to decide
        NOOP/CREATE/UPDATE.
    """

    # ---- API & sheet wiring -------------------------------------------------
    RESOURCE: str = "RoutingPolicies"
    SHEETS: Tuple[str, ...] = ("RoutingPolicy", "RP")
    REQUIRED_COLUMNS: Tuple[str, ...] = (
        "cleaned_policy_name",
        "active",
        "catch_all",
        "rule_type",
        "key",
        "value",
        "repo",
        "drop",
    )
    # The diff engine uses these canonical keys (plus criteria list)
    COMPARE_KEYS: Tuple[str, ...] = ("active", "catch_all", "routing_criteria")

    # Internal caches/flags
    _repos_cache: Dict[str, Set[str]]  # node_id -> repo names
    _unsupported_nodes: Set[str]       # node_ids where RP is unsupported

    def __init__(self) -> None:
        super().__init__()
        self._repos_cache = {}
        self._unsupported_nodes = set()

    # ---- XLSX parsing -------------------------------------------------------

    def _pick_sheet(self, sheets: Dict[str, pd.DataFrame]) -> str:
        for name in self.SHEETS:
            if name in sheets:
                return name
            # case-insensitive fallback
            for k in sheets.keys():
                if k.lower() == name.lower():
                    return k
        raise ValidationError(f"Missing sheet: expected one of {self.SHEETS}")

    @staticmethod
    def _to_bool(x: Any) -> bool:
        if isinstance(x, bool):
            return x
        s = str(x).strip().lower()
        return s in {"1", "true", "yes", "y", "on", "drop"}

    @staticmethod
    def _is_nonempty(x: Any) -> bool:
        if x is None:
            return False
        s = str(x).strip()
        return s not in {"", "nan", "none", "null"}

    @staticmethod
    def _norm_str(x: Any) -> str:
        return str(x or "").strip()

    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        """
        Group rows by cleaned_policy_name and yield one desired object per policy.

        We derive the API "type" field from the presence of "value":
          - if value is empty   -> KeyPresent
          - if value is present -> KeyPresentValueMatches

        We never put a "repo" on a drop=True criterion.
        """
        sheet_name = self._pick_sheet(sheets)
        df = sheets[sheet_name].copy()

        # Validate required columns (case-sensitive to keep it strict)
        missing = [c for c in self.REQUIRED_COLUMNS if c not in df.columns]
        if missing:
            raise ValidationError(
                f"Missing required columns on sheet '{sheet_name}': {missing}"
            )

        # Group policies
        for policy_name, grp in df.groupby("cleaned_policy_name", dropna=False):
            name = self._norm_str(policy_name)
            if not name:
                # Skip rows without a policy id; provide a hint if needed.
                first_idx = int(grp.index.min())
                raise ValidationError(
                    f"Sheet '{sheet_name}' row {first_idx + 2}: empty "
                    f"'cleaned_policy_name'"
                )

            # Aggregate header fields (take from the first row)
            first = grp.iloc[0]
            active = self._to_bool(first.get("active"))
            catch_all = self._norm_str(first.get("catch_all"))

            # Build criteria
            criteria: List[Dict[str, Any]] = []
            ignored_reasons: List[str] = []

            for idx, row in grp.iterrows():
                key = self._norm_str(row.get("key"))
                value = self._norm_str(row.get("value"))
                repo = self._norm_str(row.get("repo"))
                drop = self._to_bool(row.get("drop"))

                # Skip fully empty lines (no key/value/repo/drop)
                if not any([key, value, repo, drop]):
                    continue

                # A valid criterion must have a key
                if not key:
                    ignored_reasons.append(f"row {idx + 2}: missing key")
                    continue

                # Derive type from presence of value (API expects one of two)
                ctype = "KeyPresentValueMatches" if value else "KeyPresent"

                if drop:
                    # Drop rule: must NOT send a repo
                    crit = {"type": ctype, "key": key, "drop": True}
                    if value:
                        crit["value"] = value
                    criteria.append(crit)
                else:
                    # Store rule: repo is required
                    if not repo:
                        ignored_reasons.append(
                            f"row {idx + 2}: missing repo when drop=False"
                        )
                        continue
                    crit = {"type": ctype, "key": key, "drop": False, "repo": repo}
                    if value:
                        crit["value"] = value
                    criteria.append(crit)

            desired = {
                "policy_name": name,
                "active": bool(active),
                "catch_all": catch_all,
                "routing_criteria": criteria,
                "_ignored": ignored_reasons,  # only for logging
            }
            yield desired

    # ---- Canonicalization & diff keys --------------------------------------

    @staticmethod
    def _canon_criteria(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Produce a deterministic criteria list:
          - normalize strings
          - ensure drop is bool
          - remove empty fields
          - sort by (type, key, value, repo, drop)
        """
        canon: List[Dict[str, Any]] = []
        for r in rules or []:
            ctype = RoutingPoliciesImporter._norm_str(r.get("type"))
            key = RoutingPoliciesImporter._norm_str(r.get("key"))
            value = RoutingPoliciesImporter._norm_str(r.get("value"))
            repo = RoutingPoliciesImporter._norm_str(r.get("repo"))
            drop = bool(r.get("drop"))

            if not key:
                # invalid rule; ignore silently in canonicalization
                continue

            item: Dict[str, Any] = {"type": ctype or ("KeyPresent" if not value else "KeyPresentValueMatches"),
                                    "key": key,
                                    "drop": drop}
            if value:
                item["value"] = value
            if not drop and repo:
                item["repo"] = repo

            canon.append(item)

        def sort_key(it: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
            return (
                (it.get("type") or "").lower(),
                (it.get("key") or "").lower(),
                it.get("value") or "",
                (it.get("repo") or "").lower(),
                "1" if it.get("drop") else "0",
            )

        return sorted(canon, key=sort_key)

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        # Unique key for a policy: its name.
        return self._norm_str(desired_row.get("policy_name"))

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "active": bool(desired_row.get("active")),
            "catch_all": self._norm_str(desired_row.get("catch_all")),
            "routing_criteria": self._canon_criteria(
                desired_row.get("routing_criteria") or []
            ),
        }

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        if not existing_obj:
            return {}
        return {
            "active": bool(existing_obj.get("active")),
            "catch_all": self._norm_str(existing_obj.get("catch_all")),
            "routing_criteria": self._canon_criteria(
                existing_obj.get("routing_criteria") or []
            ),
        }

    # ---- Existing state (GET) -----------------------------------------------

    def _mark_unsupported(self, node_id: str) -> None:
        self._unsupported_nodes.add(node_id)

    def _is_unsupported(self, node_id: str) -> bool:
        return node_id in self._unsupported_nodes

    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """
        Fetch current policies and index by policy_name.

        If the node version doesn't support RP (HTTP 400 "not supported"),
        mark the node unsupported and return {} so that apply() can SKIP.
        """
        node_tag = f"{node.name}|{node.id}"
        log.info("fetch_existing: start [node=%s]", node_tag)
        try:
            raw = client.list_resource(pool_uuid, node.id, self.RESOURCE) or {}
        except requests.HTTPError as exc:
            msg = str(exc)
            if "not supported" in msg.lower():
                self._mark_unsupported(node.id)
                log.warning(
                    "fetch_existing: RoutingPolicies not supported on node=%s "
                    "(marking as unsupported; policies will be skipped)",
                    node_tag,
                )
                return {}
            log.error("fetch_existing: HTTP error on node=%s: %s", node_tag, msg)
            raise

        # Tolerate both list and dict payloads.
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get("items") or raw.get("data") or raw.get("results") or raw
            if isinstance(items, dict):
                items = items.get("data", [])
        else:
            items = []

        by_name: Dict[str, Dict[str, Any]] = {}
        for it in items or []:
            if not isinstance(it, dict):
                continue
            name = self._norm_str(it.get("policy_name") or it.get("name"))
            if name:
                by_name[name] = it

        log.info("fetch_existing: found %d policies [node=%s]", len(by_name), node_tag)
        return by_name

    # ---- Repo dependencies (pre-validation) ---------------------------------

    def _list_repos(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Set[str]:
        """Return set of repo names available on the node (cached per node)."""
        if node.id in self._repos_cache:
            return self._repos_cache[node.id]

        node_tag = f"{node.name}|{node.id}"
        try:
            raw = client.list_resource(pool_uuid, node.id, "Repos") or {}
        except Exception:
            log.exception("list_repos: failed to list repos [node=%s]", node_tag)
            raise

        # Tolerate list/dict shapes as in Repos importer
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get("repos") or raw.get("data") or raw.get("items") or []
        else:
            items = []

        names: Set[str] = set()
        for it in items or []:
            if isinstance(it, dict):
                n = self._norm_str(it.get("name"))
                if n:
                    names.add(n)

        self._repos_cache[node.id] = names
        log.debug("list_repos: %d repos cached [node=%s]", len(names), node_tag)
        return names

    @staticmethod
    def _collect_required_repos(desired_row: Dict[str, Any]) -> Set[str]:
        """
        Build the set of repositories referenced by the policy:
          - catch_all if non-empty
          - every criterion with drop=False (repo required)
        """
        needed: Set[str] = set()

        catch_all = RoutingPoliciesImporter._norm_str(desired_row.get("catch_all"))
        if catch_all:
            needed.add(catch_all)

        for it in desired_row.get("routing_criteria") or []:
            if not isinstance(it, dict):
                continue
            if bool(it.get("drop")):
                continue  # drop rules don't require a repo
            repo = RoutingPoliciesImporter._norm_str(it.get("repo"))
            if repo:
                needed.add(repo)

        return needed

    # ---- Payload builders ----------------------------------------------------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "policy_name": self.key_fn(desired_row),
            "active": bool(desired_row.get("active")),
            "catch_all": self._norm_str(desired_row.get("catch_all")),
            "routing_criteria": self._canon_criteria(
                desired_row.get("routing_criteria") or []
            ),
        }

    def build_payload_update(
        self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        # Same shape as POST; id is carried in the URL
        return self.build_payload_create(desired_row)

    # ---- Apply ---------------------------------------------------------------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Execute CREATE/UPDATE/NOOP/Skip for a single policy on a node.

        - If node is marked unsupported -> Skip.
        - If required repos are missing -> Skip.
        - Otherwise delegate to DirectorClient (async monitor handled there).
        """
        node_tag = f"{node.name}|{node.id}"
        name = self.key_fn(decision.desired or {})
        op = getattr(decision, "op", "?")

        log.info("apply: op=%s policy=%s [node=%s]", op, name, node_tag)

        # Graceful skip for unsupported nodes
        if self._is_unsupported(node.id):
            log.info(
                "apply: skipping policy=%s (RoutingPolicies unsupported) [node=%s]",
                name,
                node_tag,
            )
            return {"status": "Skipped", "result": {"reason": "unsupported"}}

        # Row-level warnings produced during parsing
        ignored = (decision.desired or {}).pop("_ignored", [])
        if ignored:
            log.warning(
                "apply: ignored %d invalid rule(s) for policy=%s: %s [node=%s]",
                len(ignored),
                name,
                ignored,
                node_tag,
            )

        # Pre-validate that *all* referenced repos exist on the node
        needed = self._collect_required_repos(decision.desired or {})
        if needed:
            available = self._list_repos(client, pool_uuid, node)
            missing = sorted(r for r in needed if r not in available)
            if missing:
                log.warning(
                    "apply: skipping policy=%s due to missing repos=%s [node=%s]",
                    name,
                    missing,
                    node_tag,
                )
                return {"status": "Skipped", "result": {"missing_repos": missing}}

        try:
            if op == "CREATE":
                payload = self.build_payload_create(decision.desired or {})
                log.debug("apply: CREATE payload=%s [node=%s]", payload, node_tag)
                return client.create_resource(
                    pool_uuid, node.id, self.RESOURCE, payload
                )

            if op == "UPDATE" and existing_id:
                payload = self.build_payload_update(
                    decision.desired or {}, {"id": existing_id}
                )
                log.debug(
                    "apply: UPDATE id=%s payload=%s [node=%s]",
                    existing_id,
                    payload,
                    node_tag,
                )
                return client.update_resource(
                    pool_uuid, node.id, self.RESOURCE, existing_id, payload
                )

            # NOOP or explicit SKIP from the diff engine
            log.debug("apply: NOOP/Skip policy=%s [node=%s]", name, node_tag)
            return {"status": "Success", "monitor_ok": None}
        except Exception:  # pragma: no cover (logged & re-raised for CLI)
            log.exception("apply: API call failed for policy=%s [node=%s]", name, node_tag)
            raise
