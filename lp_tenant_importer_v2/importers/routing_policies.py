# lp_tenant_importer_v2/routing_policies.py
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import math
import pandas as pd

from .base import BaseImporter
from ..core.nodes import Node  # type: ignore

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Rule:
    """In-memory representation of one routing rule (row)."""
    active: bool
    rule_type: Optional[str]  # "KeyPresent" | "KeyPresentValueMatches" | None (for drop/catch_all)
    key: Optional[str]
    value: Optional[str]
    repo: Optional[str]       # cleaned repo name or None when drop=True
    drop: bool                # True => drop, False => store to repo


class RoutingPoliciesImporter(BaseImporter):
    """
    Importer for Routing Policies (create/update only; delete is out of scope).

    Excel sheets expected:
      - "RoutingPolicy" (preferred) or "RP": rules + policy name mapping
      - "Repo": mapping of repository names (original_repo_name -> cleaned_repo_name)

    API resources:
      - ConfigAPI collection "RoutingPolicies"
    """

    RESOURCE = "RoutingPolicies"
    RP_SHEETS = ("RoutingPolicy", "RP")
    REPO_SHEETS = ("Repo", "Repos")  # tolerate both

    # --- lifecycle ---------------------------------------------------------

    def validate(self, xlsx_path: str) -> None:
        """Load sheets + build mappings. Keep everything in memory for apply()."""
        self.xlsx_path = xlsx_path

        # Pick RP sheet
        xl = pd.ExcelFile(xlsx_path)
        rp_sheet = next((s for s in self.RP_SHEETS if s in xl.sheet_names), None)
        if not rp_sheet:
            LOG.error("routing_policies: missing sheet 'RoutingPolicy' (or 'RP')")
            raise ValueError("Missing required sheet: RoutingPolicy / RP")
        LOG.info("routing_policies: using sheet '%s'", rp_sheet)

        self.df_rp = xl.parse(rp_sheet).copy()

        # Build policy name map (optional but recommended)
        self.policy_name_map: Dict[str, str] = {}
        for cols in (
            ("original_policy_name", "cleaned_policy_name"),
            ("original_name", "cleaned_name"),
        ):
            if all(c in self.df_rp.columns for c in cols):
                src, dst = cols
                self.policy_name_map = (
                    self.df_rp[[src, dst]]
                    .dropna(how="any")
                    .drop_duplicates()
                    .assign(
                        **{
                            src: lambda d: d[src].astype(str).str.strip(),
                            dst: lambda d: d[dst].astype(str).str.strip(),
                        }
                    )
                ).set_index(src)[dst].to_dict()
                break
        LOG.debug("policy_name_map: %d entries (examples=%s)",
                  len(self.policy_name_map),
                  dict(list(self.policy_name_map.items())[:3]))

        # Load Repo mapping from Repo/Repos sheet
        repo_sheet = next((s for s in self.REPO_SHEETS if s in xl.sheet_names), None)
        if not repo_sheet:
            LOG.warning("routing_policies: sheet 'Repo' not found; repo name mapping disabled")
            self.repo_name_map = {}
        else:
            df_repo = xl.parse(repo_sheet)
            self.repo_name_map = self._build_repo_name_map(df_repo)
            LOG.debug("repo_name_map: %d entries (examples=%s)",
                      len(self.repo_name_map),
                      dict(list(self.repo_name_map.items())[:3]))

        # Prepared caches (per run)
        self._node_repo_cache: Dict[str, Set[str]] = {}  # node_id -> {cleaned repo names}

    # --- Base hooks --------------------------------------------------------

    def fetch_existing(self, client, pool_uuid: str, node: Node) -> Dict[str, dict]:
        """Return existing policies on node, keyed by *cleaned* policy name."""
        LOG.info("fetch_existing: start [node=%s|%s]", node.name, node.id)
        try:
            items = client.list_resources(pool_uuid, node.id, self.RESOURCE)
        except Exception as exc:  # network/HTTP errors are already logged in client
            LOG.error("fetch_existing: failed [node=%s|%s] error=%s", node.name, node.id, exc)
            return {}

        # Director returns cleaned names in field "name"
        result = {str(it.get("name", "")).strip(): it for it in items if it.get("name")}
        LOG.info("fetch_existing: found %d policies [node=%s|%s]", len(result), node.name, node.id)
        return result

    def desired_items(self) -> Iterable[Tuple[str, Dict[str, Any]]]:
        """
        Yield desired policies grouped by cleaned policy name -> dict with rules.
        We only prepare the *data rows*, the API payload is formed in apply().
        """
        # Group by original/cleaned policy name
        df = self.df_rp.copy()

        # Normalize policy names (use mapping when available)
        def _clean_policy_name(x: Any) -> str:
            s = self._to_str(x)
            if not s:
                return ""
            return self.policy_name_map.get(s, s)

        if "original_policy_name" in df.columns:
            df["policy_name"] = df["original_policy_name"].map(_clean_policy_name)
        elif "cleaned_policy_name" in df.columns:
            df["policy_name"] = df["cleaned_policy_name"].map(self._to_str)
        else:
            # Fallback: a single policy sheet w/o name columns isn't importable
            return []

        # Keep only rows with a target policy name
        df = df[df["policy_name"].astype(str).str.len() > 0]

        # Ensure required columns exist
        for col in ("active", "catch_all", "rule_type", "key", "value", "repo", "drop"):
            if col not in df.columns:
                df[col] = None

        # Group rows by policy
        for pname, g in df.groupby("policy_name", sort=False):
            rows = g.to_dict(orient="records")
            yield pname, {"rows": rows}

    # --- Apply -------------------------------------------------------------

    def apply(  # type: ignore[override]
        self,
        client,
        pool_uuid: str,
        node: Node,
        decision: str,
        existing_id: Optional[str],
        desired_obj: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Create/Update the routing policy if all required repositories exist on the node.
        If some required repos are missing, skip the operation and report them.
        """
        pname = desired_obj.get("name") or desired_obj.get("policy_name") or ""
        pname = self._to_str(pname)
        if not pname:
            # When coming from Base diff engine, desired_obj usually doesn't include name;
            # re-compute it from the grouped key used in desired_items()
            pname = "<unnamed>"

        LOG.info("apply: op=%s policy=%s [node=%s|%s]", decision, pname, node.name, node.id)

        # Build rules + collect required repositories
        rules, invalid_msgs = self._build_rules(desired_obj.get("rows", []))
        if invalid_msgs:
            LOG.warning(
                "apply: ignored %d invalid rule(s) for policy=%s: %s [node=%s|%s]",
                len(invalid_msgs),
                pname,
                invalid_msgs,
                node.name,
                node.id,
            )

        required_repos = self._collect_required_repos(rules, desired_obj.get("rows", []))

        # Ensure node repo cache is warm
        existing_repos = self._repos_on_node(client, pool_uuid, node)

        missing = sorted(set(required_repos) - existing_repos)
        if missing:
            LOG.warning(
                "apply: skipping policy=%s due to missing repos=%s [node=%s|%s]",
                pname,
                missing,
                node.name,
                node.id,
            )
            return {
                "name": pname,
                "result": "create" if decision == "CREATE" else "update" if decision == "UPDATE" else decision.lower(),
                "action": "Not found",
                "status": "Skipped",
                "monitor_ok": None,
                "error": None,
            }

        # Build API payload
        payload = {
            "name": pname,
            "active": True,  # policy level active: if needed, derive from sheet later
            "criteria": [self._rule_to_payload(r) for r in rules],
            # catch_all is handled as a rule with KeyPresent on "*" (Director ignores),
            # OR maintained in criteria according to API; we include as repos-only rule below.
        }

        # catch_all (single value at policy-level)
        cat_repo = self._norm_repo_name(self._first_value(desired_obj.get("rows", []), "catch_all"))
        if cat_repo:
            payload["catch_all"] = {"repo": cat_repo}

        # Call Director
        if decision == "CREATE":
            LOG.info(
                "apply: CREATE policy=%s [node=%s|%s]",
                pname, node.name, node.id
            )
            return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
        if decision == "UPDATE":
            LOG.info(
                "apply: UPDATE policy=%s id=%s [node=%s|%s]",
                pname, existing_id, node.name, node.id
            )
            return client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)

        # NOOP or other
        return {"name": pname, "result": "noop", "action": "Identical subset"}

    # --- Helpers -----------------------------------------------------------

    @staticmethod
    def _to_str(x: Any) -> str:
        if x is None:
            return ""
        if isinstance(x, float) and math.isnan(x):
            return ""
        s = str(x).strip()
        # guard against literal 'nan', 'NaN', 'None'
        return "" if s.lower() in ("nan", "none", "null") else s

    def _norm_repo_name(self, x: Any) -> Optional[str]:
        """Robust repo normalization: empty/NaN -> None, mapping applied otherwise."""
        s = self._to_str(x)
        if not s:
            return None
        # Apply mapping (original -> cleaned); fallback to as-is if no mapping
        mapped = self.repo_name_map.get(s, s)
        return mapped if mapped else None

    @staticmethod
    def _first_value(rows: List[Dict[str, Any]], col: str) -> Any:
        for r in rows:
            if col in r:
                return r.get(col)
        return None

    def _build_repo_name_map(self, df_repo: pd.DataFrame) -> Dict[str, str]:
        """Build {'original_repo_name': 'cleaned_repo_name'} from Repo sheet."""
        # Accept variations of column names
        cand_src = [c for c in df_repo.columns if str(c).strip().lower() in ("original_repo_name", "original_name", "source_name")]
        cand_dst = [c for c in df_repo.columns if str(c).strip().lower() in ("cleaned_repo_name", "cleaned_name", "target_name")]
        if not cand_src or not cand_dst:
            LOG.warning("Repo sheet does not expose expected columns; repo mapping disabled")
            return {}
        src, dst = cand_src[0], cand_dst[0]
        m = (
            df_repo[[src, dst]]
            .dropna(how="any")
            .drop_duplicates()
            .assign(
                **{
                    src: lambda d: d[src].astype(str).str.strip(),
                    dst: lambda d: d[dst].astype(str).str.strip(),
                }
            )
        ).set_index(src)[dst].to_dict()
        return m

    def _build_rules(self, rows: List[Dict[str, Any]]) -> Tuple[List[Rule], List[str]]:
        """Convert RP rows to Rule objects, skipping invalids and collecting messages."""
        rules: List[Rule] = []
        invalid: List[str] = []

        for idx, r in enumerate(rows, start=1):
            active = str(r.get("active", "TRUE")).strip().lower() in ("true", "1", "yes")
            if not active:
                continue

            drop_flag = str(r.get("drop", "")).strip().lower() == "drop"
            repo_clean = self._norm_repo_name(r.get("repo"))

            # When drop=False, a repo is mandatory
            if not drop_flag and not repo_clean:
                invalid.append(f"row {idx}: missing repo when drop=False")
                continue

            rule_type = self._to_str(r.get("rule_type"))
            key = self._to_str(r.get("key"))
            value = self._to_str(r.get("value"))

            # For drop/catch-all rows, rule_type/key/value may be empty
            rules.append(
                Rule(
                    active=True,
                    rule_type=rule_type or None,
                    key=key or None,
                    value=value or None,
                    repo=None if drop_flag else repo_clean,
                    drop=drop_flag,
                )
            )

        return rules, invalid

    def _collect_required_repos(self, rules: List[Rule], rows: List[Dict[str, Any]]) -> Set[str]:
        """Repos that must exist on destination before creating/updating the policy."""
        req: Set[str] = set()

        # catch_all at policy-level
        cat = self._norm_repo_name(self._first_value(rows, "catch_all"))
        if cat:
            req.add(cat)

        # all rules with drop=False require a repo
        for ru in rules:
            if not ru.drop and ru.repo:
                req.add(ru.repo)

        return req

    def _repos_on_node(self, client, pool_uuid: str, node: Node) -> Set[str]:
        """Return cleaned repo names existing on the node (cached per node)."""
        if node.id in self._node_repo_cache:
            return self._node_repo_cache[node.id]

        try:
            items = client.list_resources(pool_uuid, node.id, "Repos")
        except Exception as exc:
            LOG.error("repos_on_node: failed to list repos [node=%s|%s] error=%s", node.name, node.id, exc)
            items = []

        names = {self._to_str(it.get("name")) for it in items if self._to_str(it.get("name"))}
        self._node_repo_cache[node.id] = names

        LOG.debug(
            "repos_on_node: %d repos cached [node=%s|%s] examples=%s",
            len(names),
            node.name,
            node.id,
            list(sorted(names))[:5],
        )
        return names

    @staticmethod
    def _rule_to_payload(r: Rule) -> Dict[str, Any]:
        """Director API payload for one rule."""
        # Drop rule: Director expects a criterion with drop flag and no repo
        if r.drop:
            return {
                "drop": True,
                "type": r.rule_type or None,
                "key": r.key or None,
                "value": r.value or None,
            }

        # Store rule (requires repo)
        payload = {
            "drop": False,
            "repo": r.repo,  # cleaned name
            "type": r.rule_type or None,
            "key": r.key or None,
            "value": r.value or None,
        }
        return payload
