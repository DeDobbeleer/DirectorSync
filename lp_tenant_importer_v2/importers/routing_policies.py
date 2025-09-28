# lp_tenant_importer_v2/routing_policies.py
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd
from .base import BaseImporter, Decision  # même base que Repos
from ..core.director_client import DirectorClient
from ..utils.validators import require_columns
from ..utils.reporting import print_rows  # utilisé par la base
from ..utils.diff_engine import DiffEngine

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _to_bool(x: Any) -> Optional[bool]:
    """Best-effort normalization to bool. Returns None if empty/unknown."""
    if x is None:
        return None
    if isinstance(x, bool):
        return x
    s = str(x).strip().lower()
    if s in ("true", "yes", "y", "1", "on", "active", "store"):
        return True
    if s in ("false", "no", "n", "0", "off", "inactive", "drop"):
        # NB: in our sheets "drop" means do *not* store to a repo (rule is a drop)
        # but when used on the "active" column we interpret "drop" as False.
        return False
    return None


def _is_blank(x: Any) -> bool:
    if x is None:
        return True
    if isinstance(x, float) and pd.isna(x):
        return True
    return str(x).strip() == ""


def _norm_str(x: Any) -> str:
    if _is_blank(x):
        return ""
    return str(x).strip()


def _norm_repo_name(x: Any) -> str:
    """
    Normalize repo names: trim, collapse weird 'nan/none/null/-' etc.
    """
    s = _norm_str(x)
    if s.lower() in {"nan", "none", "null", "-"}:
        return ""
    return s


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Rule:
    # "KeyPresent" or "KeyPresentValueMatches"
    rule_type: str
    key: str
    value: str
    repo: str  # destination repo (empty if drop=True)
    drop: bool


@dataclass
class DesiredPolicy:
    name: str
    active: bool
    catch_all: str  # repo name (after mapping)
    rules: List[Rule]

    @property
    def used_repos(self) -> List[str]:
        r = []
        if self.catch_all:
            r.append(self.catch_all)
        for rr in self.rules:
            if not rr.drop and rr.repo:
                r.append(rr.repo)
        # keep order, unique
        out, seen = [], set()
        for x in r:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out


# --------------------------------------------------------------------------- #
# Importer
# --------------------------------------------------------------------------- #

class RoutingPoliciesImporter(BaseImporter):
    """
    Importer for Routing Policies.

    Excel input (sheet "RoutingPolicy" or "RP") — required columns:
      - cleaned_policy_name (str)  -> name of the policy to create/update
      - active (bool-like)         -> TRUE/FALSE (or store/drop conventions)
      - catch_all (str)            -> default repo (can be empty)
      - rule_type (str)            -> KeyPresent | KeyPresentValueMatches
      - key (str)                  -> field key (empty allowed for KeyPresent?)
      - value (str)                -> value for KeyPresentValueMatches
      - repo (str)                 -> target repo (empty if drop)
      - drop (bool-like/str)       -> 'drop' to drop, 'store' to send to repo
      - policy_id (optional, str)  -> unused, kept for compatibility

    Repo name mapping:
      Read sheet "Repo" columns:
        - original_repo_name
        - cleaned_repo_name
      Every repo reference (catch_all & rule.repo) is mapped via that table.
    """
    RESOURCE = "RoutingPolicies"

    SHEET_CANDIDATES = ("RoutingPolicy", "RP")

    REQUIRED_COLUMNS = {
        "cleaned_policy_name",
        "active",
        "catch_all",
        "rule_type",
        "key",
        "value",
        "repo",
        "drop",
    }

    # columns for repo mapping table
    REPO_MAP_SHEET = "Repo"
    REPO_MAP_FROM = "original_repo_name"
    REPO_MAP_TO = "cleaned_repo_name"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # node.id -> set(repo names)
        self._repos_cache: Dict[str, set] = {}
        # global mapping old_repo -> new_repo
        self._repo_map: Dict[str, str] = {}

    # ---- Orchestration ------------------------------------------------------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> List[DesiredPolicy]:
        sheet_name = self._select_sheet(sheets)
        df = sheets[sheet_name].copy()
        require_columns(df, self.REQUIRED_COLUMNS, context=f"sheet '{sheet_name}'")

        # Build repo name map once (if the sheet exists)
        self._repo_map = self._build_repo_name_map(sheets)

        desired = self._parse_desired(df, repo_map=self._repo_map, sheet=sheet_name)
        log.info("routing_policies: using sheet '%s'", sheet_name)
        return desired

    def fetch_existing(
        self,
        client: DirectorClient,
        nodes: List[Any],
    ) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        Return dict: node_id -> { policy_name -> policy_obj }
        Also fill repo caches per node.
        """
        results: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for node in nodes:
            node_tag = f"{node.name}|{node.id}"
            log.info("fetch_existing: start [node=%s]", node_tag)

            # Fill repos cache for this node
            self._repos_cache[node.id] = self._list_repos(client, node)

            # Get existing policies (best effort)
            existing_by_name: Dict[str, Dict[str, Any]] = {}
            try:
                path = client.configapi_id(node.pool_uuid, node.id, self.RESOURCE)
                data = client.get_json(path) or {}
                items = data.get("data") if isinstance(data, dict) else data
                items = items or []
                for it in items:
                    name = _norm_str(it.get("name") or it.get("policy_name") or "")
                    if name:
                        existing_by_name[name] = it
                log.info(
                    "fetch_existing: found %d policies [node=%s]",
                    len(existing_by_name),
                    node_tag,
                )
            except Exception as e:
                # main.py affichera la ligne d'erreur
                self._rows.append(
                    {
                        "siem": node.pool_uuid,
                        "node": node.name,
                        "result": "error",
                        "action": "fetch",
                        "error": str(e),
                    }
                )
                log.error("fetch_existing: failed [node=%s] error=%s", node_tag, e)
            results[node.id] = existing_by_name
        return results

    def apply(
        self,
        client: DirectorClient,
        node: Any,
        decision: Decision[DesiredPolicy, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Execute CREATE/UPDATE/NOOP/SKIP/ERROR using DirectorClient.
        """
        node_tag = f"{node.name}|{node.id}"

        # Noop / error passed through by BaseImporter
        if decision.op in ("NOOP", "SKIP", "ERROR"):
            return {"status": "—"}

        desired = decision.desired
        assert desired is not None, "apply called without desired"

        # --- Validate referenced repos on this node
        missing = self._missing_repos(node.id, desired.used_repos)
        if missing:
            log.warning(
                "apply: skipping policy=%s due to missing repos=%s [node=%s]",
                desired.name,
                list(missing),
                node_tag,
            )
            return {"status": "Skipped", "result": {"missing_repos": sorted(missing)}}

        try:
            if decision.op == "CREATE":
                payload = self._payload_for_create(desired)
                log.info(
                    "apply: CREATE policy=%s [node=%s]",
                    desired.name,
                    node_tag,
                )
                res = client.create_resource(
                    node.pool_uuid, node.id, self.RESOURCE, payload
                )
                return self._monitor_result(client, node, res, "create")

            if decision.op == "UPDATE":
                existing_id = decision.existing.get("id") or decision.existing.get(
                    "_id"
                )
                payload = self._payload_for_update(desired)
                log.info(
                    "apply: UPDATE policy=%s id=%s [node=%s]",
                    desired.name,
                    existing_id,
                    node_tag,
                )
                res = client.update_resource(
                    node.pool_uuid,
                    node.id,
                    self.RESOURCE,
                    existing_id,
                    payload,
                )
                return self._monitor_result(client, node, res, "update")

            if decision.op == "DELETE":
                existing_id = decision.existing.get("id") or decision.existing.get(
                    "_id"
                )
                log.info(
                    "apply: DELETE policy=%s id=%s [node=%s]",
                    desired.name,
                    existing_id,
                    node_tag,
                )
                res = client.delete_resource(
                    node.pool_uuid, node.id, self.RESOURCE, existing_id
                )
                return self._monitor_result(client, node, res, "delete")

        except Exception as e:
            log.exception(
                "apply: API call failed for policy=%s [node=%s]",
                desired.name,
                node_tag,
            )
            return {"status": "Failed", "error": str(e)}

        return {"status": "—"}

    # ---- Diff keys / canon ---------------------------------------------------

    def compare_key(self, obj: DesiredPolicy | Dict[str, Any]) -> str:
        """Return the comparison key (policy name)."""
        if isinstance(obj, DesiredPolicy):
            return obj.name
        return _norm_str(obj.get("name") or obj.get("policy_name"))

    def canon_desired(self, d: DesiredPolicy) -> Dict[str, Any]:
        """Canonical form used by the diff engine."""
        return {
            "name": d.name,
            "active": bool(d.active),
            "catch_all": d.catch_all or "",
            "rules": [self._canon_rule(r) for r in d.rules],
        }

    def canon_existing(self, e: Dict[str, Any]) -> Dict[str, Any]:
        pol = e.get("policy") or {}
        rules = pol.get("rules") or e.get("rules") or []
        catch = pol.get("catch_all") or e.get("catch_all") or ""
        return {
            "name": _norm_str(e.get("name") or e.get("policy_name")),
            "active": bool(e.get("active", True)),
            "catch_all": _norm_repo_name(catch),
            "rules": [self._canon_rule_from_api(rr) for rr in rules],
        }

    # ---- Parsing desired from Excel -----------------------------------------

    def _select_sheet(self, sheets: Dict[str, pd.DataFrame]) -> str:
        for c in self.SHEET_CANDIDATES:
            if c in sheets:
                return c
        raise ValueError("Missing required sheets: RP or RoutingPolicy")

    def _build_repo_name_map(self, sheets: Dict[str, pd.DataFrame]) -> Dict[str, str]:
        """Build {old_repo -> new_repo} from 'Repo' sheet if present."""
        if self.REPO_MAP_SHEET not in sheets:
            return {}
        df = sheets[self.REPO_MAP_SHEET]
        cols = {c.lower(): c for c in df.columns}
        src = cols.get(self.REPO_MAP_FROM.lower())
        dst = cols.get(self.REPO_MAP_TO.lower())
        if not src or not dst:
            return {}

        mapping: Dict[str, str] = {}
        for _, row in df.iterrows():
            k = _norm_repo_name(row.get(src))
            v = _norm_repo_name(row.get(dst))
            if k and v:
                mapping[k] = v
        if mapping:
            log.info("repo-map: loaded %d entries from sheet '%s'", len(mapping), self.REPO_MAP_SHEET)
        return mapping

    def _parse_desired(
        self,
        df: pd.DataFrame,
        repo_map: Dict[str, str],
        sheet: str,
    ) -> List[DesiredPolicy]:
        # normalize columns to exact names
        cols = {c.lower(): c for c in df.columns}
        def col(name: str) -> str:
            # required ensured by validate()
            return cols.get(name.lower(), name)

        groups: Dict[str, List[Rule]] = {}
        meta: Dict[str, Dict[str, Any]] = {}

        # We'll also collect per-policy invalid rows to log once
        invalid_rows: Dict[str, List[str]] = {}

        for idx, row in df.iterrows():
            name = _norm_str(row.get(col("cleaned_policy_name")))
            if not name:
                # skip unnamed
                continue

            # policy meta (active & catch_all)
            if name not in meta:
                meta[name] = {
                    "active": bool(_to_bool(row.get(col("active"))) is not False),
                    "catch_all": self._map_repo(_norm_repo_name(row.get(col("catch_all"))), repo_map),
                }

            # Build rule (one row == one rule)
            rule_type = _norm_str(row.get(col("rule_type"))) or "KeyPresent"
            key = _norm_str(row.get(col("key")))
            value = _norm_str(row.get(col("value")))
            drop_flag = _to_bool(row.get(col("drop")))
            drop = (drop_flag is False) or (str(row.get(col("drop"))).strip().lower() == "drop")
            # IMPORTANT: in our spreadsheets we usually put "drop" / "store".
            #   If not "drop", we assume "store" -> need a repo.

            repo_in = _norm_repo_name(row.get(col("repo")))
            repo_mapped = self._map_repo(repo_in, repo_map)

            if not drop and not repo_mapped:
                invalid_rows.setdefault(name, []).append(
                    f"row {idx+2}: missing repo when drop=False"
                )
                continue

            groups.setdefault(name, []).append(
                Rule(
                    rule_type=rule_type,
                    key=key,
                    value=value,
                    repo=repo_mapped,
                    drop=drop,
                )
            )

        # Log invalid rows once per policy
        for pol, msgs in invalid_rows.items():
            log.warning(
                "apply: ignored %d invalid rule(s) for policy=%s: %s",
                len(msgs),
                pol,
                msgs,
            )

        desired: List[DesiredPolicy] = []
        for name, rules in groups.items():
            desired.append(
                DesiredPolicy(
                    name=name,
                    active=bool(meta[name]["active"]),
                    catch_all=_norm_repo_name(meta[name]["catch_all"]),
                    rules=rules,
                )
            )
        return desired

    # ---- Repo utilities ------------------------------------------------------

    def _map_repo(self, repo_name: str, repo_map: Dict[str, str]) -> str:
        """
        Map repo name using the mapping table (if any). Falls back to original.
        """
        if not repo_name:
            return ""
        return repo_map.get(repo_name, repo_name)

    def _list_repos(self, client: DirectorClient, node: Any) -> set:
        """Return the set of repo names existing on the given node."""
        names: set = set()
        try:
            path = client.configapi_id(node.pool_uuid, node.id, "Repos")
            data = client.get_json(path) or {}
            items = data.get("data") if isinstance(data, dict) else data
            for it in (items or []):
                nm = _norm_repo_name(it.get("name") or it.get("repo_name"))
                if nm:
                    names.add(nm)
        except Exception as e:
            log.error("list_repos: failed [node=%s|%s] err=%s", node.name, node.id, e)
        return names

    def _missing_repos(self, node_id: str, used_repos: Iterable[str]) -> set:
        have = self._repos_cache.get(node_id) or set()
        need = {r for r in used_repos if r}
        return need - have

    # ---- Payloads & canon ----------------------------------------------------

    def _payload_for_create(self, d: DesiredPolicy) -> Dict[str, Any]:
        """
        Shape according to Director API for RoutingPolicies (POST).
        Keep it aligned with v1 behaviour.
        """
        return {
            "policy_name": d.name,
            "active": bool(d.active),
            "policy": {
                "catch_all": d.catch_all or "",
                "rules": [self._rule_to_api(r) for r in d.rules],
            },
        }

    def _payload_for_update(self, d: DesiredPolicy) -> Dict[str, Any]:
        # same shape for PUT (id in the URL)
        return self._payload_for_create(d)

    def _canon_rule(self, r: Rule) -> Dict[str, Any]:
        if r.drop:
            return {"type": "drop"}
        return {
            "type": r.rule_type or "KeyPresent",
            "key": r.key,
            "value": r.value,
            "repo": r.repo,
        }

    def _canon_rule_from_api(self, rr: Dict[str, Any]) -> Dict[str, Any]:
        t = _norm_str(rr.get("type"))
        if t.lower() == "drop":
            return {"type": "drop"}
        return {
            "type": t or "KeyPresent",
            "key": _norm_str(rr.get("key")),
            "value": _norm_str(rr.get("value")),
            "repo": _norm_repo_name(rr.get("repo")),
        }

    def _rule_to_api(self, r: Rule) -> Dict[str, Any]:
        if r.drop:
            return {"type": "drop"}
        # Director expects: type, key, value, repo
        out = {
            "type": r.rule_type or "KeyPresent",
            "key": r.key,
            "repo": r.repo,
        }
        # only set value for KeyPresentValueMatches
        if (r.rule_type or "").lower() == "keypresentvaluematches":
            out["value"] = r.value
        return out

    # ---- Monitor wrapper -----------------------------------------------------

    def _monitor_result(
        self,
        client: DirectorClient,
        node: Any,
        res: Dict[str, Any],
        action: str,
    ) -> Dict[str, Any]:
        """
        Standardize async monitor result (like Repos importer).
        """
        mon_ok = None
        branch = None
        status = "Success"

        if res and isinstance(res, dict):
            branch = res.get("branch")
            # res can be {"monitor_url": "...", "branch": "..."} or similar
            mon_ok = client.monitor_job_response(res)
            if mon_ok is False:
                status = "Failed"

        return {"status": status, "monitor_ok": mon_ok, "monitor_branch": branch}
