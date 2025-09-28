# lp_tenant_importer_v2/importers/routing_policies.py
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd

from .base import BaseImporter, NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import require_columns

log = logging.getLogger(__name__)


def _node_tag(node: NodeRef) -> str:
    name = getattr(node, "name", None) or getattr(node, "id", "")
    nid = getattr(node, "id", "")
    return f"{name}|{nid}"


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
    s = _norm_str(x)
    if s.lower() in {"nan", "none", "null", "-"}:
        return ""
    return s


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
        # In sheets, "drop" on the *active* column means False.
        return False
    return None


class RoutingPoliciesImporter(BaseImporter):
    """Importer for Routing Policies aligned with the v2 BaseImporter API."""

    # ---- BaseImporter contract ----
    resource_name = "routing_policies"
    sheet_names = ("RoutingPolicy", "RP")  # NOTE: we accept *either* one
    required_columns = (
        "cleaned_policy_name",
        "active",
        "catch_all",
        "rule_type",
        "key",
        "value",
        "repo",
        "drop",
    )
    compare_keys = ("name", "active", "catch_all", "rules")

    # ---- Director API resource ----
    RESOURCE = "RoutingPolicies"

    # ---- Internal state ----
    def __init__(self) -> None:
        super().__init__()
        # node.id -> set(repo names)
        self._repos_cache: Dict[str, set] = {}
        # global mapping old_repo -> new_repo (built from optional "Repo" sheet)
        self._repo_map: Dict[str, str] = {}
        # active sheet name chosen during validate()
        self._active_sheet: str | None = None

    # --------------------------------------------------------------------- #
    # Validation: accept *either* "RoutingPolicy" or "RP", not both strict  #
    # --------------------------------------------------------------------- #
    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        sheet = self._select_sheet(sheets)
        self._active_sheet = sheet
        df = sheets[sheet]
        # We added an optional `context` kw in require_columns upstream.
        require_columns(df, self.required_columns, context=f"sheet '{sheet}'")
        # Build repo name map once if the optional mapping sheet is present
        self._repo_map = self._build_repo_name_map(sheets)
        log.info("routing_policies: using sheet '%s'", sheet)

    # --------------------------------------------------------------------- #
    # XLSX parsing → desired rows                                           #
    # --------------------------------------------------------------------- #
    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        """Yield desired routing policies from the active sheet."""
        sheet = self._active_sheet or self._select_sheet(sheets)
        df: pd.DataFrame = sheets[sheet]

        # Normalize column name access (case tolerant)
        cols = {c.lower(): c for c in df.columns}

        def col(name: str) -> str:
            return cols.get(name.lower(), name)

        # Collect per-policy meta + rules
        groups: Dict[str, List[Dict[str, Any]]] = {}
        meta: Dict[str, Dict[str, Any]] = {}
        invalid_rows: Dict[str, List[str]] = {}

        for idx, row in df.iterrows():
            name = _norm_str(row.get(col("cleaned_policy_name")))
            if not name:
                continue  # unnamed row -> skip

            # Initial meta per policy (first encounter wins)
            if name not in meta:
                meta[name] = {
                    "active": bool(_to_bool(row.get(col("active"))) is not False),
                    "catch_all": self._map_repo(
                        _norm_repo_name(row.get(col("catch_all"))), self._repo_map
                    ),
                }

            # One row == one rule
            rule_type = _norm_str(row.get(col("rule_type"))) or "KeyPresent"
            key = _norm_str(row.get(col("key")))
            value = _norm_str(row.get(col("value")))
            drop_flag = _to_bool(row.get(col("drop")))
            drop = (drop_flag is False) or (
                str(row.get(col("drop"))).strip().lower() == "drop"
            )

            repo_in = _norm_repo_name(row.get(col("repo")))
            repo_mapped = self._map_repo(repo_in, self._repo_map)

            if not drop and not repo_mapped:
                invalid_rows.setdefault(name, []).append(
                    f"row {idx + 2}: missing repo when drop=False"
                )
                continue

            # Canonical rule (our internal compare shape)
            if drop:
                rule = {"type": "drop"}
            else:
                rule = {
                    "type": rule_type or "KeyPresent",
                    "key": key,
                    "value": value,
                    "repo": repo_mapped,
                }

            groups.setdefault(name, []).append(rule)

        # Emit warnings once per policy for bad rows
        for pol, msgs in invalid_rows.items():
            log.warning(
                "apply: ignored %d invalid rule(s) for policy=%s: %s",
                len(msgs),
                pol,
                msgs,
            )

        # Yield desired rows
        for name, rules in groups.items():
            yield {
                "name": name,
                "active": bool(meta[name]["active"]),
                "catch_all": _norm_repo_name(meta[name]["catch_all"]),
                "rules": rules,
            }

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return desired_row["name"]

    # ---------------- Canonical shapes for diff ---------------------------- #
    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": desired_row.get("name", ""),
            "active": bool(desired_row.get("active", True)),
            "catch_all": desired_row.get("catch_all") or "",
            "rules": [self._canon_rule(r) for r in (desired_row.get("rules") or [])],
        }

    def canon_existing(self, existing_obj: Dict[str, Any] | None) -> Dict[str, Any] | None:
        if not existing_obj:
            return None
        pol = existing_obj.get("policy") or {}
        rules = pol.get("rules") or existing_obj.get("rules") or []
        catch = pol.get("catch_all") or existing_obj.get("catch_all") or ""
        return {
            "name": _norm_str(existing_obj.get("name") or existing_obj.get("policy_name")),
            "active": bool(existing_obj.get("active", True)),
            "catch_all": _norm_repo_name(catch),
            "rules": [self._canon_rule_from_api(rr) for rr in rules],
        }

    # -------------------- Read existing from API --------------------------- #
    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        """Return {policy_name -> policy_obj} for the node, fill repo cache."""
        node_t = _node_tag(node)
        log.info("fetch_existing: start [node=%s]", node_t)

        # Fill repos cache for this node (used to validate missing repos)
        self._repos_cache[node.id] = self._list_repos(client, pool_uuid, node)

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
        return out

    # -------------------- Payloads (API shape) ----------------------------- #
    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "policy_name": desired_row["name"],
            "active": bool(desired_row.get("active", True)),
            "policy": {
                "catch_all": desired_row.get("catch_all") or "",
                "rules": [self._rule_to_api(r) for r in (desired_row.get("rules") or [])],
            },
        }

    def build_payload_update(
        self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        # Same shape for PUT (id in URL)
        return self.build_payload_create(desired_row)

    # -------------------- Apply (uses RAW desired) ------------------------- #
    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        node_t = _node_tag(node)
        desired: Dict[str, Any] = dict(decision.desired or {})
        pol_name = desired.get("name") or "(unnamed)"

        log.info("apply: op=%s policy=%s [node=%s]", getattr(decision, "op", "?"), pol_name, node_t)

        # Validate referenced repos for this node
        missing = self._missing_repos(node.id, self._extract_used_repos(desired))
        if missing:
            log.warning(
                "apply: skipping policy=%s due to missing repos=%s [node=%s]",
                pol_name,
                sorted(missing),
                node_t,
            )
            return {"status": "Skipped", "result": {"missing_repos": sorted(missing)}}

        try:
            if decision.op == "CREATE":
                payload = self.build_payload_create(desired)
                log.info("apply: CREATE policy=%s [node=%s]", pol_name, node_t)
                res = client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
                return self._monitor_result(client, node, res, "create")

            if decision.op == "UPDATE" and existing_id:
                payload = self.build_payload_update(desired, {"id": existing_id})
                log.info("apply: UPDATE policy=%s id=%s [node=%s]", pol_name, existing_id, node_t)
                res = client.update_resource(
                    pool_uuid, node.id, self.RESOURCE, existing_id, payload
                )
                return self._monitor_result(client, node, res, "update")

            # NOOP/unknown fall-through
            log.info("apply: NOOP policy=%s [node=%s]", pol_name, node_t)
            return {"status": "Success"}

        except Exception:  # pragma: no cover — defensive
            log.exception("apply: API call failed for policy=%s [node=%s]", pol_name, node_t)
            raise

    # -------------------- Helpers: repos & rules --------------------------- #
    def _map_repo(self, repo_name: str, repo_map: Dict[str, str]) -> str:
        """Map repo name using the mapping table (if any)."""
        if not repo_name:
            return ""
        return repo_map.get(repo_name, repo_name)

    def _build_repo_name_map(self, sheets: Dict[str, pd.DataFrame]) -> Dict[str, str]:
        """Build {old_repo -> new_repo} from optional 'Repo' sheet."""
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
            k = _norm_repo_name(row.get(src))
            v = _norm_repo_name(row.get(dst))
            if k and v:
                mapping[k] = v
        if mapping:
            log.info("repo-map: loaded %d entries from sheet 'Repo'", len(mapping))
        return mapping

    def _list_repos(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> set:
        """Return the set of repo names existing on the given node."""
        names: set = set()
        try:
            data = client.list_resource(pool_uuid, node.id, "Repos") or {}
            items = (
                data.get("data")
                if isinstance(data, dict)
                else data  # accept list
            ) or []
            for it in items:
                nm = _norm_repo_name(it.get("name") or it.get("repo_name"))
                if nm:
                    names.add(nm)
        except Exception as e:  # pragma: no cover — defensive
            log.error("list_repos: failed [node=%s] err=%s", _node_tag(node), e)
        return names

    def _missing_repos(self, node_id: str, used_repos: Iterable[str]) -> set:
        have = self._repos_cache.get(node_id) or set()
        need = {r for r in used_repos if r}
        return need - have

    @staticmethod
    def _extract_used_repos(desired: Dict[str, Any]) -> List[str]:
        r: List[str] = []
        catch = desired.get("catch_all")
        if catch:
            r.append(str(catch))
        for rr in (desired.get("rules") or []):
            if isinstance(rr, dict) and rr.get("type", "").lower() != "drop":
                repo = rr.get("repo")
                if repo:
                    r.append(str(repo))
        # preserve order, unique
        out, seen = [], set()
        for x in r:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    @staticmethod
    def _canon_rule(r: Dict[str, Any]) -> Dict[str, Any]:
        t = (_norm_str(r.get("type")) or "KeyPresent").lower()
        if t == "drop":
            return {"type": "drop"}
        return {
            "type": "KeyPresentValueMatches" if t == "keypresentvaluematches" else "KeyPresent",
            "key": _norm_str(r.get("key")),
            "value": _norm_str(r.get("value")),
            "repo": _norm_repo_name(r.get("repo")),
        }

    @staticmethod
    def _canon_rule_from_api(rr: Dict[str, Any]) -> Dict[str, Any]:
        t = _norm_str(rr.get("type"))
        if t.lower() == "drop":
            return {"type": "drop"}
        return {
            "type": t or "KeyPresent",
            "key": _norm_str(rr.get("key")),
            "value": _norm_str(rr.get("value")),
            "repo": _norm_repo_name(rr.get("repo")),
        }

    @staticmethod
    def _rule_to_api(r: Dict[str, Any]) -> Dict[str, Any]:
        """Director expects: type, key, repo, and value only for KPVMatches."""
        if (_norm_str(r.get("type")) or "").lower() == "drop":
            return {"type": "drop"}
        out = {
            "type": _norm_str(r.get("type")) or "KeyPresent",
            "key": _norm_str(r.get("key")),
            "repo": _norm_repo_name(r.get("repo")),
        }
        if (out["type"] or "").lower() == "keypresentvaluematches":
            out["value"] = _norm_str(r.get("value"))
        return out

    # -------------------- Misc -------------------------------------------- #
    def _select_sheet(self, sheets: Dict[str, pd.DataFrame]) -> str:
        for c in self.sheet_names:
            if c in sheets:
                return c
        # Mirror previous user-facing error
        raise ValueError("Missing required sheets: RP or RoutingPolicy")

    @staticmethod
    def _monitor_result(
        client: DirectorClient,
        node: NodeRef,
        res: Dict[str, Any],
        action: str,
    ) -> Dict[str, Any]:
        """Standardize async monitor result like Repos importer."""
        status = "Success"
        mon_ok = None
        branch = None
        if isinstance(res, dict):
            branch = res.get("monitor_branch")
            mon_ok = res.get("monitor_ok")
            status = res.get("status") or status
        return {"status": status, "monitor_ok": mon_ok, "monitor_branch": branch}
