# lp_tenant_importer_v2/importers/routing_policies.py
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple, Set, Mapping, Optional
import math
import unicodedata
import re
import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..core.logging_utils import get_logger
from ..importers.base import BaseImporter
from ..utils.diff_engine import Decision
from ..utils.validators import ValidationError, require_columns, require_sheets

log = get_logger(__name__)


class RoutingPoliciesImporter(BaseImporter):
    """
    Importer for Routing Policies (Director API 2.7).

    Excel:
      - Sheet name: "RoutingPolicy" (preferred). "RP" is also accepted for backward compatibility.
      - Expected columns (one row per rule; rows are grouped by policy):
          * cleaned_policy_name  (policy identifier; required)
          * catch_all            (boolean-like; can be repeated across rows of the same policy)
          * rule_type            (criterion type; e.g., contains/equals/...; may be empty if relying on catch_all)
          * key                  (normalized field name; may be empty if relying on catch_all)
          * value                (value/pattern; may be empty if relying on catch_all)
          * repo                 (destination repository name; required when a rule is defined)
          * drop                 ('store' or 'drop'; defaults to 'store' if empty)

    API model:
      {
        "policy_name": "<string>",
        "catch_all": <bool>,
        "routing_criteria": [
          {"type": "<str>", "key": "<str>", "value": "<str>", "repo": "<str>", "drop": "store|drop"},
          ...
        ]
      }

    Notes:
      - The canonical comparison ignores rule order and normalizes strings.
      - The payload for UPDATE is the same as for CREATE (id travels in URL).
      - We do not translate repo names to IDs here (Director accepts repo name in criteria).
    """

    # ---- wiring ----
    RESOURCE: str = "RoutingPolicies"  # configapi resource segment
    SHEET_NAMES: Tuple[str, ...] = ("RoutingPolicy", "RP")
    REQUIRED_COLUMNS: Tuple[str, ...] = (
        "cleaned_policy_name",
        "catch_all",
        "rule_type",
        "key",
        "value",
        "repo",
        "drop",
    )
    # Fields used by the diff engine to decide NOOP/UPDATE
    COMPARE_KEYS: Tuple[str, ...] = ("catch_all", "routing_criteria")
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # cache of repos per node id
        self._repos_cache: Dict[str, Set[str]] = {}
        # global repo name mapping loaded from the Repos sheet (source -> destination)
        self._repo_map: Dict[str, str] = {}

    # ------------- helpers -------------

    @staticmethod
    def _to_bool(x: Any) -> bool:
        if isinstance(x, bool):
            return x
        s = str(x).strip().lower()
        return s in {"1", "true", "yes", "y", "on"}

    @staticmethod
    def _norm(x: Any) -> str:
        return str(x or "").strip()
    
    @staticmethod
    def _norm_key(x: Any) -> Optional[str]:
        """
        Normalize a value to a comparable key.
        - Returns None for None/NaN/empty/"nan"/"null"/"none"/"-"
        - Lowercases, trims, de-accents, collapses spaces.
        """
        if x is None:
            return None
        if isinstance(x, float) and math.isnan(x):
            return None
        s = str(x).strip()
        if s == "" or s.lower() in {"nan", "none", "null", "-"}:
            return None
        s = unicodedata.normalize("NFKD", s)
        s = "".join(ch for ch in s if not unicodedata.combining(ch))
        s = re.sub(r"\s+", " ", s).strip().casefold()
        return s or None

    @classmethod
    def _canon_rules(cls, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Canonicalize a list of rule dicts:
          - normalize strings
          - default drop -> 'store'
          - ignore entirely empty rows
          - sort by (type, key, value, repo, drop)
        """
        canon: List[Dict[str, Any]] = []
        for r in rules or []:
            t = cls._norm(r.get("type"))
            k = cls._norm(r.get("key"))
            v = cls._norm(r.get("value"))
            repo = cls._norm(r.get("repo"))
            drop = cls._norm(r.get("drop")) or "store"
            if not any([t, k, v, repo, drop]):
                continue
            canon.append({"type": t, "key": k, "value": v, "repo": repo, "drop": drop})

        def sort_key(it: Dict[str, Any]):
            return (
                it["type"].lower(),
                it["key"].lower(),
                it["value"],
                it["repo"].lower(),
                it["drop"].lower(),
            )

        return sorted(canon, key=sort_key)

    @staticmethod
    def _build_name_map(df: "pd.DataFrame",
                        candidate_pairs: List[Tuple[str, str]]) -> Dict[str, str]:
        """
        Build a {normalized_source -> cleaned_destination} map from a DataFrame,
        trying multiple (source_col, dest_col) pairs in order.
        """
        for src_col, dst_col in candidate_pairs:
            if src_col in df.columns and dst_col in df.columns:
                tmp = df[[src_col, dst_col]].copy()
                tmp["__k"] = tmp[src_col].map(RoutingPoliciesImporter._norm_key)
                tmp = tmp.dropna(subset=["__k", dst_col])
                mapping = dict(
                    tmp.drop_duplicates("__k", keep="last").set_index("__k")[dst_col]
                )
                if mapping:
                    return mapping
        return {}

    def _resolve_repo(self, raw_name: Any) -> str:
        """
        Resolve a repo name from Excel using self._repo_map.
        If not in the mapping, return a stripped string fallback (or "").
        """
        k = self._norm_key(raw_name)
        if k is None:
            return ""
        mapped = self._repo_map.get(k)
        if mapped:
            return str(mapped).strip()
        # fallback: keep original as-is but stripped
        return str(raw_name).strip()

    # ------------- BaseImporter overrides -------------
    
    def load_xlsx(self, xlsx_path: str) -> Dict[str, pd.DataFrame]:
        """Read all sheets; keep API consistent with BaseImporter contract."""
        try:
            return pd.read_excel(xlsx_path, sheet_name=None, engine="openpyxl")
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"Failed to read {xlsx_path}: {exc}") from exc
 
    def _load_repo_map_from_sheets(self, sheets: Dict[str, "pd.DataFrame"]) -> None:
        """
        Build self._repo_map from the 'Repos' sheet.
        Default pair: ('original_policy_name', 'cleaned_policy_name') as requested.
        You can add more pairs if your sheet evolves.
        """
        repo_sheet = None
        for name in sheets.keys():
            if str(name).strip().lower() == "repos":
                repo_sheet = name
                break

        if not repo_sheet:
            log.debug("routing_policies: no 'Repos' sheet found; repo mapping disabled")
            self._repo_map = {}
            return

        df = sheets[repo_sheet]
        pairs = [
            ("original_policy_name", "cleaned_policy_name"),
            # You can add future pairs here if needed:
            # ("original_repo_name", "cleaned_repo_name"),
            # ("source_name", "dest_name"),
        ]
        self._repo_map = self._build_name_map(df, pairs)
        log.debug("routing_policies: repo map loaded (%d entries)", len(self._repo_map))
 
    def validate(self, sheets: Dict[str, "pd.DataFrame"]) -> None:
        """
        Overridden to also load the repo name mapping from the 'Repos' sheet.
        """
        # Existing validation on sheet presence (RoutingPolicy / RP / etc.)
        sheet_name = self._pick_sheet(sheets)
        log.info("routing_policies: using sheet '%s'", sheet_name)

        # Load repo name mapping for destination resolution
        self._load_repo_map_from_sheets(sheets)

    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """Fetch existing policies from Director and index them by policy_name."""
        log.info("fetch_existing: start [node=%s|%s]", node.name, node.id)
        raw = client.list_resource(pool_uuid, node.id, self.RESOURCE) or {}

        # Director responses can be a list or a dict with various keys
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = (
                raw.get("routing_policies")
                or raw.get("data")
                or raw.get("RoutingPolicy")
                or raw
            )
            if isinstance(items, dict):
                items = items.get("data", [])
        else:
            items = []

        result: Dict[str, Dict[str, Any]] = {}
        for it in items or []:
            name = self._norm((it or {}).get("policy_name"))
            if name:
                result[name] = it

        log.info("fetch_existing: found %d policies [node=%s|%s]", len(result), node.name, node.id)
        return result

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        """
        Yield desired RP objects from the selected sheet, with repo names
        resolved via the XLSX mapping before any existence check or payload build.
        """
        sheet_name = self._pick_sheet(sheets)
        df = sheets[sheet_name].copy()

        missing = [c for c in self.REQUIRED_COLUMNS if c not in df.columns]
        if missing:
            raise ValidationError(
                f"Missing required columns on sheet '{sheet_name}': {missing}"
            )

        for policy_name, grp in df.groupby("cleaned_policy_name", dropna=False):
            name = self._norm_str(policy_name)
            if not name:
                first_idx = int(grp.index.min())
                raise ValidationError(
                    f"Sheet '{sheet_name}' row {first_idx + 2}: empty 'cleaned_policy_name'"
                )

            first = grp.iloc[0]
            active = self._to_bool(first.get("active"))

            # Resolve catch_all via map
            catch_all_resolved = self._resolve_repo(first.get("catch_all"))

            criteria: List[Dict[str, Any]] = []
            ignored_reasons: List[str] = []

            for idx, row in grp.iterrows():
                key = self._norm_str(row.get("key"))
                value = self._norm_str(row.get("value"))
                drop = self._to_bool(row.get("drop"))

                # Resolve repo via map (may be "")
                repo_resolved = self._resolve_repo(row.get("repo"))

                if not any([key, value, repo_resolved, drop]):
                    continue

                if not key:
                    ignored_reasons.append(f"row {idx + 2}: missing key")
                    continue

                ctype = "KeyPresentValueMatches" if value else "KeyPresent"

                if drop:
                    crit = {"type": ctype, "key": key, "drop": True}
                    if value:
                        crit["value"] = value
                    criteria.append(crit)
                else:
                    if not repo_resolved:
                        ignored_reasons.append(
                            f"row {idx + 2}: missing repo when drop=False"
                        )
                        continue
                    crit = {"type": ctype, "key": key, "drop": False, "repo": repo_resolved}
                    if value:
                        crit["value"] = value
                    criteria.append(crit)

            desired = {
                "policy_name": name,
                "active": bool(active),
                "catch_all": catch_all_resolved,  # already resolved
                "routing_criteria": criteria,      # repos already resolved
                "_ignored": ignored_reasons,
            }
            yield desired

    @staticmethod
    def _collect_required_repos(desired_row: Dict[str, Any]) -> Set[str]:
        needed: Set[str] = set()
        ca = desired_row.get("catch_all") or ""
        if ca:
            needed.add(str(ca))

        for it in desired_row.get("routing_criteria") or []:
            if not isinstance(it, dict):
                continue
            if bool(it.get("drop")):
                continue
            repo = it.get("repo") or ""
            if repo:
                needed.add(str(repo))

        return needed

    def _list_repos(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Set[str]:
        if node.id in self._repos_cache:
            log.debug(
                "list_repos: cache hit (%d repos) [node=%s|%s]",
                len(self._repos_cache[node.id]), node.name, node.id
            )
            return self._repos_cache[node.id]

        node_tag = f"{node.name}|{node.id}"
        try:
            raw = client.list_resource(pool_uuid, node.id, "Repos") or {}
        except Exception:
            log.exception("list_repos: failed to list repos [node=%s]", node_tag)
            raise

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
        log.debug(
            "list_repos: cache miss -> cached %d repos [node=%s]", len(names), node_tag
        )
        return names

    # ---- diff / canonicalization ----

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return self._norm(desired_row.get("policy_name"))

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "catch_all": bool(desired_row.get("catch_all")),
            "routing_criteria": self._canon_rules(desired_row.get("routing_criteria") or []),
        }

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        if not existing_obj:
            return {}
        return {
            "catch_all": bool(existing_obj.get("catch_all")),
            "routing_criteria": self._canon_rules(existing_obj.get("routing_criteria") or []),
        }

    # ---- payloads & apply ----

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "policy_name": self.key_fn(desired_row),
            "catch_all": bool(desired_row.get("catch_all")),
            "routing_criteria": self._canon_rules(desired_row.get("routing_criteria") or []),
        }

    def build_payload_update(
        self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        # Same structure as POST; id is passed in URL by the client
        return self.build_payload_create(desired_row)

    def apply(  # noqa: D401 (docstring inherited from BaseImporter)
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision: Decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        op = decision.op
        name = self.key_fn(decision.desired)

        if op == "CREATE":
            log.info(
                "apply: CREATE policy=%s [node=%s|%s]", name, node.name, node.id
            )
            payload = self.build_payload_create(decision.desired)
            return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)

        if op == "UPDATE":
            if not existing_id:
                raise ValidationError(f"Cannot UPDATE policy={name}: missing existing id")
            log.info(
                "apply: UPDATE policy=%s id=%s [node=%s|%s]", name, existing_id, node.name, node.id
            )
            payload = self.build_payload_update(decision.desired, {})
            return client.update_resource(
                pool_uuid, node.id, self.RESOURCE, existing_id, payload
            )

        if op in ("NOOP", "SKIP"):
            log.debug("apply: %s policy=%s [node=%s|%s]", op, name, node.name, node.id)
            # Keep return shape compatible with BaseImporter/reporting
            return {"status": "—", "monitor_ok": None}

        raise ValidationError(f"Unsupported decision op: {op}")
