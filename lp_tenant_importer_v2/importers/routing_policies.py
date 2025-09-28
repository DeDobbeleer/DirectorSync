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
    Routing Policies importer (V2) implémentant le spec final :

    - Feuille : première existante parmi 'RoutingPolicy' ou 'RP'.
    - Colonnes requises (case-insensitive) : cleaned_policy_name, catch_all,
      rule_type, key, value, repo, drop. La colonne 'active' du XLSX est ignorée.
    - Feuille 'Repo' optionnelle : original_repo_name -> cleaned_repo_name,
      mapping appliqué UNIQUEMENT si la valeur d’entrée n’est pas vide.

    Typage des lignes :
      * Type 1 ("catch-all only") : TOUTES les colonnes de règle vides
        (rule_type, key, value, repo, drop) -> aucune règle créée pour la ligne.
      * Type 2 ("catch-all + règles") : si AU MOINS un de (rule_type, key, value, drop)
        est présent, la ligne définit une règle. Elle est valide SSI rule_type, key,
        value, drop sont tous non vides. 'repo' est optionnel.
        - 'drop' est REQUIS mais sans sémantique côté import : on le transmet tel quel.

    Payload API (création/mise à jour) :
      {
        "policy_name": <name>,
        "active": true,                 # 'active' du fichier est ignoré
        "catch_all": <mapped_or_empty>,
        "routing_criteria": [ ... dans l'ordre Excel ... ]
      }

    Décision SKIP (par policy) :
      repos_to_check = [catch_all si non vide] + [chaque rule.repo non vide]
      missing = repos_to_check - repos_disponibles_sur_le_noeud
      si missing != ∅ : SKIPPED (warning + détail).
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
        "drop",  # requis pour valider une règle ; pas de sémantique côté import
    )
    # On diff sur ces clés canoniques (voir canon_*).
    compare_keys = ("name", "catch_all", "routing_criteria")

    # Director API resource name
    RESOURCE = "RoutingPolicies"

    def __init__(self) -> None:
        super().__init__()
        self._active_sheet: Optional[str] = None
        self._repo_map: Dict[str, str] = {}
        self._repos_cache: Dict[str, set] = {}  # node.id -> set(repo names)
        self._first_catch_all: Dict[str, str] = {}  # pour warn si changement intra-policy

    # ------------------------------ Validate ------------------------------ #
    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        sheet = self._select_sheet(sheets)
        self._active_sheet = sheet
        df = sheets[sheet]

        # Required columns (avec context si disponible)
        try:
            require_columns(df, self.required_columns, context=f"sheet '{sheet}'")
        except TypeError:
            require_columns(df, self.required_columns)

        # Repo mapping si présent
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
        (NB: on garde 'rules' en interne ; la conversion API -> 'routing_criteria'
         est faite dans build_payload_* et canon_desired)
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

            # Init policy (première occurrence)
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
                # Warn si catch_all change (on garde le premier)
                prev = self._first_catch_all.get(policy_name, "")
                now = self._map_repo_if_non_empty(_norm_str(row.get(col("catch_all"))))
                if now and now != prev:
                    log.warning(
                        "catch_all changed for policy=%s; first wins (prev=%s, new=%s)",
                        policy_name, prev, now
                    )

            # Lecture des champs de règle
            rule_type = _norm_str(row.get(col("rule_type")))
            key = _norm_str(row.get(col("key")))
            value = _norm_str(row.get(col("value")))
            repo_raw = _norm_str(row.get(col("repo")))
            repo_mapped = self._map_repo_if_non_empty(repo_raw)
            drop_val = _norm_str(row.get(col("drop")))

            # Type 1 : ligne sans règle
            is_no_rule_line = (rule_type == "" and key == "" and value == "" and repo_raw == "" and drop_val == "")
            if is_no_rule_line:
                continue

            # Type 2 : ligne "définie"
            core_present = any(x != "" for x in (rule_type, key, value, drop_val))
            if not core_present:
                continue

            # Validation : 4 champs requis (repo optionnel)
            if not all(x != "" for x in (rule_type, key, value, drop_val)):
                invalid_rows.append(
                    (policy_name, idx + 2, "require rule_type, key, value, drop (repo optional)")
                )
                continue

            # Construction de la règle (on CONSERVE 'drop' tel quel)
            rule: Dict[str, Any] = {
                "type": rule_type,
                "key": key,
                "value": value,
                "drop": drop_val,  # obligatoire mais sans sémantique côté import
            }
            if repo_mapped:
                rule["repo"] = repo_mapped

            policies[policy_name]["rules"].append(rule)

        # Warnings lignes invalides
        for pol, rowno, reason in invalid_rows:
            log.warning("invalid rule at row %d for policy=%s: %s", rowno, pol, reason)

        # Rendement déterministe (règles gardent l'ordre Excel)
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
        """Canonical shape used by the diff engine (alignée sur l’API V1)."""
        return {
            "name": desired_row.get("name", ""),
            "catch_all": desired_row.get("catch_all") or "",
            "routing_criteria": [self._canon_rule(r) for r in (desired_row.get("rules") or [])],
        }

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Canonicalize an existing object from Director API."""
        if not existing_obj:
            return None

        # L’API peut répondre avec des champs à la racine ou sous 'policy'
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
        """Payload API V1-compat: catch_all & routing_criteria à la racine."""
        payload = {
            "policy_name": desired_row["name"],
            "active": True,  # 'active' du XLSX est ignoré fonctionnellement
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

        # Repos à vérifier : catch_all + repos explicites des règles
        missing = self._missing_repos(node.id, self._repos_to_check(desired))
        if missing:
            miss_sorted = sorted(missing)
            log.warning(
                "apply: skipping policy=%s due to missing repos=%s [node=%s]",
                pol_name, miss_sorted, node_t
            )
            return {"status": "Skipped", "result": {"missing_repos": miss_sorted}, "error": miss_sorted}

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
        """Canonicalize a desired rule (incluant 'drop' tel quel)."""
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
        'drop' est requis mais sans sémantique côté import ; 'repo' optionnel.
        """
        out = {
            "type": _norm_str(r.get("type")) or "KeyPresent",
            "key": _norm_str(r.get("key")),
            "drop": _norm_str(r.get("drop")),   # valeur telle que dans l’Excel
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
        Repos à vérifier : catch_all (si non vide) + tous les rule.repo non vides.
        """
        repos: List[str] = []
        catch = _norm_str(desired.get("catch_all"))
        if catch:
            repos.append(catch)
        for rr in (desired.get("rules") or []):
            repo = _norm_str(rr.get("repo"))
            if repo:
                repos.append(repo)

        # Ordre préservé + dédup
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
        client: DirectorClient,  # noqa: ARG002 (parité avec Repos importer)
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
