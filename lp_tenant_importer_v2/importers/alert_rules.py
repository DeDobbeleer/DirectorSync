
"""
Alert Rules Importer (patched)
- Adds per-node owner ID resolution (username/email -> internal user id)
- Caches lookups per node
- Skips gracefully when owner cannot be resolved
- Uses resolved owner_id in payload for create/update
- Keeps the rest of the trunk (validate -> fetch -> diff -> plan -> apply) assumptions
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

# Framework imports (expected by the project structure)
from .base import BaseImporter, NodeRef, Decision
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError

log = logging.getLogger(__name__)

RESOURCE = "AlertRules"
USER_RESOURCE_CANDIDATES: Tuple[str, ...] = (
    # Try common shapes seen across Director builds
    "Users",
    "Users/list",
    "Users/fetch",
    "User",
    "User/list",
)


# ------------------------- small helpers -------------------------

def _s(val: Any) -> str:
    return str(val).strip() if val is not None else ""

def _int_or_none(val: Any) -> Optional[int]:
    try:
        if val is None or (isinstance(val, str) and not val.strip()):
            return None
        return int(val)
    except Exception:
        return None

def _split_multi(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    s = str(val).strip()
    if not s:
        return []
    # allow both csv and ; separated lists
    parts = []
    for chunk in s.replace(";", ",").split(","):
        c = chunk.strip()
        if c:
            parts.append(c)
    return parts

def _normalize_repos(raw: Any, repo_map_df: Optional[pd.DataFrame]) -> List[str]:
    """
    Accept lists or csv strings; apply optional mapping from a 'Repo' sheet:
    - If repo_map_df provided and contains columns ['alias','value'], replace alias with value.
    """
    repos = _split_multi(raw)
    if not repos:
        return []
    if isinstance(repo_map_df, pd.DataFrame) and not repo_map_df.empty:
        lowmap = {}
        # allow various column namings
        cols = {c.lower(): c for c in repo_map_df.columns}
        alias_col = cols.get("alias") or cols.get("name") or list(repo_map_df.columns)[0]
        value_col = cols.get("value") or cols.get("repo") or list(repo_map_df.columns)[-1]
        for _, r in repo_map_df.iterrows():
            alias = _s(r.get(alias_col)).lower()
            value = _s(r.get(value_col))
            if alias and value:
                lowmap[alias] = value
        out = []
        for r in repos:
            out.append(lowmap.get(r.lower(), r))
        repos = out
    # final cleanup
    cleaned = [x for x in (str(r).strip() for r in repos) if x]
    return cleaned


# --------------------------- importer ----------------------------

class AlertRulesImporter(BaseImporter):
    """
    Importer implementing:
      - iter_desired(): build desired rows from sheets
      - fetch_existing(): list existing alerts (via DirectorClient)
      - diff(): provided by BaseImporter trunk, or overridden in the real project
      - apply(): create/update/noop for each node with owner resolution
    """

    def name(self) -> str:
        return "alert_rules"

    # ---------------- desired ----------------

    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        df: pd.DataFrame = sheets["Alert"].copy()

        repo_map_df: Optional[pd.DataFrame] = None
        maybe_repo = sheets.get("Repo")
        if isinstance(maybe_repo, pd.DataFrame):
            repo_map_df = maybe_repo

        for _, row in df.iterrows():
            name = _s(row.get("name"))
            if not name:
                continue
            desired: Dict[str, Any] = {
                "name": name,
                # Keep raw username/email; resolve per node during apply()
                "owner_login": _s(row.get("settings.user")),
                "risk": _s(row.get("settings.risk")),
                "aggregate": _s(row.get("settings.aggregate")),
                "condition_option": _s(row.get("settings.condition.condition_option")),
                "condition_value": _int_or_none(row.get("settings.condition.condition_value")) or 0,
                "limit": _int_or_none(row.get("settings.livesearch_data.limit")) or 0,
                "query": _s(row.get("settings.extra_config.query") or row.get("settings.livesearch_data.query")),
                "description": _s(row.get("settings.description")),
                "search_interval_minute": _int_or_none(row.get("settings.livesearch_data.search_interval_minute")) or 0,
                "flush_on_trigger": _s(row.get("settings.flush_on_trigger")).lower() in {"on", "true", "1", "yes"},
                "throttling_enabled": _s(row.get("settings.throttling_enabled")).lower() in {"on", "true", "1", "yes"},
                "throttling_field": _s(row.get("settings.throttling_field")),
                "throttling_time_range": _int_or_none(row.get("settings.throttling_time_range")) or 0,
                "log_source": _split_multi(row.get("settings.log_source")),
                "context_template": _s(row.get("settings.context_template")),
                "active": _s(row.get("settings.active")).lower() in {"on", "true", "1", "yes"},
                "repos_norm": _normalize_repos(row.get("settings.repos"), repo_map_df),
                # raw ranges (kept for conversion downstream, if any)
                "timerange_minute": _int_or_none(row.get("settings.livesearch_data.timerange_minute")),
                "timerange_hour": _int_or_none(row.get("settings.livesearch_data.timerange_hour")),
                "timerange_day": _int_or_none(row.get("settings.livesearch_data.timerange_day")),
                "timerange_second": _int_or_none(row.get("settings.livesearch_data.timerange_second") or row.get("settings.time_range_seconds")),
            }
            yield desired

    # ---------------- existing ----------------

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> List[Dict[str, Any]]:
        # Basic list; concrete implementation can adapt schemas if required
        try:
            raw = client.list_resource(pool_uuid, node.id, RESOURCE) or []
        except Exception as exc:
            log.error("fetch_existing failed [node=%s]: %s", node.name, exc)
            return []
        results: List[Dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = _s(item.get("name"))
            if not name:
                continue
            results.append({
                "id": _s(item.get("id") or item.get("_id")),
                "name": name,
            })
        log.info("fetch_existing: %d rules [node=%s]", len(results), node.name)
        return results

    # ---------------- payload builders ----------------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        owner_id = _s(desired_row.get("owner_id"))
        if not owner_id:
            raise ValidationError("owner is required (user id not resolved for target node)")

        repos = desired_row.get("repos_norm", [])
        if not isinstance(repos, list) or not repos or not all(isinstance(x, str) and x.strip() for x in repos):
            raise ValidationError("repos must be a non-empty list of strings")

        payload: Dict[str, Any] = {
            "searchname": desired_row["name"],
            "description": _s(desired_row.get("description")),
            "aggregate": _s(desired_row.get("aggregate")) or "max",
            "condition_option": _s(desired_row.get("condition_option")) or "greaterthan",
            "condition_value": int(desired_row.get("condition_value") or 0),
            "timerange_hour": int(desired_row.get("timerange_hour") or 1),
            "limit": int(desired_row.get("limit") or 100),
            "owner": owner_id,
            "query": _s(desired_row.get("query")),
            "flush_on_trigger": "on" if desired_row.get("flush_on_trigger") else "off",
            "repos": repos,
            "risk": _s(desired_row.get("risk")) or "low",
        }
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing: Dict[str, Any]) -> Dict[str, Any]:
        # For simplicity, reuse the same structure; real diffing can be applied in BaseImporter
        payload = self.build_payload_create(desired_row)
        # The API may require name/immutable fields handling; adjust if your backend differs
        return payload

    # ---------------- apply ----------------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision: Decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        desired = decision.desired or {}
        name = _s(desired.get("name")) or "(unnamed)"

        # ----- per-node owner resolution -----
        try:
            cache: Dict[str, str] = getattr(self, "_owner_cache", {})
            if not isinstance(cache, dict):
                cache = {}
                setattr(self, "_owner_cache", cache)

            owner_login = _s(desired.get("owner_login"))
            if owner_login:
                cache_key = f"{node.id}:{owner_login.lower()}"
                if cache_key in cache:
                    desired["owner_id"] = cache[cache_key]
                else:
                    uid = self._resolve_owner_id_for_node(client, pool_uuid, node, owner_login)
                    if uid:
                        cache[cache_key] = uid
                        desired["owner_id"] = uid
                    else:
                        msg = f"owner '{owner_login}' not found/unique on node={node.name}"
                        log.warning("SKIP %s alert=%s [node=%s] reason=%s", decision.op, name, node.name, msg)
                        return {"status": "Skipped", "reason": msg}
            else:
                owner_id_ctx = _s(desired.get("owner_id") or desired.get("owner"))
                if owner_id_ctx:
                    desired["owner_id"] = owner_id_ctx
                else:
                    msg = "missing settings.user and no owner id in context"
                    log.warning("SKIP %s alert=%s [node=%s] reason=%s", decision.op, name, node.name, msg)
                    return {"status": "Skipped", "reason": msg}
        except Exception as e:
            log.error("owner resolution failed for alert=%s [node=%s]: %s", name, node.name, e)
            return {"status": "Failed", "error": f"owner resolution error: {e}"}

        # ----- standard apply -----
        try:
            if decision.op == "CREATE":
                try:
                    payload = self.build_payload_create(desired)
                except ValidationError as ve:
                    log.warning("SKIP CREATE alert=%s [node=%s] reason=%s (no API call)", name, node.name, ve)
                    return {"status": "Skipped", "reason": str(ve)}
                log.info("CREATE alert=%s [node=%s]", name, node.name)
                log.debug("CREATE payload=%s", payload)
                return client.create_resource(pool_uuid, node.id, RESOURCE, payload)

            if decision.op == "UPDATE" and existing_id:
                try:
                    payload = self.build_payload_update(desired, {"id": existing_id})
                except ValidationError as ve:
                    log.warning("SKIP UPDATE alert=%s id=%s [node=%s] reason=%s (no API call)", name, existing_id, node.name, ve)
                    return {"status": "Skipped", "reason": str(ve)}
                log.info("UPDATE alert=%s id=%s [node=%s]", name, existing_id, node.name)
                log.debug("UPDATE payload=%s", payload)
                return client.update_resource(pool_uuid, node.id, RESOURCE, existing_id, payload)

            log.info("NOOP alert=%s [node=%s]", name, node.name)
            return {"status": "Success"}

        except Exception as exc:
            msg = str(exc)
            log.error("APPLY FAILED alert=%s [node=%s]: %s", name, node.name, msg)
            return {"status": "Failed", "error": msg}

    # ---------------- owner lookup ----------------

    def _resolve_owner_id_for_node(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        login_or_email: str,
    ) -> str:
        """
        Resolve a user's internal id for the given *node* from a username or email.
        Strategy:
          1) Query user collections from likely endpoints (USER_RESOURCE_CANDIDATES).
          2) Prefer exact match on 'username' (case-insensitive), else on 'email'.
          3) Return a single id only if unique; otherwise return "" to force a SKIP.
        """
        users: List[Dict[str, Any]] = []
        for res in USER_RESOURCE_CANDIDATES:
            try:
                path = client.configapi(pool_uuid, node.id, res)
                data = client.get_json(path) or {}
                if isinstance(data, list):
                    users = data
                elif isinstance(data, dict):
                    for key in ("items", "results", "data"):
                        val = data.get(key)
                        if isinstance(val, list):
                            users = val
                            break
                if users:
                    break
            except Exception as exc:
                log.debug("owner lookup: %s not usable on node=%s: %s", res, node.name, exc)
                continue

        if not users:
            return ""

        want = login_or_email.strip().lower()

        def _fld(u: Dict[str, Any], key: str) -> str:
            v = u.get(key)
            return str(v).strip() if v is not None else ""

        matches: List[str] = []
        for u in users:
            if not isinstance(u, dict):
                continue
            uname = _fld(u, "username").lower()
            email = _fld(u, "email").lower()
            if uname == want or (email and email == want):
                uid = _fld(u, "_id") or _fld(u, "id")
                if uid:
                    matches.append(uid)

        uniq = sorted(set(matches))
        if len(uniq) == 1:
            return uniq[0]
        return ""


__all__ = ["AlertRulesImporter"]
