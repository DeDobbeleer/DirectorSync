from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from ..core.config import ImportContext
from ..core.director_client import DirectorClient
from ..utils.validators import bool_from_cell, int_from_cell, non_empty_str, list_from_cell, norm_str

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------------------
@dataclass
class AlertRuleRow:
    """Structured view of one Excel row for an Alert Rule."""
    name: str
    searchname: str
    risk: str
    owner: str
    aggregate: str
    condition_option: str
    condition_value: int
    limit: int
    flush_on_trigger: str
    timerange_day: int
    timerange_hour: int
    timerange_minute: int
    query: str
    repos: List[str]
    log_source: List[str]


# --------------------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------------------
def _safe_int(value: Any, field: str) -> int:
    """Force int conversion with explicit error for better debug."""
    try:
        if value is None or value == "":
            raise ValueError("empty")
        if isinstance(value, (int,)):
            return int(value)
        if isinstance(value, float):
            if value.is_integer():
                return int(value)
            raise ValueError(f"non-integer float {value!r}")
        return int(str(value).strip())
    except Exception as e:
        raise ValueError(f"Invalid integer in column '{field}': {value!r} ({e})") from e


def _split_comma_list(cell: Any) -> List[str]:
    """
    Accept:
      - Python/JSON list-like strings: '["repo1","repo2"]'
      - Comma-separated plain string: 'repo1, repo2'
      - Already-a-list value
    Returns a normalized list[str].
    """
    if cell is None:
        return []
    if isinstance(cell, list):
        return [norm_str(x) for x in cell if norm_str(x)]
    s = str(cell).strip()
    if not s:
        return []
    # Try JSON list first
    if s.startswith("[") and s.endswith("]"):
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [norm_str(x) for x in parsed if norm_str(x)]
        except Exception:
            # fall back to split below
            pass
    # Fallback: comma-separated
    return [norm_str(x) for x in s.split(",") if norm_str(x)]


def _normalize_repos(cell: Any) -> List[str]:
    """
    Normalize repos to bare strings (no nested quotes, no list-as-string).
    Example inputs:
      '["10.1.2.3:5504/Repo-A","10.2.3.4:5504/Repo-B"]'
      '10.1.2.3:5504/Repo-A, 10.2.3.4:5504/Repo-B'
      ['10.1.2.3:5504/Repo-A', '10.2.3.4:5504/Repo-B']
    """
    items = _split_comma_list(cell)
    # Remove surrounding quotes if user put '"value"' style
    cleaned: List[str] = []
    for it in items:
        v = it.strip()
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = v[1:-1].strip()
        if v.startswith("'") and v.endswith("'") and len(v) >= 2:
            v = v[1:-1].strip()
        if v:
            cleaned.append(v)
    return cleaned


def _normalize_log_source(cell: Any) -> List[str]:
    """
    Same normalization as repos, but empty list is allowed/meaningful.
    """
    return _normalize_repos(cell)


def _must_get(d: Dict[str, Any], key: str) -> Any:
    """Raise with a helpful message if key missing."""
    if key not in d:
        raise KeyError(f"Missing required column '{key}' in Excel row")
    return d[key]


def _owner_to_id(owner_name: str, users: List[Dict[str, Any]]) -> Optional[str]:
    """
    Find a user id by its username (case-insensitive).
    If not found: return None.
    """
    target = owner_name.strip().lower()
    for u in users:
        uname = str(u.get("username", "")).lower()
        if uname == target:
            return str(u.get("_id"))
    return None


def _collect_row(data: Dict[str, Any]) -> AlertRuleRow:
    """
    Map Excel row to AlertRuleRow with strict typing and PEP8-friendly, self-documented fields.
    Required columns are enforced; errors are explicit and actionable.
    """
    name = non_empty_str(_must_get(data, "name"), "name")
    searchname = non_empty_str(_must_get(data, "searchname"), "searchname")
    risk = non_empty_str(_must_get(data, "risk"), "risk").lower()
    owner = non_empty_str(_must_get(data, "owner"), "owner")
    aggregate = non_empty_str(_must_get(data, "aggregate"), "aggregate").lower()
    condition_option = non_empty_str(_must_get(data, "condition_option"), "condition_option").lower()
    condition_value = _safe_int(_must_get(data, "condition_value"), "condition_value")
    limit = _safe_int(_must_get(data, "limit"), "limit")
    flush_on_trigger = non_empty_str(_must_get(data, "flush_on_trigger"), "flush_on_trigger").lower()

    # official columns for time range
    timerange_day = _safe_int(_must_get(data, "timerange_day"), "timerange_day")
    timerange_hour = _safe_int(_must_get(data, "timerange_hour"), "timerange_hour")
    timerange_minute = _safe_int(_must_get(data, "timerange_minute"), "timerange_minute")

    # official column for the Query (settings.extra_config.query)
    query = non_empty_str(_must_get(data, "settings.extra_config.query"), "settings.extra_config.query")

    # repos and log_source must be list[str] (API expects an array of plain strings)
    repos = _normalize_repos(_must_get(data, "repos"))
    log_source = _normalize_log_source(_must_get(data, "log_source"))

    return AlertRuleRow(
        name=name,
        searchname=searchname,
        risk=risk,
        owner=owner,
        aggregate=aggregate,
        condition_option=condition_option,
        condition_value=condition_value,
        limit=limit,
        flush_on_trigger=flush_on_trigger,
        timerange_day=timerange_day,
        timerange_hour=timerange_hour,
        timerange_minute=timerange_minute,
        query=query,
        repos=repos,
        log_source=log_source,
    )


def _row_to_payload(row: AlertRuleRow, owner_id: str) -> Dict[str, Any]:
    """
    Convert a validated row into a Director API payload.
    All keys/shape follow the AlertRules Config API (v2.6+).
    """
    payload: Dict[str, Any] = {
        "name": row.name,
        "owner": owner_id,
        "risk": row.risk,
        "aggregate": row.aggregate,
        "condition_option": row.condition_option,
        "condition_value": row.condition_value,
        "limit": row.limit,
        "searchname": row.searchname,
        "timerange_day": row.timerange_day,
        "timerange_hour": row.timerange_hour,
        "timerange_minute": row.timerange_minute,
        "flush_on_trigger": row.flush_on_trigger,
        "query": row.query,
        # These two must be arrays of strings. (No JSON-encoded strings)
        "repos": row.repos,
        "log_source": row.log_source,
    }
    return payload


# --------------------------------------------------------------------------------------
# Importer
# --------------------------------------------------------------------------------------
class AlertRulesImporter:
    """
    Importer for Alert Rules that conforms to the v2 framework:
      - Read/validate Excel rows
      - Resolve dependencies (owner -> id via Users API)
      - Create resources via DirectorClient
      - Monitor via monitorapi URL
      - NO fallbacks: if a required field is missing in Excel, we SKIP and log
    """

    SHEET = "alert_rules"

    def __init__(self, ctx: ImportContext, director: DirectorClient) -> None:
        self.ctx = ctx
        self.director = director
        self.users_cache: Dict[str, List[Dict[str, Any]]] = {}  # by node name/id

    # ----------------------------- Users dependency -----------------------------
    def _load_users_for_node(self, node_id: str, node_name: str) -> List[Dict[str, Any]]:
        """
        Fetch and cache users for a given node (tenant node id).
        We use the Config API: GET /{pool}/{node}/Users
        """
        cache_key = node_name
        if cache_key in self.users_cache:
            return self.users_cache[cache_key]

        url = f"configapi/{self.ctx.pool_uuid}/{node_id}/Users"
        resp = self.director.get(url)
        users = resp.json() if hasattr(resp, "json") else resp
        if not isinstance(users, list):
            log.warning("Unexpected Users response for node=%s: %r", node_name, users)
            users = []
        self.users_cache[cache_key] = users
        log.debug("Users cache loaded: node=%s size=%d", node_name, len(users))
        return users

    def _resolve_owner(self, owner: str, users: List[Dict[str, Any]], node_name: str) -> Optional[str]:
        """
        Resolve owner name to its Logpoint ID by scanning the Users list.
        If not found: return None (caller will SKIP the row).
        """
        user_id = _owner_to_id(owner, users)
        if user_id:
            log.info("owner resolved: %r -> id=%s [node=%s]", owner, user_id, node_name)
        else:
            log.warning("Unknown owner %r on node=%s -> SKIP", owner, node_name)
        return user_id

    # ----------------------------- Existing rules -----------------------------
    def fetch_existing(self, node_id: str, node_name: str) -> List[Dict[str, Any]]:
        """
        Fetch existing rules by using the official "fetchMyRules" endpoint.
        This is a POST with no payload, returning a monitor URL; we must monitor the job.
        """
        try:
            # Per framework: do not call requests directly; go via DirectorClient + monitor job.
            # See docs: POST /{pool}/{node}/AlertRules/fetchMyRules
            url = f"configapi/{self.ctx.pool_uuid}/{node_id}/AlertRules/fetchMyRules"
            log.debug("Fetching existing alert rules via %s", url)

            # For fetchMyRules, the API expects POST with an empty JSON payload.
            post_resp = self.director.post(url, data={})
            monitor_url = self.director.extract_monitor_url(post_resp)
            if not monitor_url:
                log.warning("fetch_existing: monitor URL not found in response [node=%s]", node_name)
                return []

            result = self.director.monitor_job_url(monitor_url, node_id=node_id)
            data = result.get("response") or {}
            # The result shape can vary; make it defensive.
            rules = data.get("data") or data.get("rules") or []
            if not isinstance(rules, list):
                log.warning("fetch_existing: unexpected payload shape [node=%s]: %r", node_name, data)
                return []

            log.info("fetch_existing: %d rules [node=%s]", len(rules), node_name)
            if log.isEnabledFor(logging.DEBUG):
                log.debug("fetch_existing: DEBUG dump of payload [node=%s]: %s", node_name, json.dumps(data, ensure_ascii=False))
            return rules

        except Exception as e:
            log.warning("fetch_existing failed [node=%s]: %s", node_name, e)
            log.info("fetch_existing: 0 rules [node=%s]", node_name)
            return []

    # ----------------------------- Apply (create/update) -----------------------------
    def apply(self, node_id: str, node_name: str, rows: List[Dict[str, Any]]) -> List[Tuple[str, str, str, str, Optional[str]]]:
        """
        Apply the desired state from Excel rows.
        Returns a list of tuples for reporting:
          (siem, node, name, action, status_or_error)
        """
        results: List[Tuple[str, str, str, str, Optional[str]]] = []

        # Preload dependencies
        users = self._load_users_for_node(node_id, node_name)

        # (Optional) existing rules set — currently unused but ready for future "update" logic
        _existing = self.fetch_existing(node_id, node_name)

        for raw in rows:
            try:
                row = _collect_row(raw)

                # Resolve owner
                owner_id = self._resolve_owner(row.owner, users, node_name)
                if not owner_id:
                    results.append((self.ctx.siem_uuid, node_name, row.name, "create", "Skipped (unknown owner)"))
                    continue

                payload = _row_to_payload(row, owner_id)
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("new collected and normalized payload: %s", payload)

                # For now we only support CREATE (no ID from Excel to match)
                log.info("CREATE alert=%s [node=%s]", row.name, node_name)
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("CREATE payload=%s", payload)

                # API call + monitor via framework
                create_url = f"configapi/{self.ctx.pool_uuid}/{node_id}/AlertRules"
                resp = self.director.create_resource(
                    pool_uuid=self.ctx.pool_uuid,
                    node_id=node_id,
                    resource="AlertRules",
                    data=payload
                )

                # The DirectorClient.create_resource() already monitors and returns a final status,
                # but we keep the line-by-line reporting consistent with other importers.
                results.append((self.ctx.siem_uuid, node_name, row.name, "create", "Success", None))

            except KeyError as e:
                msg = f"Missing field: {e}"
                log.warning("SKIP CREATE alert=%s [node=%s] reason=%s", raw.get("name") or raw.get("searchname") or "<unnamed>", node_name, msg)
                results.append((self.ctx.siem_uuid, node_name, str(raw.get("name") or raw.get("searchname") or "<unnamed>"), "create", f"Skipped ({msg})", None))
            except ValueError as e:
                # Type/format issues (e.g., "30.0" in an int column)
                log.error("APPLY FAILED alert=%s [node=%s]: %s", raw.get("name") or raw.get("searchname") or "<unnamed>", node_name, e)
                results.append((self.ctx.siem_uuid, node_name, str(raw.get("name") or raw.get("searchname") or "<unnamed>"), "create", "Failed", str(e)))
            except Exception as e:
                log.exception("APPLY FAILED (unexpected) alert=%s [node=%s]", raw.get("name") or raw.get("searchname") or "<unnamed>", node_name)
                results.append((self.ctx.siem_uuid, node_name, str(raw.get("name") or raw.get("searchname") or "<unnamed>"), "create", "Failed", str(e)))

        return results
