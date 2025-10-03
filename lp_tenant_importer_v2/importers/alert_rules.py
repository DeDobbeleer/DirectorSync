# lp_tenant_importer_v2/importers/alert_rules.py
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter, NodeRef
from ..core.director_client import DirectorClient
from ..utils.resolvers import normalize_repo_list_for_tenant
from ..utils.validators import ValidationError

log = logging.getLogger(__name__)

RESOURCE = "AlertRules"


# ------------------------------ Column aliases ------------------------------ #
# For each canonical key, list acceptable XLSX columns (first non-empty wins).
ALIASES: Dict[str, List[str]] = {
    # Identity
    "name": ["name", "Name"],

    # Core settings
    "settings.risk": ["settings.risk", "risk", "Risk"],
    "settings.aggregate": ["settings.aggregate", "aggregate", "Aggregate"],

    # Condition
    "settings.condition.condition_option": [
        "settings.condition.condition_option",
        "settings.condition.option",
        "condition_option",
        "condition.option",
    ],
    "settings.condition.condition_value": [
        "settings.condition.condition_value",
        "settings.condition.value",
        "condition_value",
        "condition.value",
    ],

    # Live search core
    "settings.livesearch_data.limit": [
        "settings.livesearch_data.limit",
        "settings.limit",
        "limit",
    ],
    "query": [
        "settings.livesearch_data.query",
        "settings.extra_config.query",
        "settings.query",
        "query",
    ],
    "settings.repos": [
        "settings.repos",
        "repos",
        "settings.livesearch_data.repos",
    ],

    # Timerange (we will keep only one among minute/hour/day)
    "timerange_minute": [
        "settings.livesearch_data.timerange_minute",
        "settings.timerange.minute",
        "timerange_minute",
        "timerange.minute",
        "settings.time_range_minutes",
    ],
    "timerange_hour": [
        "settings.livesearch_data.timerange_hour",
        "settings.timerange.hour",
        "timerange_hour",
        "timerange.hour",
    ],
    "timerange_day": [
        "settings.livesearch_data.timerange_day",
        "settings.timerange.day",
        "timerange_day",
        "timerange.day",
    ],
    # Seconds appear in some sheets; for MyAlertRules we drop it later.
    "timerange_second": [
        "settings.livesearch_data.timerange_second",
        "settings.timerange.second",
        "timerange_second",
        "timerange.second",
        "settings.time_range_seconds",
    ],

    # Optional / descriptive
    "settings.description": ["settings.description", "description", "Description"],
    "settings.livesearch_data.search_interval_minute": [
        "settings.livesearch_data.search_interval_minute",
        "settings.search_interval_minute",
        "search_interval_minute",
    ],
    "settings.flush_on_trigger": ["settings.flush_on_trigger", "flush_on_trigger"],
    "settings.throttling_enabled": ["settings.throttling_enabled", "throttling_enabled"],
    "settings.throttling_field": ["settings.throttling_field", "throttling_field"],
    "settings.throttling_time_range": ["settings.throttling_time_range", "throttling_time_range"],
    "settings.log_source": ["settings.log_source", "log_source"],
    "settings.context_template": ["settings.context_template", "context_template"],
    "settings.active": ["settings.active", "active"],
}


# --------------------------------- Helpers --------------------------------- #
def _s(value: Any) -> str:
    """Return value as trimmed string (empty if None)."""
    if isinstance(value, str):
        return value.strip()
    if value is None:
        return ""
    return str(value).strip()


def _int_or_none(value: Any) -> Optional[int]:
    """Parse int from arbitrary input; return None if not parseable."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except Exception:
        try:
            return int(float(str(value).replace(",", ".")))
        except Exception:
            return None


def _split_multi(cell: Any, seps: Tuple[str, ...]) -> List[str]:
    """Split a cell by multiple separators into a list of non-empty strings."""
    if cell is None:
        return []
    if isinstance(cell, list):
        return [x.strip() for x in cell if isinstance(x, str) and x.strip()]
    text = str(cell)
    for sep in seps:
        text = text.replace(sep, "\n")
    return [x.strip() for x in text.split("\n") if x.strip()]


def _first(row: pd.Series, keys: List[str]) -> Any:
    """Return the first non-empty value among aliases in this row."""
    for key in keys:
        if key in row:
            val = row.get(key)
            if isinstance(val, list) and val:
                return val
            if _s(val) != "":
                return val
    return None


def _first_list(row: pd.Series, keys: List[str], seps: Tuple[str, ...]) -> List[str]:
    """Return a list from the first non-empty alias value, splitting if necessary."""
    val = _first(row, keys)
    return _split_multi(val, seps) if val is not None else []


# -------------------------------- Importer --------------------------------- #
class AlertRulesImporter(BaseImporter):
    """
    AlertRules importer (MyAlertRules), aligned with the V2 importer pattern.

    No dependency on profiles.yml. Owner is resolved from:
      1) env var LP_ALERT_OWNER,
      2) API context (username/user_id/owner_id),
    Repos are normalized via the shared resolver (supports optional "Repo" sheet).
    """

    SHEET_ALERT = "Alert"
    SHEET_REPO = "Repo"  # optional: old -> cleaned mapping

    # Static behavior (since we do not use profiles.yml)
    LIST_SEPARATORS: Tuple[str, ...] = ("|", ",", "\n")
    TIMERANGE_PRIORITY: Tuple[str, ...] = ("minute", "hour", "day")

    # Strict POST/PUT whitelist to avoid accidental 400s
    POST_WHITELIST = {
        "searchname",
        "owner",
        "risk",
        "repos",
        "aggregate",
        "condition_option",
        "condition_value",
        "limit",
        "timerange_minute",
        "timerange_hour",
        "timerange_day",
        "query",
        "description",
        "log_source",
        "search_interval_minute",
        "flush_on_trigger",
        "throttling_enabled",
        "throttling_field",
        "throttling_time_range",
        "alert_context_template",
    }
    PUT_WHITELIST = POST_WHITELIST - {"searchname"}

    def __init__(self) -> None:
        super().__init__()
        # If needed, BaseImporter provides: self.xlsx_reader and self.ctx

    # ------------------------------ Lifecycle ------------------------------ #
    @property
    def sheet_names(self) -> List[str]:
        """Required sheet list for BaseImporter pre-validation."""
        return [self.SHEET_ALERT]  # Repo sheet is optional

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        """Validate presence of required columns (via alias groups)."""
        if self.SHEET_ALERT not in sheets:
            raise ValidationError(f"Missing required sheet: {self.SHEET_ALERT}")

        df = sheets[self.SHEET_ALERT]

        def need_alias(canon: str) -> None:
            candidates = ALIASES.get(canon, [canon])
            if not any(col in df.columns for col in candidates):
                raise ValidationError(f"Alert sheet: missing any of {candidates}")

        # Minimum column requirements to build a valid payload
        need_alias("name")
        need_alias("settings.risk")
        need_alias("settings.aggregate")
        need_alias("settings.condition.condition_option")
        need_alias("settings.condition.condition_value")
        need_alias("settings.livesearch_data.limit")
        need_alias("settings.repos")
        if not any(
            any(col in df.columns for col in ALIASES.get(canon, [canon]))
            for canon in ("timerange_minute", "timerange_hour", "timerange_day", "timerange_second")
        ):
            raise ValidationError("Alert sheet: missing timerange (minute/hour/day/second)")

    # --------------------------- Director state --------------------------- #
    def fetch_existing(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Return mapping {searchname -> object} using MyAlertRules/fetch.
        Tolerates different API shapes and never raises.
        """
        path = client.configapi(pool_uuid, node.id, f"{RESOURCE}/MyAlertRules/fetch")
        items: List[Dict[str, Any]] = []
        try:
            data = client.post_json(path, {"data": {}}) or []
            if isinstance(data, dict):
                items = data.get("items") or data.get("data") or data.get("results") or []
                if not isinstance(items, list):
                    items = []
            elif isinstance(data, list):
                items = data
        except Exception as exc:  # pragma: no cover
            log.warning("fetch_existing failed [node=%s]: %s", node.name, exc)
            items = []

        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            if not isinstance(it, dict):
                continue
            key = _s(it.get("searchname") or it.get("name"))
            if key:
                out[key] = it

        log.info("fetch_existing: %d rules [node=%s]", len(out), node.name)
        return out

    # ------------------------ XLSX → desired objects ----------------------- #
    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        """
        Yield normalized desired rows parsed from the Alert sheet.

        The result is a flat dict with canonical keys; build_* methods
        then transform it into the exact API payload with whitelisting.
        """
        df: pd.DataFrame = sheets[self.SHEET_ALERT].copy()

        # Optional Repo mapping sheet (old -> cleaned)
        repo_map_df: Optional[pd.DataFrame] = (
            sheets.get(self.SHEET_REPO) if isinstance(sheets.get(self.SHEET_REPO), pd.DataFrame) else None
        )

        for _, row in df.iterrows():
            name = _s(_first(row, ALIASES["name"]))
            if not name:
                continue

            # Raw timerange inputs
            t_min = _int_or_none(_first(row, ALIASES["timerange_minute"]))
            t_hour = _int_or_none(_first(row, ALIASES["timerange_hour"]))
            t_day = _int_or_none(_first(row, ALIASES["timerange_day"]))
            # Seconds are intentionally ignored later for MyAlertRules
            _ = _int_or_none(_first(row, ALIASES["timerange_second"]))

            desired: Dict[str, Any] = {
                # Internal; remapped to `searchname` for POST
                "name": name,

                # Basic settings
                "risk": _s(_first(row, ALIASES["settings.risk"])),
                "aggregate": _s(_first(row, ALIASES["settings.aggregate"])),

                # Condition
                "condition_option": _s(_first(row, ALIASES["settings.condition.condition_option"])) or "count",
                "condition_value": _int_or_none(_first(row, ALIASES["settings.condition.condition_value"])) or 0,

                # Livesearch
                "limit": _int_or_none(_first(row, ALIASES["settings.livesearch_data.limit"])) or 0,
                "query": _s(_first(row, ALIASES["query"])),

                # Optional descriptive fields
                "description": _s(_first(row, ALIASES["settings.description"])),
                "log_source": _first_list(row, ALIASES["settings.log_source"], self.LIST_SEPARATORS),

                # Scheduling & throttling
                "search_interval_minute": _int_or_none(
                    _first(row, ALIASES["settings.livesearch_data.search_interval_minute"])
                ) or 0,
                "flush_on_trigger": _s(_first(row, ALIASES["settings.flush_on_trigger"])).lower()
                in {"on", "true", "1", "yes"},
                "throttling_enabled": _s(_first(row, ALIASES["settings.throttling_enabled"])).lower()
                in {"on", "true", "1", "yes"},
                "throttling_field": _s(_first(row, ALIASES["settings.throttling_field"])),
                "throttling_time_range": _int_or_none(_first(row, ALIASES["settings.throttling_time_range"])) or 0,

                "alert_context_template": _s(_first(row, ALIASES["settings.context_template"])),
                "active": _s(_first(row, ALIASES["settings.active"])).lower() in {"on", "true", "1", "yes"},

                # Repos as raw list (normalized below)
                "repos": _first_list(row, ALIASES["settings.repos"], self.LIST_SEPARATORS),

                # Timerange raw (normalized below)
                "timerange_minute": t_min,
                "timerange_hour": t_hour,
                "timerange_day": t_day,
            }

            # Normalize repos using the shared resolver (same as other modules).
            desired["repos"] = normalize_repo_list_for_tenant(
                desired.get("repos", []),
                tenant_ctx=self.ctx,
                # We do not rely on profiles; resolver will use tenant ips from ctx.
                use_tenant_ip=True,
                enable_repo_sheet_mapping=True,
                xlsx_reader=self.xlsx_reader,  # provided by BaseImporter
                repo_map_df=repo_map_df,
            )

            # Keep only one timerange key according to static priority.
            chosen: Optional[str] = None
            for unit in self.TIMERANGE_PRIORITY:
                key = f"timerange_{unit}"
                val = desired.get(key)
                if isinstance(val, int) and val > 0:
                    chosen = key
                    break
            for unit in ("minute", "hour", "day"):
                key = f"timerange_{unit}"
                if key != chosen and key in desired:
                    desired.pop(key, None)
            # We never include seconds for MyAlertRules

            log.debug(
                "Parsed XLSX row name=%s repos=%d timerange=%s",
                name,
                len(desired.get("repos", [])),
                [k for k in ("timerange_minute", "timerange_hour", "timerange_day") if k in desired],
            )
            yield desired

    # -------------------------- Matching key (existing) --------------------- #
    def desired_key(self, desired_row: Dict[str, Any]) -> str:
        """Use the rule searchname as the matching key (here `name` in desired)."""
        return _s(desired_row.get("name"))

    # ----------------------------- Payload builders ------------------------ #
    def _resolve_owner(self, desired_row: Dict[str, Any]) -> str:
        """
        Resolve owner without requiring a XLSX column:
          1) env: LP_ALERT_OWNER
          2) API context: owner_id / user_id / username
        """
        # If already provided in desired_row, keep it
        explicit = _s(desired_row.get("owner"))
        if explicit:
            return explicit

        env_owner = _s(os.getenv("LP_ALERT_OWNER", ""))
        if env_owner:
            log.debug("Owner resolved from env LP_ALERT_OWNER: %s", env_owner)
            return env_owner

        ctx = getattr(self, "ctx", None)
        if ctx is not None:
            for attr in ("owner_id", "user_id", "username"):
                v = _s(getattr(ctx, attr, None))
                if v:
                    log.debug("Owner resolved from context %s: %s", attr, v)
                    return v

        return ""

    def _normalize_onoff(self, payload: Dict[str, Any], key: str) -> None:
        """Normalize boolean flags to API 'on'/absent convention."""
        if key in payload and isinstance(payload[key], bool):
            if payload[key]:
                payload[key] = "on"
            else:
                payload.pop(key, None)

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a POST payload from a normalized desired row:
        - Rename `name` → `searchname`
        - Ensure `owner` and non-empty `repos`
        - Normalize booleans to 'on'/absent
        - Apply strict POST whitelist
        """
        payload: Dict[str, Any] = {}

        # name → searchname
        name = _s(desired_row.get("name"))
        if name:
            payload["searchname"] = name

        # Copy everything else (except internal `name`)
        for key, val in desired_row.items():
            if key == "name" or val in (None, ""):
                continue
            payload[key] = val

        # Resolve owner
        payload["owner"] = self._resolve_owner(desired_row)

        # Mandatory guards before hitting the API
        if not _s(payload.get("owner")):
            raise ValidationError("owner is required and could not be resolved from context")

        repos = payload.get("repos") or []
        if not isinstance(repos, list) or not repos:
            raise ValidationError("repos is required and must be a non-empty list")

        # Only one timerange key allowed (iter_desired already tried to enforce)
        present_tr = [k for k in ("timerange_minute", "timerange_hour", "timerange_day") if k in payload]
        if len(present_tr) > 1:
            # Keep the first according to static priority
            keep: Optional[str] = None
            for unit in self.TIMERANGE_PRIORITY:
                key = f"timerange_{unit}"
                if key in payload:
                    keep = key
                    break
            for key in ("timerange_minute", "timerange_hour", "timerange_day"):
                if key != keep:
                    payload.pop(key, None)

        # Boolean normalization: True → "on", False → remove key
        self._normalize_onoff(payload, "flush_on_trigger")
        self._normalize_onoff(payload, "throttling_enabled")

        # Apply POST whitelist (avoid unknown fields)
        payload = {k: v for k, v in payload.items() if k in self.POST_WHITELIST}
        return payload

    def build_payload_update(
        self,
        desired_row: Dict[str, Any],
        existing: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a PUT payload. Same rules as POST, but never includes `searchname`."""
        payload = self.build_payload_create(desired_row)
        payload.pop("searchname", None)
        # Apply PUT whitelist
        payload = {k: v for k, v in payload.items() if k in self.PUT_WHITELIST}
        return payload

    # --------------------------------- Apply -------------------------------- #
    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        action: str,
        name: str,
        desired_row: Dict[str, Any],
        existing_id: Optional[str],
        dry_run: bool,
    ) -> Dict[str, Any]:
        """
        Execute one operation. This method never raises:
        - ValidationError → SKIPPED (no API call) with reason
        - Other exceptions → FAILED with error message
        """
        try:
            if action == "create":
                payload = self.build_payload_create(desired_row)
                log.debug("CREATE payload: %s", payload)
                if dry_run:
                    return {"status": "Dry-run", "action": action}
                return client.create_resource(pool_uuid, node.id, RESOURCE, payload)

            if action == "update":
                payload = self.build_payload_update(desired_row, {})
                log.debug("UPDATE payload: %s", payload)
                if dry_run:
                    return {"status": "Dry-run", "action": action}
                assert existing_id, "existing_id required for update"
                return client.update_resource(pool_uuid, node.id, RESOURCE, existing_id, payload)

            if action == "noop":
                return {"status": "Noop"}

            return {"status": "Skipped", "reason": f"unknown action {action}"}

        except ValidationError as ve:
            log.warning(
                "SKIP %s alert=%s [node=%s] reason=%s (no API call)",
                action.upper(),
                name,
                node.name,
                ve,
            )
            return {"status": "Skipped", "reason": str(ve)}

        except Exception as exc:  # pragma: no cover
            # Keep the run going; report a clean error row.
            log.error("API error for alert=%s [node=%s]: %s", name, node.name, exc)
            return {"status": "Failed", "error": str(exc)}
