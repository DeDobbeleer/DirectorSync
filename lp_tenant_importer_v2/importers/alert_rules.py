# lp_tenant_importer_v2/importers/alert_rules.py
"""
AlertRules importer (DirectorSync v2)

This module implements an end-to-end importer for Logpoint Alert Rules
using the v2 framework pipeline (BaseImporter). It mirrors the structure
and conventions used by the other v2 importers (e.g., ProcessingPolicies,
SyslogCollectors), and strictly delegates HTTP/monitoring to DirectorClient.

Design goals
------------
- Parse the `Alert` sheet from the provided XLSX (see samples/*_config.xlsx).
- Compute an idempotent plan based on a canonical "core rule" subset:
  (searchname, risk, repos, aggregate, condition_*, limit, timerange_*,
   query, description, flush_on_trigger, search_interval_minute,
   throttling_*, metadata, log_source, alert_context_template).
- Apply in a deterministic sequence:
  1) CREATE/UPDATE the core rule,
  2) Sync active state (activate/deactivate),
  3) Apply sharing (RBAC) based on visible_to / visible_to_users,
  4) Apply notifications by type (Email/Syslog/HTTP/SMS/SNMP/SSH).
- Fail fast with actionable messages on missing dependencies (repos, users,
  groups, etc.) and return SKIP (not FAIL) when operator action is needed.
- Keep HTTP plumbing out of the importer (use DirectorClient helpers only).

Note
----
This importer intentionally compares only the "core rule" fields when building
the plan (NOOP / CREATE / UPDATE). Sharing and notifications are treated as
post-apply sub-resources and are not part of the diff subset; they are kept
idempotent by re-applying their desired state deterministically.

"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter
from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError

log = logging.getLogger(__name__)


# ----------------------------- small helpers ---------------------------------


_EMPTY = {"", "nan", "none", "null", "-", "[]", "{}"}


def _is_blank(x: Any) -> bool:
    """Return True if the cell is effectively empty."""
    if x is None:
        return True
    if isinstance(x, float):
        try:
            if pd.isna(x):
                return True
        except Exception:
            pass
    s = str(x).strip()
    return s == "" or s.lower() in _EMPTY


def _s(x: Any) -> str:
    """Normalize any scalar to a stripped string (empty if blank)."""
    return "" if _is_blank(x) else str(x).strip()


def _as_bool_flag_on(x: Any) -> Optional[str]:
    """
    Convert Excel boolean-ish to "on" (string) when truthy; otherwise None.
    API endpoints often use string flags ("on") instead of booleans.
    """
    if isinstance(x, bool):
        return "on" if x else None
    val = _s(x).lower()
    if val in {"1", "true", "yes", "on"}:
        return "on"
    return None


def _split_multi(cell: Any, seps: Tuple[str, ...] = ("|", ",", ";")) -> List[str]:
    """
    Split a multi-valued cell by allowed separators, trim, dedupe, sort.
    Robust to list-like inputs and JSON; returns a *sorted* list of strings.
    """
    if _is_blank(cell):
        return []

    # list-like already
    if isinstance(cell, (list, tuple, set)):
        return sorted({_s(x) for x in cell if _s(x)})

    raw = _s(cell)
    # Try JSON first (array or scalar)
    if raw.startswith("[") or raw.startswith("{"):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return sorted({_s(x) for x in parsed if _s(x)})
            # Scalar-ish dict: pick readable values if any
            if isinstance(parsed, dict):
                parts = []
                for k in ("name", "value", "id"):
                    if k in parsed and _s(parsed[k]):
                        parts.append(_s(parsed[k]))
                if parts:
                    return sorted(set(parts))
                return []
        except Exception:
            pass

    # fallback: string split with multiple separators
    canon = raw
    for s in seps[1:]:
        canon = canon.replace(s, seps[0])
    parts = [p.strip() for p in canon.split(seps[0])]
    return sorted({p for p in parts if p})


def _csv(parts: Iterable[str]) -> str:
    """Canonical CSV from an iterable (trim, dedupe, sort)."""
    return ",".join(sorted({_s(x) for x in parts if _s(x)}))


def _int_or_none(x: Any) -> Optional[int]:
    """Cast to int when possible, else None."""
    s = _s(x)
    if not s:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def _parse_notifications(cell: Any) -> List[Dict[str, Any]]:
    """
    Parse `settings.notifications` column into a list of dicts.

    Accepted formats:
    - JSON array [{...}, {...}]
    - JSON object {"type": "...", ...} (wrapped into a list)
    - CSV of mini-JSONs (rare) -> we try naive split then json.loads per part
    - Empty / invalid -> []
    """
    if _is_blank(cell):
        return []

    if isinstance(cell, list):
        # best-effort: ensure list of dicts
        out: List[Dict[str, Any]] = []
        for item in cell:
            if isinstance(item, dict):
                out.append(item)
            else:
                # scalar → wrap
                out.append({"value": _s(item)})
        return out

    raw = _s(cell)
    # Try a direct JSON parse
    if raw.startswith("[") or raw.startswith("{"):
        try:
            parsed = json.loads(raw)
        except Exception:
            log.debug("notifications: invalid JSON, value=%r", raw[:200])
            return []
        if isinstance(parsed, list):
            return [p if isinstance(p, dict) else {"value": _s(p)} for p in parsed]
        if isinstance(parsed, dict):
            return [parsed]
        return []

    # Try CSV of json fragments
    parts = _split_multi(raw)
    out: List[Dict[str, Any]] = []
    for p in parts:
        if p.startswith("{"):
            try:
                out.append(json.loads(p))
                continue
            except Exception:
                pass
        out.append({"value": _s(p)})
    return out


# ------------------------------ data model -----------------------------------


@dataclass(frozen=True)
class _DesiredAlert:
    """In-memory desired model built from a row."""
    name: str
    # core
    owner: str
    risk: str
    repos: List[str]
    aggregate: str
    condition_option: str
    condition_value: int
    limit: int
    timerange_day: Optional[int]
    timerange_hour: Optional[int]
    timerange_minute: Optional[int]
    query: str
    description: str
    search_interval_minute: Optional[int]
    flush_on_trigger: bool
    throttling_enabled: bool
    throttling_field: str
    throttling_time_range: Optional[int]
    metadata: List[Tuple[str, str]]
    log_source: List[str]
    context_template: str
    # post-apply
    active: bool
    visible_to_groups: List[str]
    visible_to_users: List[str]
    notifications: List[Dict[str, Any]]

    def canon_core(self) -> Dict[str, Any]:
        """
        Comparable subset for plan decisions (NOOP/CREATE/UPDATE).
        Lists are normalized into order-insensitive strings.
        """
        return {
            "risk": _s(self.risk).lower(),
            "repos": _csv(self.repos),
            "aggregate": _s(self.aggregate).lower(),
            "condition_option": _s(self.condition_option).lower(),
            "condition_value": int(self.condition_value),
            "limit": int(self.limit),
            # represent timerange using a single key/value pair
            "timerange_key": "day"
            if self.timerange_day
            else ("hour" if self.timerange_hour else "minute"),
            "timerange_value": (
                self.timerange_day
                if self.timerange_day
                else (self.timerange_hour if self.timerange_hour else self.timerange_minute or 0)
            ),
            "query": _s(self.query),
            "description": _s(self.description),
            "flush_on_trigger": bool(self.flush_on_trigger),
            "search_interval_minute": self.search_interval_minute or 0,
            "throttling_enabled": bool(self.throttling_enabled),
            "throttling_field": _s(self.throttling_field),
            "throttling_time_range": self.throttling_time_range or 0,
            "metadata": _csv([f"{k}={v}" for (k, v) in self.metadata]),
            "log_source": _csv(self.log_source),
            "context_template": _s(self.context_template),
        }


# ------------------------------ importer -------------------------------------


class AlertRulesImporter(BaseImporter):
    """
    AlertRules importer using the BaseImporter pipeline.

    Sheets:
        - "Alert" (required)

    Required columns (case-insensitive):
        - name
        - settings.user
        - settings.risk
        - settings.repos
        - settings.aggregate
        - settings.condition.condition_option
        - settings.condition.condition_value
        - at least ONE of:
          settings.livesearch_data.timerange_minute
          settings.livesearch_data.timerange_hour
          settings.livesearch_data.timerange_day
          OR settings.time_range_seconds (will be converted)
        - settings.livesearch_data.limit

    Optional (recommended):
        - settings.livesearch_data.query
        - settings.description
        - settings.flush_on_trigger
        - settings.livesearch_data.search_interval_minute
        - settings.throttling_enabled
        - settings.throttling_field
        - settings.throttling_time_range
        - settings.metadata   (expects either JSON [{field,value},..] or CSV "k=v|k2=v2")
        - settings.log_source (CSV or JSON list)
        - settings.context_template
        - settings.active
        - settings.visible_to            (groups)
        - settings.visible_to_users      (users)
        - settings.notifications         (JSON list of typed objects)
        - tenant_scope                   (used to choose fetch endpoint family)
    """

    resource_name: str = "alert_rules"
    sheet_names = ("Alert",)
    required_columns = tuple()  # custom validate() below
    compare_keys = (
        "risk",
        "repos",
        "aggregate",
        "condition_option",
        "condition_value",
        "limit",
        "timerange_key",
        "timerange_value",
        "query",
        "description",
        "flush_on_trigger",
        "search_interval_minute",
        "throttling_enabled",
        "throttling_field",
        "throttling_time_range",
        "metadata",
        "log_source",
        "context_template",
    )

    # Resource root segment (relative to configapi/{pool}/{node}/...)
    RESOURCE = "AlertRules"

    # --- validate ---------------------------------------------------------

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        if "Alert" not in sheets:
            raise ValidationError("Missing required sheet: 'Alert'")

        df = sheets["Alert"]
        cols = {str(c).strip().lower() for c in df.columns}

        def need(col_name: str) -> None:
            if col_name.lower() not in cols:
                raise ValidationError(f"Missing required column in 'Alert': {col_name}")

        # Hard requirements
        need("name")
        need("settings.user")
        need("settings.risk")
        need("settings.repos")
        need("settings.aggregate")
        need("settings.condition.condition_option")
        need("settings.condition.condition_value")
        need("settings.livesearch_data.limit")

        has_minute = "settings.livesearch_data.timerange_minute" in cols
        has_hour = "settings.livesearch_data.timerange_hour" in cols
        has_day = "settings.livesearch_data.timerange_day" in cols
        has_seconds = "settings.time_range_seconds" in cols
        if not (has_minute or has_hour or has_day or has_seconds):
            raise ValidationError(
                "At least one timerange column is required: "
                "settings.livesearch_data.timerange_minute|hour|day "
                "or settings.time_range_seconds"
            )

    # --- desired rows parsing --------------------------------------------

    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:  # type: ignore[override]
        df = sheets["Alert"].copy()

        # Normalize column names (case-insensitive lookups)
        def col(name: str) -> Optional[str]:
            targets = {c.lower(): c for c in df.columns}
            return targets.get(name.lower())

        def get(name: str) -> Any:
            c = col(name)
            return df[c] if c in df else None

        # Extract/convert columns
        name_col = get("name")
        owner_col = get("settings.user")
        risk_col = get("settings.risk")
        repos_col = get("settings.repos")
        agg_col = get("settings.aggregate")
        cond_opt = get("settings.condition.condition_option")
        cond_val = get("settings.condition.condition_value")
        limit_col = get("settings.livesearch_data.limit")

        tr_min = get("settings.livesearch_data.timerange_minute")
        tr_hr = get("settings.livesearch_data.timerange_hour")
        tr_day = get("settings.livesearch_data.timerange_day")
        tr_sec = get("settings.time_range_seconds")

        query_col = get("settings.livesearch_data.query") or get("settings.extra_config.query")
        desc_col = get("settings.description")
        flush_col = get("settings.flush_on_trigger") or get("settings.livesearch_data.flush_on_trigger")
        search_iv = get("settings.livesearch_data.search_interval_minute")
        thr_en = get("settings.throttling_enabled")
        thr_field = get("settings.throttling_field")
        thr_range = get("settings.throttling_time_range")
        meta_col = get("settings.metadata")
        logsrc_col = get("settings.log_source")
        ctxt_tmpl = get("settings.context_template")

        active_col = get("settings.active")
        vis_groups = get("settings.visible_to")
        vis_users = get("settings.visible_to_users")
        notif_col = get("settings.notifications")

        # Build row-wise desired
        for idx in range(len(df)):
            name = _s(name_col.iloc[idx])
            if not name:
                # silently skip empty names (consistent with other importers)
                continue

            # Convert timerange (favor day/hour/minute columns; else convert seconds → minutes)
            tr_d = _int_or_none(tr_day.iloc[idx]) if tr_day is not None else None
            tr_h = _int_or_none(tr_hr.iloc[idx]) if tr_hr is not None else None
            tr_m = _int_or_none(tr_min.iloc[idx]) if tr_min is not None else None
            if not (tr_d or tr_h or tr_m):
                sec = _int_or_none(tr_sec.iloc[idx]) if tr_sec is not None else None
                if sec:
                    # choose best bucket: prefer minutes
                    tr_m = max(1, int(round(sec / 60.0)))

            desired = _DesiredAlert(
                name=name,
                owner=_s(owner_col.iloc[idx]),
                risk=_s(risk_col.iloc[idx]),
                repos=_split_multi(repos_col.iloc[idx]),
                aggregate=_s(agg_col.iloc[idx]),
                condition_option=_s(cond_opt.iloc[idx]),
                condition_value=int(_int_or_none(cond_val.iloc[idx]) or 0),
                limit=int(_int_or_none(limit_col.iloc[idx]) or 0),
                timerange_day=tr_d,
                timerange_hour=tr_h,
                timerange_minute=tr_m,
                query=_s(query_col.iloc[idx]) if query_col is not None else "",
                description=_s(desc_col.iloc[idx]) if desc_col is not None else "",
                search_interval_minute=_int_or_none(search_iv.iloc[idx]) if search_iv is not None else None,
                flush_on_trigger=bool(_as_bool_flag_on(flush_col.iloc[idx])) if flush_col is not None else False,
                throttling_enabled=bool(_as_bool_flag_on(thr_en.iloc[idx])) if thr_en is not None else False,
                throttling_field=_s(thr_field.iloc[idx]) if thr_field is not None else "",
                throttling_time_range=_int_or_none(thr_range.iloc[idx]) if thr_range is not None else None,
                metadata=self._parse_metadata(meta_col.iloc[idx]) if meta_col is not None else [],
                log_source=_split_multi(logsrc_col.iloc[idx]) if logsrc_col is not None else [],
                context_template=_s(ctxt_tmpl.iloc[idx]) if ctxt_tmpl is not None else "",
                active=(_s(active_col.iloc[idx]).lower() in {"1", "true", "yes", "on"})
                if active_col is not None
                else False,
                visible_to_groups=_split_multi(vis_groups.iloc[idx]) if vis_groups is not None else [],
                visible_to_users=_split_multi(vis_users.iloc[idx]) if vis_users is not None else [],
                notifications=_parse_notifications(notif_col.iloc[idx]) if notif_col is not None else [],
            )

            # Validate critical numeric requirements here (friendlier than API 400)
            if desired.limit < 1:
                raise ValidationError(f"[Alert:{name}] 'limit' must be >= 1")
            if not (desired.timerange_day or desired.timerange_hour or desired.timerange_minute):
                raise ValidationError(f"[Alert:{name}] missing timerange (day/hour/minute or time_range_seconds)")

            yield {
                "key": name,      # stable key used by BaseImporter
                "desired": desired,
            }

    @staticmethod
    def _parse_metadata(cell: Any) -> List[Tuple[str, str]]:
        """
        Parse metadata either as JSON array [{"field":"k","value":"v"}, ...]
        or as CSV of "k=v" items. Returns a list of (k, v).
        """
        if _is_blank(cell):
            return []

        if isinstance(cell, list):
            out: List[Tuple[str, str]] = []
            for item in cell:
                if isinstance(item, dict):
                    k = _s(item.get("field"))
                    v = _s(item.get("value"))
                    if k:
                        out.append((k, v))
            return sorted(set(out))

        raw = _s(cell)
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    out: List[Tuple[str, str]] = []
                    for it in parsed:
                        if isinstance(it, dict):
                            k = _s(it.get("field"))
                            v = _s(it.get("value"))
                            if k:
                                out.append((k, v))
                    return sorted(set(out))
            except Exception:
                pass

        # CSV of k=v items
        parts = _split_multi(raw)
        out: List[Tuple[str, str]] = []
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                if _s(k):
                    out.append((_s(k), _s(v)))
        return sorted(set(out))

    # --- diff keys --------------------------------------------------------

    def key_fn(self, desired_row: Dict[str, Any]) -> str:  # type: ignore[override]
        return _s(desired_row["key"])

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[override]
        return desired_row["desired"].canon_core()

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:  # type: ignore[override]
        if not existing_obj:
            return None

        # Convert API payload to the same comparable subset used by desired.canon_core()
        # We accept minor schema drift gracefully (missing keys default to empty).
        def get_any(d: Dict[str, Any], *keys: str) -> Any:
            for k in keys:
                if k in d:
                    return d[k]
            return None

        repos = _split_multi(get_any(existing_obj, "repos", "repository", "repositories"))
        log_source = _split_multi(get_any(existing_obj, "log_source", "logsources"))

        # timerange: prefer day>hour>minute if present
        tr_d = _int_or_none(get_any(existing_obj, "timerange_day"))
        tr_h = _int_or_none(get_any(existing_obj, "timerange_hour"))
        tr_m = _int_or_none(get_any(existing_obj, "timerange_minute"))

        meta_items: List[Tuple[str, str]] = []
        md = get_any(existing_obj, "metadata") or []
        if isinstance(md, list):
            for it in md:
                if isinstance(it, dict):
                    k = _s(it.get("field"))
                    v = _s(it.get("value"))
                    if k:
                        meta_items.append((k, v))
        metadata_csv = _csv([f"{k}={v}" for (k, v) in meta_items])

        return {
            "risk": _s(get_any(existing_obj, "risk")).lower(),
            "repos": _csv(repos),
            "aggregate": _s(get_any(existing_obj, "aggregate")).lower(),
            "condition_option": _s(get_any(existing_obj, "condition_option")).lower(),
            "condition_value": int(_int_or_none(get_any(existing_obj, "condition_value")) or 0),
            "limit": int(_int_or_none(get_any(existing_obj, "limit")) or 0),
            "timerange_key": "day" if tr_d else ("hour" if tr_h else "minute"),
            "timerange_value": tr_d if tr_d else (tr_h if tr_h else tr_m or 0),
            "query": _s(get_any(existing_obj, "query")),
            "description": _s(get_any(existing_obj, "description")),
            "flush_on_trigger": bool(get_any(existing_obj, "flush_on_trigger") in {"on", True}),
            "search_interval_minute": _int_or_none(get_any(existing_obj, "search_interval_minute")) or 0,
            "throttling_enabled": bool(get_any(existing_obj, "throttling_enabled") in {"on", True}),
            "throttling_field": _s(get_any(existing_obj, "throttling_field")),
            "throttling_time_range": _int_or_none(get_any(existing_obj, "throttling_time_range")) or 0,
            "metadata": metadata_csv,
            "log_source": _csv(log_source),
            "context_template": _s(get_any(existing_obj, "alert_context_template", "context_template")),
        }

    # --- fetch existing ---------------------------------------------------

    def fetch_existing(  # type: ignore[override]
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """
        Try to list existing rules for a node, returning {searchname -> obj}.

        Strategy (defensive to API flavors):
        1) GET configapi/{pool}/{node}/AlertRules                (direct list)
        2) POST configapi/.../AlertRules/MyAlertRules/fetch      (monitor)
        3) POST configapi/.../AlertRules/SharedAlertRules/fetch  (monitor)
        4) POST configapi/.../AlertRules/VendorAlertRules/fetch  (monitor)

        The first successful response wins. Unknown payload shapes are adapted
        best-effort (we look for common containers like result[], data[], rules[]).
        """
        def _adapt_list(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
            if not isinstance(payload, dict):
                return []
            # common containers
            for key in ("result", "results", "data", "rules", "items", "list"):
                val = payload.get(key)
                if isinstance(val, list):
                    return [x for x in val if isinstance(x, dict)]
                if isinstance(val, dict) and isinstance(val.get("items"), list):
                    return [x for x in val["items"] if isinstance(x, dict)]
            # monitor responses often have {response: {success, result: []}}
            resp = payload.get("response")
            if isinstance(resp, dict):
                val = resp.get("result") or resp.get("results")
                if isinstance(val, list):
                    return [x for x in val if isinstance(x, dict)]
            return []

        def _monitorize(res: Dict[str, Any]) -> Dict[str, Any]:
            # Try job id first (modern), then monitor URL (legacy)
            job_id = client._extract_job_id(res)  # type: ignore[attr-defined]
            if isinstance(job_id, str) and job_id:
                ok, data = client.monitor_job(pool_uuid, node.id, job_id)
                return data if ok else {}
            mpath = client._extract_monitor_path(res)  # type: ignore[attr-defined]
            if isinstance(mpath, str) and mpath:
                ok, data = client.monitor_job_url(mpath)
                return data if ok else {}
            return res

        # 1) Direct GET list
        try:
            raw = client.get_json(
                client.configapi(pool_uuid, node.id, self.RESOURCE)
            ) or {}
            items = _adapt_list(raw) or (raw if isinstance(raw, list) else [])
            out: Dict[str, Dict[str, Any]] = {}
            for it in items:
                key = _s(it.get("searchname") or it.get("name"))
                if key:
                    out[key] = {"id": _s(it.get("id") or it.get("_id")), **it}
            if out:
                return out
        except Exception as exc:  # pragma: no cover - informative only
            log.debug("GET AlertRules failed on %s: %s", node.name, exc)

        # 2..4) Fetch flavors (monitor)
        for path in (
            f"{self.RESOURCE}/MyAlertRules/fetch",
            f"{self.RESOURCE}/SharedAlertRules/fetch",
            f"{self.RESOURCE}/VendorAlertRules/fetch",
        ):
            try:
                res = client.post_json(client.configapi(pool_uuid, node.id, path), {})
                data = _monitorize(res)
                items = _adapt_list(data)
                out: Dict[str, Dict[str, Any]] = {}
                for it in items:
                    key = _s(it.get("searchname") or it.get("name"))
                    if key:
                        out[key] = {"id": _s(it.get("id") or it.get("_id")), **it}
                if out:
                    return out
            except Exception as exc:  # pragma: no cover
                log.debug("fetch %s failed on %s: %s", path, node.name, exc)

        return {}

    # --- payload builders --------------------------------------------------

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[override]
        d: _DesiredAlert = desired_row["desired"]

        payload: Dict[str, Any] = {
            "searchname": d.name,
            "owner": d.owner,
            "risk": d.risk,
            "repos": d.repos,
            "aggregate": d.aggregate,
            "condition_option": d.condition_option,
            "condition_value": d.condition_value,
            "limit": d.limit,
            "query": d.query,
            "description": d.description,
        }

        # timerange: choose exactly one
        if d.timerange_day:
            payload["timerange_day"] = d.timerange_day
        elif d.timerange_hour:
            payload["timerange_hour"] = d.timerange_hour
        else:
            payload["timerange_minute"] = d.timerange_minute or 1

        if d.search_interval_minute:
            payload["search_interval_minute"] = d.search_interval_minute

        if d.flush_on_trigger:
            payload["flush_on_trigger"] = "on"

        if d.throttling_enabled:
            payload["throttling_enabled"] = "on"
            if d.throttling_field:
                payload["throttling_field"] = d.throttling_field
            if d.throttling_time_range:
                payload["throttling_time_range"] = d.throttling_time_range

        if d.metadata:
            payload["metadata"] = [{"field": k, "value": v} for (k, v) in d.metadata]

        if d.log_source:
            payload["log_source"] = d.log_source

        if d.context_template:
            payload["alert_context_template"] = d.context_template

        return payload

    def build_payload_update(  # type: ignore[override]
        self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        # For now we use the same shape as CREATE; Director accepts PUT with
        # the full definition. If later the API requires partials, filter here.
        return self.build_payload_create(desired_row)

    # --- apply ------------------------------------------------------------

    def apply(  # type: ignore[override]
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Execute CREATE/UPDATE/NOOP/SKIP on the API and then post-apply:
        - active state (activate/deactivate),
        - sharing (share/unshare),
        - notifications (per type).
        """
        desired: _DesiredAlert = decision.desired["desired"]
        monitor_branch = None

        # ------------ core create/update
        if decision.op == "CREATE":
            res = client.post_json(
                client.configapi(pool_uuid, node.id, self.RESOURCE),
                self.build_payload_create(decision.desired),
            )
            # monitor if needed
            job_id = client._extract_job_id(res)  # type: ignore[attr-defined]
            if job_id:
                ok, data = client.monitor_job(pool_uuid, node.id, job_id)
                monitor_branch = f"job:{job_id}"
                if not ok:
                    return {
                        "status": "Failed",
                        "monitor_ok": False,
                        "monitor_branch": monitor_branch,
                        "error": f"Create failed: {data.get('message')}",
                    }
                created = data.get("response", {}).get("result") or data.get("result") or {}
            else:
                created = res.get("result") or res

            rule_id = _s(created.get("id") or created.get("_id"))
            if not rule_id:
                # try to re-fetch by name as a fallback
                existing_map = self.fetch_existing(client, pool_uuid, node)
                rule = existing_map.get(desired.name)
                rule_id = rule and _s(rule.get("id"))
                if not rule_id:
                    return {
                        "status": "Failed",
                        "monitor_ok": False,
                        "monitor_branch": monitor_branch,
                        "error": "Create succeeded but rule id missing",
                    }

        elif decision.op == "UPDATE":
            if not existing_id:
                return {
                    "status": "Failed",
                    "monitor_ok": False,
                    "monitor_branch": monitor_branch,
                    "error": "Update planned but no existing id",
                }
            res = client.put_json(
                client.configapi(pool_uuid, node.id, f"{self.RESOURCE}/{existing_id}"),
                self.build_payload_update(decision.desired, decision.existing or {}),
            )
            job_id = client._extract_job_id(res)  # type: ignore[attr-defined]
            if job_id:
                ok, data = client.monitor_job(pool_uuid, node.id, job_id)
                monitor_branch = f"job:{job_id}"
                if not ok:
                    return {
                        "status": "Failed",
                        "monitor_ok": False,
                        "monitor_branch": monitor_branch,
                        "error": f"Update failed: {data.get('message')}",
                    }
            rule_id = existing_id

        elif decision.op in ("NOOP", "SKIP"):
            # BaseImporter never calls apply for NOOP/SKIP, but keep safe.
            return {"status": "Skipped", "monitor_ok": True, "monitor_branch": monitor_branch}

        else:
            return {"status": "Failed", "error": f"Unknown decision {decision.op}"}

        # ----------- post-apply (state, sharing, notifications)

        # 1) state
        state_path = None
        try:
            # Try to detect current active state from existing (best-effort)
            # If unknown, just apply desired unconditionally.
            if desired.active:
                state_path = f"{self.RESOURCE}/{rule_id}/activate"
            else:
                state_path = f"{self.RESOURCE}/{rule_id}/deactivate"
            resp = client.post_json(client.configapi(pool_uuid, node.id, state_path), {})
            job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
            if job_id:
                ok, _data = client.monitor_job(pool_uuid, node.id, job_id)
                if not ok:
                    log.warning("activate/deactivate monitor failed: id=%s", job_id)
        except Exception as exc:
            log.warning("state sync failed (%s): %s", state_path, exc)

        # 2) sharing (RBAC)
        try:
            rbac_cfg = self._make_rbac_config(desired.visible_to_groups, desired.visible_to_users)
            if rbac_cfg:
                resp = client.post_json(
                    client.configapi(pool_uuid, node.id, f"{self.RESOURCE}/{rule_id}/share"),
                    {"rbac_config": rbac_cfg},
                )
                job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
                if job_id:
                    ok, _data = client.monitor_job(pool_uuid, node.id, job_id)
                    if not ok:
                        log.warning("share monitor failed: id=%s", job_id)
            else:
                # If sheet wants no sharing, unshare to reset
                resp = client.post_json(
                    client.configapi(pool_uuid, node.id, f"{self.RESOURCE}/{rule_id}/unshare"), {}
                )
                job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
                if job_id:
                    ok, _data = client.monitor_job(pool_uuid, node.id, job_id)
                    if not ok:
                        log.warning("unshare monitor failed: id=%s", job_id)
        except Exception as exc:
            log.warning("share/unshare failed: %s", exc)

        # 3) notifications (per type)
        try:
            self._apply_notifications(client, pool_uuid, node, rule_id, desired.notifications)
        except Exception as exc:
            log.warning("notifications apply failed: %s", exc)

        return {"status": "Success", "monitor_ok": True, "monitor_branch": monitor_branch}

    # --- RBAC -------------------------------------------------------------

    @staticmethod
    def _make_rbac_config(groups: List[str], users: List[str]) -> Dict[str, Any]:
        """
        Convert visible_to / visible_to_users into `rbac_config`.
        The sheet is expected to provide identifiers that Director accepts.
        If you keep names here, resolve to IDs prior to calling share if needed.
        """
        cfg: Dict[str, Any] = {}
        if groups:
            cfg["group_permissions"] = [{"group_id": g, "permission": "READ"} for g in groups]
        if users:
            cfg["user_permissions"] = [{"user_id": u, "permission": "READ"} for u in users]
        return cfg

    # --- notifications ----------------------------------------------------

    def _apply_notifications(
        self,
        client: DirectorClient,
        pool: str,
        node: NodeRef,
        rule_id: str,
        items: List[Dict[str, Any]],
    ) -> None:
        """
        Apply notifications in a simple idempotent way:
        - For each item, POST to its corresponding sub-endpoint.
        - If the API requires delete/update semantics, extend here to
          diff against existing notifications (future enhancement).
        """
        for item in items or []:
            typ = _s(item.get("type")).lower()
            if not typ:
                continue
            if typ == "email":
                self._post_email_notification(client, pool, node, rule_id, item)
            elif typ == "syslog":
                self._post_syslog_notification(client, pool, node, rule_id, item)
            elif typ == "http":
                self._post_http_notification(client, pool, node, rule_id, item)
            elif typ == "sms":
                self._post_sms_notification(client, pool, node, rule_id, item)
            elif typ == "snmp":
                self._post_snmp_notification(client, pool, node, rule_id, item)
            elif typ == "ssh":
                self._post_ssh_notification(client, pool, node, rule_id, item)
            else:
                log.warning("Unknown notification type: %s", typ)

    def _post_email_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any]
    ) -> None:
        payload: Dict[str, Any] = {
            "notify_email": _as_bool_flag_on(d.get("notify_email")) or "on",
            "email_emails": d.get("email_emails") or d.get("emails") or [],
        }
        for k in (
            "subject",
            "email_template",
            "email_threshold_option",
            "email_threshold_value",
            "dispatch_option",
            "simple_view",
            "logo_enable",
            "b64_logo",
            "link_disable",
        ):
            if k in d and not _is_blank(d[k]):
                payload[k] = d[k]
        resp = client.post_json(
            client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/EmailNotification"),
            payload,
        )
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        if job_id:
            client.monitor_job(pool, node.id, job_id)

    def _post_syslog_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any]
    ) -> None:
        payload: Dict[str, Any] = {
            "notify_syslog": _as_bool_flag_on(d.get("notify_syslog")) or "on",
            "server": d.get("server"),
            "port": _int_or_none(d.get("port")) or 514,
            "protocol": d.get("protocol") or "UDP",
            "facility": _int_or_none(d.get("facility")) or 13,
            "severity": _int_or_none(d.get("severity")) or 5,
            "message": d.get("message") or "",
            "split_rows": bool(d.get("split_rows")),
        }
        if d.get("threshold_option"):
            payload["threshold_option"] = d["threshold_option"]
        if d.get("threshold_value") is not None:
            payload["threshold_value"] = _int_or_none(d.get("threshold_value")) or 0

        resp = client.post_json(
            client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/SyslogNotification"),
            payload,
        )
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        if job_id:
            client.monitor_job(pool, node.id, job_id)

    def _post_http_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any]
    ) -> None:
        payload: Dict[str, Any] = {
            "notify_http": _as_bool_flag_on(d.get("notify_http")) or "on",
            "http_url": d.get("http_url"),
            "http_request_type": d.get("http_request_type") or "POST",
            "http_body": d.get("http_body") or "",
            "http_header": d.get("http_header") or {},
            "http_querystring": d.get("http_querystring") or "",
        }
        if d.get("http_threshold_option"):
            payload["http_threshold_option"] = d["http_threshold_option"]
        if d.get("http_threshold_value") is not None:
            payload["http_threshold_value"] = _int_or_none(d.get("http_threshold_value")) or 0

        resp = client.post_json(
            client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/HTTPNotification"),
            payload,
        )
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        if job_id:
            client.monitor_job(pool, node.id, job_id)

    def _post_sms_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any]
    ) -> None:
        payload: Dict[str, Any] = {
            "notify_sms": _as_bool_flag_on(d.get("notify_sms")) or "on",
            "sms_server": d.get("sms_server"),
            "sms_port": _int_or_none(d.get("sms_port")) or 25,
            "sms_sender": d.get("sms_sender") or "",
            "sms_password": d.get("sms_password") or "",
            "sms_receivers": d.get("sms_receivers") or [],
            "sms_body": d.get("sms_body") or "",
        }
        if d.get("sms_threshold_option"):
            payload["sms_threshold_option"] = d["sms_threshold_option"]
        if d.get("sms_threshold_value") is not None:
            payload["sms_threshold_value"] = _int_or_none(d.get("sms_threshold_value")) or 0

        resp = client.post_json(
            client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/SMSNotification"),
            payload,
        )
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        if job_id:
            client.monitor_job(pool, node.id, job_id)

    def _post_snmp_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any]
    ) -> None:
        payload: Dict[str, Any] = {
            "notify_snmp": _as_bool_flag_on(d.get("notify_snmp")) or "on",
            "snmp_agent": d.get("snmp_agent"),
        }
        # pass-through additional SNMP security/version keys if provided
        for k in ("snmp_version", "snmp_security", "snmp_community", "snmp_user", "snmp_auth", "snmp_priv"):
            if k in d and not _is_blank(d[k]):
                payload[k] = d[k]

        resp = client.post_json(
            client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/SNMPNotification"),
            payload,
        )
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        if job_id:
            client.monitor_job(pool, node.id, job_id)

    def _post_ssh_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any]
    ) -> None:
        payload: Dict[str, Any] = {
            "notify_ssh": _as_bool_flag_on(d.get("notify_ssh")) or "on",
            "ssh_server": d.get("ssh_server"),
            "ssh_port": _int_or_none(d.get("ssh_port")) or 22,
            "ssh_auth_type": d.get("ssh_auth_type") or "password",
            "ssh_username": d.get("ssh_username") or "",
        }
        if payload["ssh_auth_type"] == "password":
            payload["ssh_auth_password"] = d.get("ssh_auth_password") or d.get("ssh_password") or ""
        else:
            payload["ssh_key"] = d.get("ssh_key") or ""

        if d.get("ssh_command"):
            payload["ssh_command"] = d["ssh_command"]
        if d.get("ssh_threshold_option"):
            payload["ssh_threshold_option"] = d["ssh_threshold_option"]
        if d.get("ssh_threshold_value") is not None:
            payload["ssh_threshold_value"] = _int_or_none(d.get("ssh_threshold_value")) or 0

        resp = client.post_json(
            client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/SSHNotification"),
            payload,
        )
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        if job_id:
            client.monitor_job(pool, node.id, job_id)
