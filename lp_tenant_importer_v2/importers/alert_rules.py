# lp_tenant_importer_v2/importers/alert_rules.py
"""
AlertRules importer (DirectorSync v2)

- Robust XLSX parsing (no Series ambiguity)
- Correct API envelopes: ALL POST/PUT use {"data": ...}
- Fetch via .../fetch + monitor flow
- Comprehensive logging (DEBUG/INFO/WARNING/ERROR) for API actions

Design goals
------------
- Parse the `Alert` sheet to build a desired model per rule.
- Plan on a canonical "core" subset (sharing/state/notifications are post-apply).
- Apply in sequence: core (create/update) -> state -> sharing -> notifications.
- Log each API action with useful context and safe redaction.
- Fail fast on operator errors (SKIP) and surface API errors clearly.
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

# ----------------------------- redaction & utils ------------------------------

_EMPTY = {"", "nan", "none", "null", "-", "[]", "{}"}

# fields to redact when logging payloads
_REDACT_KEYS = {
    "authorization", "x-api-key", "api_key", "token", "auth_key", "auth_value", "auth_pass",
    "ssh_auth_password", "ssh_key", "sms_password",
    "snmp_community", "snmp_auth", "snmp_priv",
    # email list is PII; only count it
    "email_emails",
}


def _is_blank(x: Any) -> bool:
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
    return "" if _is_blank(x) else str(x).strip()


def _as_bool_flag_on(x: Any) -> Optional[str]:
    if isinstance(x, bool):
        return "on" if x else None
    val = _s(x).lower()
    if val in {"1", "true", "yes", "on"}:
        return "on"
    return None


def _split_multi(cell: Any, seps: Tuple[str, ...] = ("|", ",", ";")) -> List[str]:
    if _is_blank(cell):
        return []
    if isinstance(cell, (list, tuple, set)):
        return sorted({_s(x) for x in cell if _s(x)})
    raw = _s(cell)
    if raw.startswith("[") or raw.startswith("{"):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return sorted({_s(x) for x in parsed if _s(x)})
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
    canon = raw
    for s in seps[1:]:
        canon = canon.replace(s, seps[0])
    parts = [p.strip() for p in canon.split(seps[0])]
    return sorted({p for p in parts if p})


def _csv(parts: Iterable[str]) -> str:
    return ",".join(sorted({_s(x) for x in parts if _s(x)}))


def _int_or_none(x: Any) -> Optional[int]:
    s = _s(x)
    if not s:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def _parse_notifications(cell: Any) -> List[Dict[str, Any]]:
    if _is_blank(cell):
        return []
    if isinstance(cell, list):
        out: List[Dict[str, Any]] = []
        for item in cell:
            if isinstance(item, dict):
                out.append(item)
            else:
                out.append({"value": _s(item)})
        return out
    raw = _s(cell)
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


def _cols_map(df: pd.DataFrame) -> Dict[str, str]:
    return {str(c).strip().lower(): str(c) for c in df.columns}


def _pick_col(df: pd.DataFrame, *aliases: str) -> Optional[str]:
    cmap = _cols_map(df)
    for a in aliases:
        if not a:
            continue
        cn = cmap.get(a.strip().lower())
        if cn:
            return cn
    return None


def _redact_for_log(obj: Any) -> Any:
    """
    Redact sensitive fields recursively.
    - For dicts: mask values of known sensitive keys.
    - For lists of emails: replace with a count.
    """
    if isinstance(obj, dict):
        red: Dict[str, Any] = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in _REDACT_KEYS:
                if lk == "email_emails":
                    red[k] = f"<{len(v) if isinstance(v, list) else 1} recipients>"
                else:
                    red[k] = "<redacted>"
            else:
                red[k] = _redact_for_log(v)
        return red
    if isinstance(obj, list):
        return [_redact_for_log(x) for x in obj]
    return obj


def _payload_keys_summary(payload: Dict[str, Any]) -> str:
    keys = sorted(payload.keys())
    return f"keys={keys} size={len(json.dumps(payload))}"


# ------------------------------ data model -----------------------------------


@dataclass(frozen=True)
class _DesiredAlert:
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
        return {
            "risk": _s(self.risk).lower(),
            "repos": _csv(self.repos),
            "aggregate": _s(self.aggregate).lower(),
            "condition_option": _s(self.condition_option).lower(),
            "condition_value": int(self.condition_value),
            "limit": int(self.limit),
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
    """

    resource_name: str = "alert_rules"
    sheet_names = ("Alert",)
    required_columns = tuple()
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

        # Column mapping (once)
        name_col = _pick_col(df, "name")
        owner_col = _pick_col(df, "settings.user")
        risk_col = _pick_col(df, "settings.risk")
        repos_col = _pick_col(df, "settings.repos")
        agg_col = _pick_col(df, "settings.aggregate")
        cond_opt = _pick_col(df, "settings.condition.condition_option")
        cond_val = _pick_col(df, "settings.condition.condition_value")
        limit_col = _pick_col(df, "settings.livesearch_data.limit")

        tr_min = _pick_col(df, "settings.livesearch_data.timerange_minute")
        tr_hr = _pick_col(df, "settings.livesearch_data.timerange_hour")
        tr_day = _pick_col(df, "settings.livesearch_data.timerange_day")
        tr_sec = _pick_col(df, "settings.time_range_seconds")

        query_col = _pick_col(df, "settings.livesearch_data.query", "settings.extra_config.query")
        desc_col = _pick_col(df, "settings.description")
        flush_col = _pick_col(df, "settings.flush_on_trigger", "settings.livesearch_data.flush_on_trigger")
        search_iv = _pick_col(df, "settings.livesearch_data.search_interval_minute")
        thr_en = _pick_col(df, "settings.throttling_enabled")
        thr_field = _pick_col(df, "settings.throttling_field")
        thr_range = _pick_col(df, "settings.throttling_time_range")
        meta_col = _pick_col(df, "settings.metadata")
        logsrc_col = _pick_col(df, "settings.log_source")
        ctxt_tmpl = _pick_col(df, "settings.context_template")

        active_col = _pick_col(df, "settings.active")
        vis_groups = _pick_col(df, "settings.visible_to")
        vis_users = _pick_col(df, "settings.visible_to_users")
        notif_col = _pick_col(df, "settings.notifications")

        for idx, row in df.iterrows():
            def cell(cn: Optional[str]) -> Any:
                return row[cn] if cn else None

            name = _s(cell(name_col))
            if not name:
                continue

            tr_d = _int_or_none(cell(tr_day))
            tr_h = _int_or_none(cell(tr_hr))
            tr_m = _int_or_none(cell(tr_min))
            if not (tr_d or tr_h or tr_m):
                sec = _int_or_none(cell(tr_sec))
                if sec:
                    tr_m = max(1, int(round(sec / 60.0)))

            desired = _DesiredAlert(
                name=name,
                owner=_s(cell(owner_col)),
                risk=_s(cell(risk_col)),
                repos=_split_multi(cell(repos_col)),
                aggregate=_s(cell(agg_col)),
                condition_option=_s(cell(cond_opt)),
                condition_value=int(_int_or_none(cell(cond_val)) or 0),
                limit=int(_int_or_none(cell(limit_col)) or 0),
                timerange_day=tr_d,
                timerange_hour=tr_h,
                timerange_minute=tr_m,
                query=_s(cell(query_col)),
                description=_s(cell(desc_col)),
                search_interval_minute=_int_or_none(cell(search_iv)),
                flush_on_trigger=bool(_as_bool_flag_on(cell(flush_col))),
                throttling_enabled=bool(_as_bool_flag_on(cell(thr_en))),
                throttling_field=_s(cell(thr_field)),
                throttling_time_range=_int_or_none(cell(thr_range)),
                metadata=self._parse_metadata(cell(meta_col)),
                log_source=_split_multi(cell(logsrc_col)),
                context_template=_s(cell(ctxt_tmpl)),
                active=(_s(cell(active_col)).lower() in {"1", "true", "yes", "on"}),
                visible_to_groups=_split_multi(cell(vis_groups)),
                visible_to_users=_split_multi(cell(vis_users)),
                notifications=_parse_notifications(cell(notif_col)),
            )

            if desired.limit < 1:
                raise ValidationError(f"[Alert:{name}] 'limit' must be >= 1")
            if not (desired.timerange_day or desired.timerange_hour or desired.timerange_minute):
                raise ValidationError(f"[Alert:{name}] missing timerange (day/hour/minute or time_range_seconds)")

            yield {
                "key": name,
                "desired": desired,
            }

    @staticmethod
    def _parse_metadata(cell: Any) -> List[Tuple[str, str]]:
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

        def get_any(d: Dict[str, Any], *keys: str) -> Any:
            for k in keys:
                if k in d:
                    return d[k]
            return None

        repos = _split_multi(get_any(existing_obj, "repos", "repository", "repositories"))
        log_source = _split_multi(get_any(existing_obj, "log_source", "logsources"))

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

    # --- logging helpers for API/monitor ----------------------------------

    def _log_api_start(self, method: str, path: str, action: str, tenant: str, node: NodeRef, rule: str, payload: Dict[str, Any]) -> None:
        log.info("event=http.request method=%s path=%s action=%s tenant=%s node=%s|%s rule=%s %s",
                 method, path, action, tenant, getattr(node, "name", node.id), node.id, rule, _payload_keys_summary(_redact_for_log(payload)))
        log.debug("payload=%s", json.dumps(_redact_for_log(payload))[:1024])

    def _log_api_ok(self, method: str, path: str, action: str, tenant: str, node: NodeRef, rule: str) -> None:
        log.info("event=http.ok method=%s path=%s action=%s tenant=%s node=%s|%s rule=%s",
                 method, path, action, tenant, getattr(node, "name", node.id), node.id, rule)

    def _log_monitor_start(self, request_id: str, url: str, tenant: str, node: NodeRef, rule: str) -> None:
        log.info("event=monitor.start request_id=%s url=%s tenant=%s node=%s|%s rule=%s",
                 request_id, url, tenant, getattr(node, "name", node.id), node.id, rule)

    def _log_monitor_done(self, request_id: str, tenant: str, node: NodeRef, rule: str, items: Optional[int] = None) -> None:
        log.info("event=monitor.done request_id=%s items=%s tenant=%s node=%s|%s rule=%s",
                 request_id, (items if items is not None else "-"), tenant, getattr(node, "name", node.id), node.id, rule)

    def _log_monitor_fail(self, request_id: str, tenant: str, node: NodeRef, rule: str, reason: str) -> None:
        log.warning("event=monitor.fail request_id=%s reason=%s tenant=%s node=%s|%s rule=%s",
                    request_id, reason, tenant, getattr(node, "name", node.id), node.id, rule)

    # --- fetch existing ---------------------------------------------------

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:  # type: ignore[override]
        """
        List existing rules for a node via Fetch* endpoints (monitorized),
        returning {searchname -> obj}. AlertRules do not offer a direct GET list.
        """
        def _adapt_list(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
            if not isinstance(payload, dict):
                return []
            for key in ("result", "results", "data", "rules", "items", "list"):
                val = payload.get(key)
                if isinstance(val, list):
                    return [x for x in val if isinstance(x, dict)]
                if isinstance(val, dict) and isinstance(val.get("items"), list):
                    return [x for x in val["items"] if isinstance(x, dict)]
            resp = payload.get("response")
            if isinstance(resp, dict):
                val = resp.get("result") or resp.get("results")
                if isinstance(val, list):
                    return [x for x in val if isinstance(x, dict)]
            return []

        def _monitorize(res: Dict[str, Any], tenant: str) -> Dict[str, Any]:
            job_id = client._extract_job_id(res)  # type: ignore[attr-defined]
            mon_path = client._extract_monitor_path(res)  # type: ignore[attr-defined]
            if isinstance(job_id, str) and job_id:
                self._log_monitor_start(job_id, f"(job:{job_id})", tenant, node, "<fetch>")
                ok, data = client.monitor_job(pool_uuid, node.id, job_id)
                if ok:
                    self._log_monitor_done(job_id, tenant, node, "<fetch>")
                    return data
                self._log_monitor_fail(job_id, tenant, node, "<fetch>", "job monitor failed")
                return {}
            if isinstance(mon_path, str) and mon_path:
                self._log_monitor_start("<url>", mon_path, tenant, node, "<fetch>")
                ok, data = client.monitor_job_url(mon_path)
                if ok:
                    self._log_monitor_done("<url>", tenant, node, "<fetch>")
                    return data
                self._log_monitor_fail("<url>", tenant, node, "<fetch>", "url monitor failed")
                return {}
            return res

        out: Dict[str, Dict[str, Any]] = {}
        node_t = f"{getattr(node, 'name', node.id)}|{node.id}"

        for sub in (
            f"{self.RESOURCE}/MyAlertRules/fetch",
            f"{self.RESOURCE}/SharedAlertRules/fetch",
            f"{self.RESOURCE}/VendorAlertRules/fetch",
        ):
            path = client.configapi(pool_uuid, node.id, sub)
            try:
                self._log_api_start("POST", path, "fetch", client.tenant, node, "<fetch>", {"data": {}})
                res = client.post_json(path, {"data": {}})
                self._log_api_ok("POST", path, "fetch", client.tenant, node, "<fetch>")
                data = _monitorize(res, client.tenant)
                items = _adapt_list(data)
                for it in items:
                    key = _s(it.get("searchname") or it.get("name"))
                    if key:
                        out[key] = {"id": _s(it.get("id") or it.get("_id")), **it}
            except Exception as exc:
                log.warning("fetch_existing: POST %s failed on %s: %s", sub, node_t, exc)

        log.info("fetch_existing: found %d alert rules [node=%s]", len(out), node_t)
        return out

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

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[override]
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
        Execute CREATE/UPDATE and then post-apply:
        - state (activate/deactivate),
        - sharing (share/unshare),
        - notifications (per type).
        All API calls are logged; all POST/PUT bodies are wrapped in {"data": ...}.
        """
        desired: _DesiredAlert = decision.desired["desired"]
        monitor_branch = None
        rule_name = desired.name

        # ------------ core create/update
        try:
            if decision.op == "CREATE":
                path = client.configapi(pool_uuid, node.id, self.RESOURCE)
                body = {"data": self.build_payload_create(decision.desired)}
                self._log_api_start("POST", path, "create", client.tenant, node, rule_name, body)
                res = client.post_json(path, body)
                self._log_api_ok("POST", path, "create", client.tenant, node, rule_name)
                job_id = client._extract_job_id(res)  # type: ignore[attr-defined]
                mon_path = client._extract_monitor_path(res)  # type: ignore[attr-defined]
                if job_id:
                    self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
                    ok, data = client.monitor_job(pool_uuid, node.id, job_id)
                    monitor_branch = f"job:{job_id}"
                    if not ok:
                        self._log_monitor_fail(job_id, client.tenant, node, rule_name, "create monitor failed")
                        return {"status": "Failed", "monitor_ok": False, "monitor_branch": monitor_branch,
                                "error": f"Create failed: {data.get('message')}"}
                    self._log_monitor_done(job_id, client.tenant, node, rule_name)
                    created = data.get("response", {}).get("result") or data.get("result") or {}
                elif mon_path:
                    self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
                    ok, data = client.monitor_job_url(mon_path)
                    monitor_branch = "<url>"
                    if not ok:
                        self._log_monitor_fail("<url>", client.tenant, node, rule_name, "create monitor failed")
                        return {"status": "Failed", "monitor_ok": False, "monitor_branch": monitor_branch,
                                "error": f"Create failed via monitor url"}
                    self._log_monitor_done("<url>", client.tenant, node, rule_name)
                    created = data.get("response", {}).get("result") or data.get("result") or {}
                else:
                    created = res.get("result") or res

                rule_id = _s(created.get("id") or created.get("_id"))
                if not rule_id:
                    # fallback: re-fetch by name
                    exist_map = self.fetch_existing(client, pool_uuid, node)
                    rule = exist_map.get(rule_name)
                    rule_id = rule and _s(rule.get("id"))
                    if not rule_id:
                        return {"status": "Failed", "monitor_ok": False, "monitor_branch": monitor_branch,
                                "error": "Create succeeded but rule id missing"}

            elif decision.op == "UPDATE":
                if not existing_id:
                    return {"status": "Failed", "monitor_ok": False, "monitor_branch": monitor_branch,
                            "error": "Update planned but no existing id"}
                path = client.configapi(pool_uuid, node.id, f"{self.RESOURCE}/{existing_id}")
                body = {"data": self.build_payload_update(decision.desired, decision.existing or {})}
                self._log_api_start("PUT", path, "update", client.tenant, node, rule_name, body)
                res = client.put_json(path, body)
                self._log_api_ok("PUT", path, "update", client.tenant, node, rule_name)
                job_id = client._extract_job_id(res)  # type: ignore[attr-defined]
                mon_path = client._extract_monitor_path(res)  # type: ignore[attr-defined]
                if job_id:
                    self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
                    ok, data = client.monitor_job(pool_uuid, node.id, job_id)
                    monitor_branch = f"job:{job_id}"
                    if not ok:
                        self._log_monitor_fail(job_id, client.tenant, node, rule_name, "update monitor failed")
                        return {"status": "Failed", "monitor_ok": False, "monitor_branch": monitor_branch,
                                "error": f"Update failed: {data.get('message')}"}
                    self._log_monitor_done(job_id, client.tenant, node, rule_name)
                elif mon_path:
                    self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
                    ok, _data = client.monitor_job_url(mon_path)
                    monitor_branch = "<url>"
                    if not ok:
                        self._log_monitor_fail("<url>", client.tenant, node, rule_name, "update monitor failed")
                        return {"status": "Failed", "monitor_ok": False, "monitor_branch": monitor_branch,
                                "error": "Update failed via monitor url"}
                rule_id = existing_id

            elif decision.op in ("NOOP", "SKIP"):
                return {"status": "Skipped", "monitor_ok": True, "monitor_branch": monitor_branch}

            else:
                return {"status": "Failed", "error": f"Unknown decision {decision.op}"}

        except Exception as exc:
            log.error("apply core %s failed: %s", decision.op, exc)
            return {"status": "Failed", "monitor_ok": False, "monitor_branch": monitor_branch, "error": str(exc)}

        # ----------- post-apply (state, sharing, notifications)

        # 1) state (activate/deactivate)
        try:
            state_action = "activate" if desired.active else "deactivate"
            state_path = client.configapi(pool_uuid, node.id, f"{self.RESOURCE}/{rule_id}/{state_action}")
            self._log_api_start("POST", state_path, f"state.{state_action}", client.tenant, node, rule_name, {"data": {}})
            resp = client.post_json(state_path, {"data": {}})
            self._log_api_ok("POST", state_path, f"state.{state_action}", client.tenant, node, rule_name)
            job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
            mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
            if job_id:
                self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
                ok, _data = client.monitor_job(pool_uuid, node.id, job_id)
                if not ok:
                    self._log_monitor_fail(job_id, client.tenant, node, rule_name, "state monitor failed")
            elif mon_path:
                self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
                ok, _data = client.monitor_job_url(mon_path)
                if not ok:
                    self._log_monitor_fail("<url>", client.tenant, node, rule_name, "state monitor failed")
            log.info("event=state.%s rule_id=%s node=%s|%s", state_action, rule_id, getattr(node, "name", node.id), node.id)
        except Exception as exc:
            log.warning("state sync failed: rule=%s id=%s err=%s", rule_name, rule_id, exc)

        # 2) sharing (RBAC)
        try:
            rbac_cfg = self._make_rbac_config(desired.visible_to_groups, desired.visible_to_users)
            if rbac_cfg:
                spath = client.configapi(pool_uuid, node.id, f"{self.RESOURCE}/{rule_id}/share")
                body = {"data": {"rbac_config": rbac_cfg}}
                self._log_api_start("POST", spath, "share", client.tenant, node, rule_name, body)
                resp = client.post_json(spath, body)
                self._log_api_ok("POST", spath, "share", client.tenant, node, rule_name)
                job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
                mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
                if job_id:
                    self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
                    ok, _data = client.monitor_job(pool_uuid, node.id, job_id)
                    if not ok:
                        self._log_monitor_fail(job_id, client.tenant, node, rule_name, "share monitor failed")
                elif mon_path:
                    self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
                    ok, _data = client.monitor_job_url(mon_path)
                    if not ok:
                        self._log_monitor_fail("<url>", client.tenant, node, rule_name, "share monitor failed")
                log.info("event=share.apply rule_id=%s groups=%d users=%d", rule_id, len(desired.visible_to_groups), len(desired.visible_to_users))
            else:
                upath = client.configapi(pool_uuid, node.id, f"{self.RESOURCE}/{rule_id}/unshare")
                self._log_api_start("POST", upath, "unshare", client.tenant, node, rule_name, {"data": {}})
                resp = client.post_json(upath, {"data": {}})
                self._log_api_ok("POST", upath, "unshare", client.tenant, node, rule_name)
                job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
                mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
                if job_id:
                    self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
                    ok, _data = client.monitor_job(pool_uuid, node.id, job_id)
                    if not ok:
                        self._log_monitor_fail(job_id, client.tenant, node, rule_name, "unshare monitor failed")
                elif mon_path:
                    self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
                    ok, _data = client.monitor_job_url(mon_path)
                    if not ok:
                        self._log_monitor_fail("<url>", client.tenant, node, rule_name, "unshare monitor failed")
                log.info("event=unshare.apply rule_id=%s", rule_id)
        except Exception as exc:
            log.warning("share/unshare failed: rule=%s id=%s err=%s", rule_name, rule_id, exc)

        # 3) notifications (per type)
        try:
            self._apply_notifications(client, pool_uuid, node, rule_id, desired.notifications, rule_name)
        except Exception as exc:
            log.warning("notifications apply failed: rule=%s id=%s err=%s", rule_name, rule_id, exc)

        return {"status": "Success", "monitor_ok": True, "monitor_branch": monitor_branch}

    # --- RBAC -------------------------------------------------------------

    @staticmethod
    def _make_rbac_config(groups: List[str], users: List[str]) -> Dict[str, Any]:
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
        rule_name: str,
    ) -> None:
        for item in items or []:
            typ = _s(item.get("type")).lower()
            if not typ:
                continue
            if typ == "email":
                self._post_email_notification(client, pool, node, rule_id, item, rule_name)
            elif typ == "syslog":
                self._post_syslog_notification(client, pool, node, rule_id, item, rule_name)
            elif typ == "http":
                self._post_http_notification(client, pool, node, rule_id, item, rule_name)
            elif typ == "sms":
                self._post_sms_notification(client, pool, node, rule_id, item, rule_name)
            elif typ == "snmp":
                self._post_snmp_notification(client, pool, node, rule_id, item, rule_name)
            elif typ == "ssh":
                self._post_ssh_notification(client, pool, node, rule_id, item, rule_name)
            else:
                log.warning("Unknown notification type: %s (rule=%s id=%s)", typ, rule_name, rule_id)

    def _post_email_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any], rule_name: str
    ) -> None:
        payload: Dict[str, Any] = {
            "notify_email": _as_bool_flag_on(d.get("notify_email")) or "on",
            "email_emails": d.get("email_emails") or d.get("emails") or [],
        }
        for k in (
            "subject", "email_template", "email_threshold_option", "email_threshold_value",
            "dispatch_option", "simple_view", "logo_enable", "b64_logo", "link_disable",
        ):
            if k in d and not _is_blank(d[k]):
                payload[k] = d[k]
        path = client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/EmailNotification")
        body = {"data": payload}
        self._log_api_start("POST", path, "notify.email", client.tenant, node, rule_name, body)
        resp = client.post_json(path, body)
        self._log_api_ok("POST", path, "notify.email", client.tenant, node, rule_name)
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
        if job_id:
            self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
            ok, _ = client.monitor_job(pool, node.id, job_id)
            if ok:
                self._log_monitor_done(job_id, client.tenant, node, rule_name)
            else:
                self._log_monitor_fail(job_id, client.tenant, node, rule_name, "notify email monitor failed")
        elif mon_path:
            self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
            ok, _ = client.monitor_job_url(mon_path)
            if ok:
                self._log_monitor_done("<url>", client.tenant, node, rule_name)
            else:
                self._log_monitor_fail("<url>", client.tenant, node, rule_name, "notify email monitor failed")

    def _post_syslog_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any], rule_name: str
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
        path = client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/SyslogNotification")
        body = {"data": payload}
        self._log_api_start("POST", path, "notify.syslog", client.tenant, node, rule_name, body)
        resp = client.post_json(path, body)
        self._log_api_ok("POST", path, "notify.syslog", client.tenant, node, rule_name)
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
        if job_id:
            self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
            ok, _ = client.monitor_job(pool, node.id, job_id)
            if ok:
                self._log_monitor_done(job_id, client.tenant, node, rule_name)
            else:
                self._log_monitor_fail(job_id, client.tenant, node, rule_name, "notify syslog monitor failed")
        elif mon_path:
            self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
            ok, _ = client.monitor_job_url(mon_path)
            if ok:
                self._log_monitor_done("<url>", client.tenant, node, rule_name)
            else:
                self._log_monitor_fail("<url>", client.tenant, node, rule_name, "notify syslog monitor failed")

    def _post_http_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any], rule_name: str
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
        path = client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/HTTPNotification")
        body = {"data": payload}
        self._log_api_start("POST", path, "notify.http", client.tenant, node, rule_name, body)
        resp = client.post_json(path, body)
        self._log_api_ok("POST", path, "notify.http", client.tenant, node, rule_name)
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
        if job_id:
            self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
            ok, _ = client.monitor_job(pool, node.id, job_id)
            if ok:
                self._log_monitor_done(job_id, client.tenant, node, rule_name)
            else:
                self._log_monitor_fail(job_id, client.tenant, node, rule_name, "notify http monitor failed")
        elif mon_path:
            self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
            ok, _ = client.monitor_job_url(mon_path)
            if ok:
                self._log_monitor_done("<url>", client.tenant, node, rule_name)
            else:
                self._log_monitor_fail("<url>", client.tenant, node, rule_name, "notify http monitor failed")

    def _post_sms_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any], rule_name: str
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
        path = client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/SMSNotification")
        body = {"data": payload}
        self._log_api_start("POST", path, "notify.sms", client.tenant, node, rule_name, body)
        resp = client.post_json(path, body)
        self._log_api_ok("POST", path, "notify.sms", client.tenant, node, rule_name)
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
        if job_id:
            self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
            ok, _ = client.monitor_job(pool, node.id, job_id)
            if ok:
                self._log_monitor_done(job_id, client.tenant, node, rule_name)
            else:
                self._log_monitor_fail(job_id, client.tenant, node, rule_name, "notify sms monitor failed")
        elif mon_path:
            self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
            ok, _ = client.monitor_job_url(mon_path)
            if ok:
                self._log_monitor_done("<url>", client.tenant, node, rule_name)
            else:
                self._log_monitor_fail("<url>", client.tenant, node, rule_name, "notify sms monitor failed")

    def _post_snmp_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any], rule_name: str
    ) -> None:
        payload: Dict[str, Any] = {
            "notify_snmp": _as_bool_flag_on(d.get("notify_snmp")) or "on",
            "snmp_agent": d.get("snmp_agent"),
        }
        for k in ("snmp_version", "snmp_security", "snmp_community", "snmp_user", "snmp_auth", "snmp_priv"):
            if k in d and not _is_blank(d[k]):
                payload[k] = d[k]
        path = client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/SNMPNotification")
        body = {"data": payload}
        self._log_api_start("POST", path, "notify.snmp", client.tenant, node, rule_name, body)
        resp = client.post_json(path, body)
        self._log_api_ok("POST", path, "notify.snmp", client.tenant, node, rule_name)
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
        if job_id:
            self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
            ok, _ = client.monitor_job(pool, node.id, job_id)
            if ok:
                self._log_monitor_done(job_id, client.tenant, node, rule_name)
            else:
                self._log_monitor_fail(job_id, client.tenant, node, rule_name, "notify snmp monitor failed")
        elif mon_path:
            self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
            ok, _ = client.monitor_job_url(mon_path)
            if ok:
                self._log_monitor_done("<url>", client.tenant, node, rule_name)
            else:
                self._log_monitor_fail("<url>", client.tenant, node, rule_name, "notify snmp monitor failed")

    def _post_ssh_notification(
        self, client: DirectorClient, pool: str, node: NodeRef, rule_id: str, d: Dict[str, Any], rule_name: str
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

        path = client.configapi(pool, node.id, f"{self.RESOURCE}/{rule_id}/SSHNotification")
        body = {"data": payload}
        self._log_api_start("POST", path, "notify.ssh", client.tenant, node, rule_name, body)
        resp = client.post_json(path, body)
        self._log_api_ok("POST", path, "notify.ssh", client.tenant, node, rule_name)
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        mon_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
        if job_id:
            self._log_monitor_start(job_id, f"(job:{job_id})", client.tenant, node, rule_name)
            ok, _ = client.monitor_job(pool, node.id, job_id)
            if ok:
                self._log_monitor_done(job_id, client.tenant, node, rule_name)
            else:
                self._log_monitor_fail(job_id, client.tenant, node, rule_name, "notify ssh monitor failed")
        elif mon_path:
            self._log_monitor_start("<url>", mon_path, client.tenant, node, rule_name)
            ok, _ = client.monitor_job_url(mon_path)
            if ok:
                self._log_monitor_done("<url>", client.tenant, node, rule_name)
            else:
                self._log_monitor_fail("<url>", client.tenant, node, rule_name, "notify ssh monitor failed")
