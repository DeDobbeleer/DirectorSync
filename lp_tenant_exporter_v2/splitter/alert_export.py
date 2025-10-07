# splitter/alert_export.py
# -*- coding: utf-8 -*-
"""
Export alerts from a configuration JSON (AIO or dedicated Search-Head) to flat
DataFrames and route them per tenant according to the 'repos' routing logic.

This module keeps the existing 'Alert' sheet export intact and adds a new
'AlertNotifications' sheet that lists, per alert, one row per notification
found in the configuration JSON.

Routing rules (unchanged):
- repos missing/empty -> all tenants
- 'host:port' (no repo_name) -> all tenants (shared backend)
- 'host:port/repo_name' -> map repo_name to tenant via repo_name_to_tenant

Public API (unchanged + new):
from splitter.alert_export import (
    ALERT_SHEET,
    load_alerts_df,
    write_alert_sheet_per_tenant,
    ALERT_NOTIFICATIONS_SHEET,                         # NEW
    load_alert_notifications_df,                      # NEW
    write_alert_notifications_sheet_per_tenant,       # NEW
)
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd

LOGGER = logging.getLogger(__name__)

ALERT_SHEET = "Alert"
ALERT_NOTIFICATIONS_SHEET = "AlertNotifications"

# ---------- utilities ----------


def _ci_get(d: dict, key: str):
    """Return d[key] in a case-insensitive manner."""
    if not isinstance(d, dict):
        return None
    kl = key.lower()
    for k, v in d.items():
        if str(k).lower() == kl:
            return v
    return None


def _find_alert_list(obj: dict) -> List[dict]:
    """Return the list Sync/AlertRules/Alert (case-insensitive)."""
    sync = _ci_get(obj, "Sync") or _ci_get(obj, "sync") or {}
    ar = _ci_get(sync, "AlertRules") or {}
    alerts = _ci_get(ar, "Alert") or []
    if isinstance(alerts, dict):
        alerts = [alerts]
    return alerts or []


def _flatten(obj: Any, prefix: str, out: Dict[str, Any]):
    """
    Flatten nested dicts into dot-notated columns. Lists are JSON-encoded
    to keep them lossless.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                _flatten(v, key, out)
            elif isinstance(v, list):
                out[key] = json.dumps(v, ensure_ascii=False)
            else:
                out[key] = v
    else:
        out[prefix or "value"] = obj




# ---------- main API: alerts (existing) ----------


def load_alerts_df(source_json: str | Path) -> pd.DataFrame:
    """
    Load the JSON and return a flattened DataFrame (1 row per alert).
    Returns an empty DF with 'alert_index' column if no alert found.
    """
    data = json.loads(Path(source_json).read_text(encoding="utf-8", errors="replace"))
    alerts = _find_alert_list(data)
    if not alerts:
        return pd.DataFrame(columns=["alert_index"])

    rows: List[Dict[str, Any]] = []
    for i, a in enumerate(alerts):
        row: Dict[str, Any] = {"alert_index": i}
        _flatten(a, "", row)

        # Ensure 'settings.repos' exists (JSON list) for routing
        if "settings.repos" not in row:
            row["settings.repos"] = "[]"

        rows.append(row)

    df = pd.DataFrame(rows)

    # Reordering (keep requested headers first if present)
    priority_first = [
        "name",
        "settings.repos",
        "settings.user",
        "settings.assigned_to",
        "settings.visible_to_user",
        "settings.visible_to_users",
        "settings.visible_to",
    ]
    first = [c for c in priority_first if c in df.columns]
    remaining = [c for c in df.columns if c not in first]
    return df[first + remaining]

# ---------- NEW: notifications export ----------

_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "community",  # SNMP
    "bearer",
}


def _mask_secrets(value: Any, key_hint: str | None = None) -> Any:
    """
    Recursively mask sensitive values. If the key name looks sensitive or the value is an
    auth header/token, replace with '****'.
    """
    if isinstance(value, dict):
        return {k: _mask_secrets(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_secrets(v, key_hint) for v in value]
    if isinstance(value, str):
        kh = (key_hint or "").lower()
        if kh in _SENSITIVE_KEYS:
            return "****"
        # Mask common auth-like strings
        if kh in {"header", "headers"} and ("authorization" in value.lower()):
            return "****"
        if any(s in value.lower() for s in ("bearer ", "basic ", "token=", "apikey=", "api_key=")):
            return "****"
    return value


def _normalize_for_json(obj: Any) -> Any:
    """
    Produce a stable, comparable structure:
    - sort dict keys,
    - sort homogeneous string lists,
    - for lists of dicts, sort items by their JSON representation.
    """
    if isinstance(obj, dict):
        return {k: _normalize_for_json(obj[k]) for k in sorted(obj.keys(), key=lambda x: str(x).lower())}
    if isinstance(obj, list):
        if all(isinstance(x, str) for x in obj):
            return sorted(obj, key=lambda s: s.lower())
        if all(isinstance(x, dict) for x in obj):
            return sorted((_normalize_for_json(x) for x in obj), key=lambda d: json.dumps(d, sort_keys=True))
        return [_normalize_for_json(x) for x in obj]
    return obj


def _infer_type_from_collection_name(name: str) -> str | None:
    n = (name or "").lower()
    for t in ("email", "http", "sms", "snmp", "ssh", "syslog"):
        if t in n:
            return t
    if "notification" in n:
        return None
    return None


def _iter_notification_collections(alert: dict) -> List[Tuple[str, List[dict], str | None]]:
    """
    Discover plausible notification lists inside an alert.
    Returns a list of tuples: (source_path, list_of_notifications, type_hint).
    We check first level and 'settings' sub-dict for any key that contains 'notification'
    (case-insensitive). Values can be a list or a single dict.
    """
    results: List[Tuple[str, List[dict], str | None]] = []

    def _collect_from_dict(base: dict, base_path: str):
        for k, v in base.items():
            if "notification" not in str(k).lower():
                continue
            lst: List[dict] = []
            if isinstance(v, list):
                lst = [x for x in v if isinstance(x, dict)]
            elif isinstance(v, dict):
                lst = [v]
            if not lst:
                continue
            type_hint = _infer_type_from_collection_name(str(k))
            results.append((f"{base_path}.{k}" if base_path else str(k), lst, type_hint))

    if isinstance(alert, dict):
        _collect_from_dict(alert, "")
        settings = _ci_get(alert, "settings")
        if isinstance(settings, dict):
            _collect_from_dict(settings, "settings")

    return results


def load_alert_notifications_df(source_json: str | Path) -> pd.DataFrame:
    """
    Load the JSON and return a DataFrame with one row per notification found in each alert.

    Columns:
    - alert_index, alert_name, settings.repos, tenant_scope (filled at write time),
      source_path, notification_index, type, enabled, label, id, params_json

    Notes:
    - 'params_json' contains the full notification object (masked & normalized).
    - If no notifications are found, returns an empty DF with the expected columns.
    """
    data = json.loads(Path(source_json).read_text(encoding="utf-8", errors="replace"))
    alerts = _find_alert_list(data)
    base_cols = [
        "alert_index",
        "alert_name",
        "settings.repos",
        "source_path",
        "notification_index",
        "type",
        "enabled",
        "label",
        "id",
        "params_json",
    ]

    if not alerts:
        return pd.DataFrame(columns=base_cols)

    rows: List[Dict[str, Any]] = []

    for i, alert in enumerate(alerts):
        # parent alert context
        name = _ci_get(alert, "name")
        repos = None
        settings = _ci_get(alert, "settings")
        if isinstance(settings, dict):
            repos = _ci_get(settings, "repos")
        # Ensure JSON string format for routing coherence
        repos_json = json.dumps(repos if isinstance(repos, list) else (repos or []), ensure_ascii=False)

        collections = _iter_notification_collections(alert)
        if not collections:
            continue

        for src_path, notif_list, type_hint in collections:
            for j, notif in enumerate(notif_list):
                # Extract common fields
                n_type = (
                    _ci_get(notif, "type")
                    or _ci_get(notif, "notification_type")
                    or _ci_get(notif, "kind")
                    or type_hint
                )
                enabled = _ci_get(notif, "enabled")
                if isinstance(enabled, str):
                    enabled = enabled.strip().lower() in {"true", "1", "yes", "y"}
                label = _ci_get(notif, "label") or _ci_get(notif, "name")
                n_id = _ci_get(notif, "id") or _ci_get(notif, "uuid")

                # Mask & normalize full payload into params_json
                masked = _mask_secrets(notif)
                normalized = _normalize_for_json(masked)
                params_json = json.dumps(normalized, ensure_ascii=False, sort_keys=True)

                row: Dict[str, Any] = {
                    "alert_index": i,
                    "alert_name": name,
                    "settings.repos": repos_json,
                    "source_path": src_path,
                    "notification_index": j,
                    "type": n_type,
                    "enabled": enabled,
                    "label": label,
                    "id": n_id,
                    "params_json": params_json,
                }
                rows.append(row)

    if not rows:
        return pd.DataFrame(columns=base_cols)

    df = pd.DataFrame(rows)

    # Stable sort for readability (name → type → label/id → index)
    sort_cols = [c for c in ("alert_name", "type", "label", "id", "notification_index") if c in df.columns]
    if sort_cols:
        df = df.sort_values(sort_cols, kind="stable").reset_index(drop=True)

    return df
