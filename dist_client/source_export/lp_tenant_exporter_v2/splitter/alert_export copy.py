# splitter/alert_export.py
"""
Export alerts from a JSON dump (AIO or dedicated Search-Head) to a flattened DataFrame,
and route per tenant using the 'repos' logic.

Routing rules:
- empty/missing repos -> all tenants
- 'host:port' (no /) -> all tenants (shared backend)
- 'host:port/repo_name' -> map repo_name -> tenant via repo_name_to_tenant

Integration usage:
    from splitter.alert_export import (
        ALERT_SHEET,
        load_alerts_df,
        write_alert_sheet_per_tenant,
    )
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pandas as pd

ALERT_SHEET = "Alert"

# ---------- utilities ----------
def _ci_get(d: dict, key: str):
    """Get d[key] case-insensitively."""
    if not isinstance(d, dict):
        return None
    kl = key.lower()
    for k, v in d.items():
        if str(k).lower() == kl:
            return v
    return None

def _find_alert_list(obj: dict) -> list[dict]:
    """Return the Sync/AlertRules/Alert list (case-insensitive)."""
    sync = _ci_get(obj, "Sync") or _ci_get(obj, "sync") or {}
    ar = _ci_get(sync, "AlertRules") or {}
    alerts = _ci_get(ar, "Alert") or []
    if isinstance(alerts, dict):
        alerts = [alerts]
    return alerts or []

def _flatten(obj: Any, prefix: str, out: dict[str, Any]):
    """Flatten into dotted columns. Lists are JSON-encoded (zero loss)."""
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

_repo_rx = re.compile(r"^\s*([^/\s]+)\s*(?:/\s*([^/\s]+))?\s*$")  # host:port[/repo_name]

def _parse_repo(s: str) -> tuple[str | None, str | None]:
    if not isinstance(s, str):
        return (None, None)
    m = _repo_rx.match(s)
    if not m:
        return (None, None)
    return (m.group(1), m.group(2))  # (host:port, repo_name or None)

# ---------- main API ----------
def load_alerts_df(source_json: str | Path) -> pd.DataFrame:
    """
    Load the JSON and return a flattened DataFrame (1 row per alert).
    If no alert is found, return an empty DataFrame with 'alert_index'.
    """
    data = json.loads(Path(source_json).read_text(encoding="utf-8", errors="replace"))
    alerts = _find_alert_list(data)
    if not alerts:
        return pd.DataFrame(columns=["alert_index"])

    rows: list[dict[str, Any]] = []
    for i, a in enumerate(alerts):
        row: dict[str, Any] = {"alert_index": i}
        _flatten(a, "", row)
        # Ensure the 'settings.repos' column (JSON list) exists for routing
        if "settings.repos" not in row:
            row["settings.repos"] = "[]"
        rows.append(row)

    df = pd.DataFrame(rows)

    # === Requested reordering ===
    # Force to the front (if present): name, owner, settings.assigned_to,
    # settings.visible_to_user, settings.visible_to_users, settings.visible_to
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

    # Remaining columns in original order
    remaining = [c for c in df.columns if c not in first]
    return df[first + remaining]

def route_alert_to_tenants(
    repos_json: str | list | None,
    tenants: Iterable[str],
    repo_name_to_tenant: dict[str, str] | None = None,
) -> tuple[list[str], str]:
    """
    Compute the target tenant(s) for an alert.
    Returns (tenant_list, scope_tag)
      scope_tag ∈ {"all-tenants","backend-wide","repo-mapped","repo-mapped-unknown"}
    """
    tenant_list = list(tenants)
    repo_map = repo_name_to_tenant or {}

    # Normalize repos to a Python list
    if repos_json is None:
        return (tenant_list, "all-tenants")

    if isinstance(repos_json, str):
        try:
            repos = json.loads(repos_json)
        except Exception:
            repos = []
    elif isinstance(repos_json, list):
        repos = repos_json
    else:
        repos = []

    repos = [r for r in repos if isinstance(r, str)]
    if not repos:
        return (tenant_list, "all-tenants")

    saw_repo_name = False
    tenants_res = set()
    for r in repos:
        host, repo_name = _parse_repo(r)
        if repo_name:
            saw_repo_name = True
            t = repo_map.get(repo_name)
            if t:
                tenants_res.add(t)
        else:
            # host:port without repo name => shared backend
            return (tenant_list, "backend-wide")

    if not saw_repo_name:
        return (tenant_list, "backend-wide")

    if tenants_res:
        return (sorted(tenants_res), "repo-mapped")

    # Repo names present but unknown mapping -> broadcast to all (or handle differently if needed)
    return (tenant_list, "repo-mapped-unknown")

def write_alert_sheet_per_tenant(
    writer: pd.ExcelWriter,
    tenant_name: str,
    alerts_df: pd.DataFrame,
    all_tenants: list[str],
    repo_name_to_tenant: dict[str, str] | None = None,
) -> None:
    """
    Filter the alert DataFrame for the current tenant and write the 'Alert' sheet if needed.
    """
    if alerts_df is None or alerts_df.empty:
        return

    keep_idx: list[int] = []
    scopes: dict[int, str] = {}
    for i, r in alerts_df.iterrows():
        tgt, scope = route_alert_to_tenants(
            r.get("settings.repos"),
            all_tenants,
            repo_name_to_tenant,
        )
        if tenant_name in tgt:
            keep_idx.append(i)
            scopes[i] = scope

    if not keep_idx:
        return

    out = alerts_df.loc[keep_idx].copy()
    out["tenant_scope"] = [scopes[i] for i in keep_idx]
    out.to_excel(writer, sheet_name=ALERT_SHEET, index=False)
