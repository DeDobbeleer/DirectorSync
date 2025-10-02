# splitter/alert_export.py
# -*- coding: utf-8 -*-
"""
Export des alertes depuis un JSON (AIO ou Search-Head dédié) vers une DataFrame aplanie,
et routage par tenant selon la logique 'repos'.

Règles de routage:
- repos vide/absent -> tous les tenants
- 'host:port' (sans /) -> tous les tenants (backend mutualisé)
- 'host:port/repo_name' -> on mappe repo_name -> tenant via repo_name_to_tenant

Usage côté intégration:
    from splitter.alert_export import (
        ALERT_SHEET,
        load_alerts_df,
        write_alert_sheet_per_tenant,
    )
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd

ALERT_SHEET = "Alert"

# ---------- utilitaires ----------
def _ci_get(d: dict, key: str):
    """Récupère d[key] de manière insensible à la casse."""
    if not isinstance(d, dict):
        return None
    kl = key.lower()
    for k, v in d.items():
        if str(k).lower() == kl:
            return v
    return None

def _find_alert_list(obj: dict) -> List[dict]:
    """Retourne la liste Sync/AlertRules/Alert (insensible à la casse)."""
    sync = _ci_get(obj, "Sync") or _ci_get(obj, "sync") or {}
    ar = _ci_get(sync, "AlertRules") or {}
    alerts = _ci_get(ar, "Alert") or []
    if isinstance(alerts, dict):
        alerts = [alerts]
    return alerts or []

def _flatten(obj: Any, prefix: str, out: Dict[str, Any]):
    """Aplatissement en colonnes pointées. Les listes sont JSON-encodées (zéro perte)."""
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

def _parse_repo(s: str) -> Tuple[str | None, str | None]:
    if not isinstance(s, str):
        return (None, None)
    m = _repo_rx.match(s)
    if not m:
        return (None, None)
    return (m.group(1), m.group(2))  # (host:port, repo_name or None)

# ---------- API principale ----------
def load_alerts_df(source_json: str | Path) -> pd.DataFrame:
    """
    Charge le JSON et renvoie une DataFrame aplanie (1 ligne par alerte).
    Si aucune alerte trouvée, renvoie une DF vide avec 'alert_index'.
    """
    data = json.loads(Path(source_json).read_text(encoding="utf-8", errors="replace"))
    alerts = _find_alert_list(data)
    if not alerts:
        return pd.DataFrame(columns=["alert_index"])

    rows: List[Dict[str, Any]] = []
    for i, a in enumerate(alerts):
        row: Dict[str, Any] = {"alert_index": i}
        _flatten(a, "", row)
        # S'assurer d'avoir la colonne 'settings.repos' (JSON list) pour le routage
        if "settings.repos" not in row:
            row["settings.repos"] = "[]"
        rows.append(row)

    df = pd.DataFrame(rows)

    # === Réordonnancement demandé ===
    # On force en tête (si présentes) : name, owner, settings.assigned_to,
    # settings.visible_to_user, settings.visible_to_users, settings.visible_to
    priority_first = [
        "name",
        "settings.user",
        "settings.assigned_to",
        "settings.visible_to_user",
        "settings.visible_to_users",
        "settings.visible_to",
    ]
    first = [c for c in priority_first if c in df.columns]

    # Le reste des colonnes, dans l'ordre d'origine
    remaining = [c for c in df.columns if c not in first]
    return df[first + remaining]

def route_alert_to_tenants(
    repos_json: str | list | None,
    tenants: Iterable[str],
    repo_name_to_tenant: Dict[str, str] | None = None,
) -> Tuple[List[str], str]:
    """
    Calcule la/les cibles tenant(s) pour une alerte.
    Retourne (liste_tenants, scope_tag)
      scope_tag ∈ {"all-tenants","backend-wide","repo-mapped","repo-mapped-unknown"}
    """
    tenant_list = list(tenants)
    repo_map = repo_name_to_tenant or {}

    # Normalisation des repos en liste Python
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
            # host:port sans nom de repo => backend mutualisé
            return (tenant_list, "backend-wide")

    if not saw_repo_name:
        return (tenant_list, "backend-wide")

    if tenants_res:
        return (sorted(tenants_res), "repo-mapped")

    # Repo_names présents mais mapping inconnu -> on diffuse à tous (ou gérer autrement si besoin)
    return (tenant_list, "repo-mapped-unknown")

def write_alert_sheet_per_tenant(
    writer: pd.ExcelWriter,
    tenant_name: str,
    alerts_df: pd.DataFrame,
    all_tenants: List[str],
    repo_name_to_tenant: Dict[str, str] | None = None,
) -> None:
    """
    Filtre la DF des alertes pour le tenant courant et écrit la feuille 'Alert' si besoin.
    """
    if alerts_df is None or alerts_df.empty:
        return

    keep_idx: List[int] = []
    scopes: Dict[int, str] = {}
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
