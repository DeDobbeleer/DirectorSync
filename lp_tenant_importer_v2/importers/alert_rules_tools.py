# lp_tenant_importer_v2/importers/alert_rules_tools.py
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import pandas as pd

from lp_tenant_importer_v2.core.logging_utils import get_logger

LOG = get_logger(__name__)

# ---- helpers ---------------------------------------------------------------

def _pick_sheet(xlsx: Path) -> str:
    """Pick the AlertRules sheet (robust to naming variants)."""
    xf = pd.ExcelFile(xlsx)
    # perfect matches first
    candidates = [s for s in xf.sheet_names if s.strip().lower() in {
        "alertrules", "alert_rules", "alert rules"
    }]
    if candidates:
        return candidates[0]
    # fuzzy: any sheet that contains 'alert' and 'rule'
    low = [(s, s.lower()) for s in xf.sheet_names]
    for s, ls in low:
        if "alert" in ls and "rule" in ls:
            return s
    # fallback: first sheet
    return xf.sheet_names[0]


_COL_ALIASES: Dict[str, Tuple[str, ...]] = {
    "name": ("name", "alert name", "rule name", "alert_name", "rule"),
    "owner": ("owner", "owned by", "rule_owner"),
    "assign_to": ("assign_to", "assign to", "assigned_to", "assigned to", "assignto"),
    "visible_to_users": (
        "visible_to_users",
        "visible for users",
        "visible_for_users",
        "visible users",
        "visible",
        "visibility",
    ),
}

def _resolve_columns(df: pd.DataFrame) -> Dict[str, str]:
    """Map canonical -> actual dataframe column names (case/space/underscore insensitive)."""
    cols_norm = {c: c.strip().lower().replace(" ", "_") for c in df.columns}
    by_norm = {v: k for k, v in cols_norm.items()}
    resolved: Dict[str, str] = {}
    for canon, aliases in _COL_ALIASES.items():
        for alias in aliases:
            if alias in by_norm:
                resolved[canon] = by_norm[alias]
                break
    missing = [k for k in ("name", "owner", "assign_to", "visible_to_users") if k not in resolved]
    if missing:
        raise KeyError(
            f"Missing required columns in sheet: {', '.join(missing)}. "
            f"Present columns={list(df.columns)}"
        )
    return resolved


def _to_markdown(rows: List[Dict[str, str]]) -> str:
    headers = ["Alert Name", "Owner", "Assign_to", "Visible_to_Users"]
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        out.append("| " + " | ".join([
            str(r.get("name", "")) or "",
            str(r.get("owner", "")) or "",
            str(r.get("assign_to", "")) or "",
            str(r.get("visible_to_users", "")) or "",
        ]) + " |")
    return "\n".join(out)


# ---- command ---------------------------------------------------------------

def cmd_list_alert_user_visibility(args: argparse.Namespace, env: dict, cfg: dict) -> int:
    """
    List AlertRules [Name, Owner, Assign_to, Visible_to_Users] from the XLSX only.
    - No Director API calls
    - Output: table (stdout) | md | csv | json (stdout or --output)
    """
    xlsx_path = Path(args.xlsx).expanduser()
    if not xlsx_path.exists():
        LOG.error("XLSX not found: %s", xlsx_path)
        return 2

    fmt = (getattr(args, "format", None) or "table").lower()
    out_file = getattr(args, "output", None)
    sheet = getattr(args, "sheet", None) or _pick_sheet(xlsx_path)

    LOG.info("listing.alert_rules.start xlsx=%s sheet=%s format=%s", xlsx_path, sheet, fmt)

    df = pd.read_excel(xlsx_path, sheet_name=sheet, dtype=str).fillna("")
    colmap = _resolve_columns(df)

    # Normalize output rows
    rows: List[Dict[str, str]] = []
    for _, r in df.iterrows():
        rows.append({
            "name": r[colmap["name"]].strip(),
            "owner": r[colmap["owner"]].strip(),
            "assign_to": r[colmap["assign_to"]].strip(),
            "visible_to_users": r[colmap["visible_to_users"]].strip(),
        })

    # emit
    payload = None
    if fmt in ("md", "markdown", "table"):
        payload = _to_markdown(rows)
    elif fmt == "csv":
        payload = "Alert Name,Owner,Assign_to,Visible_to_Users\n" + "\n".join(
            f'{r["name"]},{r["owner"]},{r["assign_to"]},{r["visible_to_users"]}' for r in rows
        )
    elif fmt == "json":
        payload = json.dumps(rows, ensure_ascii=False, indent=2)
    else:
        LOG.error("Unknown --format: %s", fmt)
        return 2

    if out_file:
        Path(out_file).write_text(payload, encoding="utf-8")
        LOG.info("listing.alert_rules.written file=%s", out_file)
    else:
        # stdout
        sys.stdout.write(payload + ("\n" if not payload.endswith("\n") else ""))

    LOG.info("listing.alert_rules.done count=%d", len(rows))
    return 0
