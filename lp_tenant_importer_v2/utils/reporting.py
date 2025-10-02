"""
Reporting helpers (table or JSON) for importer results.

`print_rows` auto-selects relevant columns and produces a compact table that
fits CLI usage. JSON output is also supported for machine consumption.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

log = logging.getLogger(__name__)


def _derive_status(op_result: dict) -> str:
    """Final status for the row, with monitor_ok taking precedence."""
    mon_ok = op_result.get("monitor_ok", None)
    if mon_ok is True:
        return "Success"
    if mon_ok is False:
        return "Failed"
    # No monitor info (sync/disabled): fall back to API-returned status
    return op_result.get("status") or "—"


def _monitor_icon(mon_ok: object) -> str:
    if mon_ok is True:
        return "✓"
    if mon_ok is False:
        return "✗"
    return "—"


def _normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a raw result row so the table is consistent:
    - status derived from monitor_ok when present,
    - monitor_ok rendered as an icon,
    - ensure monitor_branch/corr/error columns exist,
    - log a warning on status/monitor mismatch.
    """
    r = dict(row)  # shallow copy

    # Derive and enforce final status
    final_status = _derive_status(r)

    # Detect/report inconsistencies (if both status and monitor_ok are present)
    raw_status = r.get("status")
    mon_ok = r.get("monitor_ok")
    if isinstance(mon_ok, bool) and isinstance(raw_status, str):
        expected = "Success" if mon_ok else "Failed"
        if raw_status and raw_status != expected:
            log.warning(
                "reporting: status/monitor mismatch (status=%s monitor_ok=%s branch=%s corr=%s)",
                raw_status, mon_ok, r.get("monitor_branch"), r.get("corr"),
            )

    # Apply normalized fields
    r["status"] = final_status
    r["monitor_ok"] = _monitor_icon(mon_ok)
    r["monitor_branch"] = r.get("monitor_branch") or "—"
    r["corr"] = r.get("corr") or "—"

    err = r.get("error")
    r["error"] = (str(err).strip()[:160] if isinstance(err, (str, bytes)) and str(err).strip() else "—")

    return r


def print_rows(rows: List[Dict[str, Any]], fmt: str = "table") -> None:
    """Render importer result rows as a table or JSON.

    Args:
        rows: List of dict rows with common fields (e.g., siem, node, name, action).
        fmt: Either ``"table"`` (default) or ``"json"``.
    """
    # Normalize all rows first so columns are consistent
    norm_rows = [_normalize_row(r) for r in rows]

    def _present(v) -> bool:
        return not (v is None or v == "" or v == [])

    # Candidate columns in preferred order
    candidates = [
        "siem",
        "node",
        "name",
        "policy",
        "path",
        "result",
        "owner",
        "assign_to",
        "visible_to_users",
        "action",
        "status",
        "monitor_ok",
        "monitor_branch",
        "verified",
        "error",
        "corr",
    ]
    mandatory = {"siem", "node", "result", "action"}

    if fmt == "json":
        print(json.dumps(norm_rows, indent=2))
        return

    # Table mode
    cols: List[str] = []
    for c in candidates:
        if (c in mandatory) or any(_present(r.get(c)) for r in norm_rows):
            cols.append(c)

    def _fmt(v, col):
        s = "" if v is None else str(v)
        if col == "node" and len(s) > 16:
            return f"{s[:8]}…{s[-4:]}"
        if s == "":
            return "—"
        # Booleans (if any remain) will still print as ✓/✗
        if isinstance(v, bool):
            return "✓" if v else "✗"
        return s

    widths = {c: len(c) for c in cols}
    for r in norm_rows:
        for c in cols:
            w = len(_fmt(r.get(c), c))
            widths[c] = max(widths[c], w)

    header = "| " + " | ".join(c.ljust(widths[c]) for c in cols) + " |"
    sep = "| " + " | ".join("-" * widths[c] for c in cols) + " |"
    print(header)
    print(sep)
    for r in norm_rows:
        print("| " + " | ".join(_fmt(r.get(c), c).ljust(widths[c]) for c in cols) + " |")
