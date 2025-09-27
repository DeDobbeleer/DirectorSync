"""
Reporting helpers to print table or JSON.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List


def print_rows(rows: List[Dict[str, Any]], fmt: str = "table") -> None:
    def _present(v) -> bool:
        return not (v is None or v == "" or v == [])

    candidates = [
        "siem", "node", "name", "policy", "path",
        "result", "action", "status", "monitor_ok", "verified", "error",
    ]
    mandatory = {"siem", "node", "result", "action"}

    if fmt == "json":
        print(json.dumps(rows, indent=2))
        return

    # table
    cols = []
    for c in candidates:
        if (c in mandatory) or any(_present(r.get(c)) for r in rows):
            cols.append(c)

    def _fmt(v, col):
        s = "" if v is None else str(v)
        if col == "node" and len(s) > 16:
            return f"{s[:8]}…{s[-4:]}"
        if s == "":
            return "—"
        if isinstance(v, bool):
            return "✓" if v else "✗"
        return s

    widths = {c: len(c) for c in cols}
    for r in rows:
        for c in cols:
            w = len(_fmt(r.get(c), c))
            widths[c] = max(widths[c], w)

    header = "| " + " | ".join(c.ljust(widths[c]) for c in cols) + " |"
    sep = "| " + " | ".join("-" * widths[c] for c in cols) + " |"
    print(header)
    print(sep)
    for r in rows:
        print("| " + " | ".join(_fmt(r.get(c), c).ljust(widths[c]) for c in cols) + " |")
