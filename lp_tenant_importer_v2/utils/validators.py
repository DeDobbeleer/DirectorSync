"""
XLSX validators (required sheets/columns).
"""
from __future__ import annotations

from typing import Dict, Iterable, List


class ValidationError(Exception):
    pass


def require_sheets(xlsx_sheets: Dict[str, "pd.DataFrame"], required: Iterable[str]) -> None:
    missing = [s for s in required if s not in xlsx_sheets]
    if missing:
        raise ValidationError(f"Missing required sheets: {', '.join(missing)}")


def require_columns(df: "pd.DataFrame", required: Iterable[str]) -> None:
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValidationError(f"Missing required columns: {', '.join(missing)}")
