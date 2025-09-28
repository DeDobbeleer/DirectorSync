"""
XLSX validators (required sheets/columns).
"""
from __future__ import annotations

from typing import Dict, Iterable
import pandas as pd


class ValidationError(Exception):
    """Raised when the XLSX configuration is missing sheets or columns."""
    pass


def require_sheets(xlsx_sheets: Dict[str, pd.DataFrame], required: Iterable[str]) -> None:
    """Ensure that all required sheet names are present."""
    missing = [s for s in required if s not in xlsx_sheets]
    if missing:
        raise ValidationError(f"Missing required sheets: {', '.join(missing)}")


def require_columns(df: pd.DataFrame, required: Iterable[str]) -> None:
    """Ensure that all required columns are present in a DataFrame."""
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValidationError(f"Missing required columns: {', '.join(missing)}")

def require_columns(
    df: pd.DataFrame,
    required: Iterable[str],
    context: str | None = None,
) -> None:
    """Ensure that all required columns are present in a DataFrame.

    Parameters
    ----------
    df : pandas.DataFrame
        The DataFrame to validate.
    required : Iterable[str]
        Column names that must be present in ``df``.
    context : str, optional
        Extra information to prepend to the error message (e.g., the sheet
        name). If provided, it will be formatted as "{context}: ...".

    Raises
    ------
    ValidationError
        If one or more required columns are missing.
    """
    missing = [c for c in required if c not in df.columns]
    if missing:
        prefix = f"{context}: " if context else ""
        raise ValidationError(
            f"{prefix}Missing required columns: {', '.join(missing)}"
        )

