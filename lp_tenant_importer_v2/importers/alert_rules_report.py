from __future__ import annotations

"""
AlertRules XLSX lister (report-only importer)

- Reads the Alert rules sheet from the provided XLSX and lists:
  Name, Owner, Assign_to, Visible_to_Users.
- No API calls are performed. Works per node, returns a flat table
  enriched with 'siem' and 'node' columns for consistency with the
  rest of the tooling.

Design notes:
- Fully aligned with the BaseImporter contract: returns ImportResult.
- Robust sheet detection with aliases.
- Case-insensitive column access with multiple fallbacks.
- Verbose logging at INFO/DEBUG and explicit error reporting.
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import pandas as pd

from .base import BaseImporter, ImportContext, ImportResult

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _ColMap:
    """Holds canonical names and fallback column aliases (case-insensitive)."""

    name: Tuple[str, ...] = ("name", "rule", "alert", "alert_name", "title")
    owner: Tuple[str, ...] = ("owner", "owned_by")
    assign_to: Tuple[str, ...] = ("assign_to", "assignto", "assigned_to", "assignee")
    visible_to_users: Tuple[str, ...] = (
        "visible_to_users",
        "visible_for",
        "visiblefor",
        "visible_to",
        "visibility",
    )


class AlertRulesXlsxLister(BaseImporter):
    """
    Report-only importer that lists Alert Rules user dependencies from XLSX.

    It adheres to the BaseImporter interface and returns ImportResult so
    that main.py can handle it like any other importer.
    """

    # Canonical sheet name and accepted aliases (case-insensitive)
    CANONICAL_SHEET: str = "Alert"
    SHEET_ALIASES: Mapping[str, str] = {
        # key (lower) -> canonical
        "alert": "Alert",
        "alertrules": "Alert",
        "alert rules": "Alert",
        "alert_rules": "Alert",
        "alertrule": "Alert",
    }

    COLS = _ColMap()

    # ------------------------ BaseImporter API -----------------------------

    def run_for_nodes(self, ctx: ImportContext) -> ImportResult:
        """
        Read the XLSX once, then emit rows for each target node.

        Returns
        -------
        ImportResult
            rows: list of flat dict rows
            any_error: True if any non-fatal processing error occurred
        """
        xlsx_path = ctx.xlsx_path
        nodes = list(ctx.nodes)
        log.info(
            "alert_rules_report: starting (xlsx=%s, nodes=%d)",
            xlsx_path,
            len(nodes),
        )

        any_error = False
        rows: List[Dict[str, Any]] = []

        # Load the workbook and locate the sheet
        try:
            xl = pd.ExcelFile(xlsx_path)
            sheet_name = self._resolve_sheet_name(xl.sheet_names)
            if sheet_name is None:
                msg = (
                    "No sheet named 'Alert' (or aliases) found. "
                    f"Available sheets: {xl.sheet_names}"
                )
                log.error("alert_rules_report: %s", msg)
                return ImportResult(rows=[], any_error=True)
        except Exception as exc:  # noqa: BLE001
            log.exception("alert_rules_report: failed to open XLSX: %s", exc)
            return ImportResult(rows=[], any_error=True)

        # Parse sheet content once
        try:
            df = pd.read_excel(
                xlsx_path,
                sheet_name=sheet_name,
                dtype=str,
                keep_default_na=False,
                engine=None,  # let pandas pick available engine
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("alert_rules_report: failed to read sheet '%s': %s", sheet_name, exc)
            return ImportResult(rows=[], any_error=True)

        if df.empty:
            log.info("alert_rules_report: sheet '%s' is empty.", sheet_name)
            # Still return success (no rows), not an error
            return ImportResult(rows=[], any_error=False)

        # Normalize column names once (lower strip)
        norm_cols = {c.lower().strip(): c for c in df.columns}
        log.debug("alert_rules_report: detected columns: %s", list(df.columns))

        # Resolve each needed column with fallbacks
        try:
            col_name = self._first_present(self.COLS.name, norm_cols)
            col_owner = self._first_present(self.COLS.owner, norm_cols)
            col_assign_to = self._first_present(self.COLS.assign_to, norm_cols)
            col_visible = self._first_present(self.COLS.visible_to_users, norm_cols)
        except KeyError as missing:
            any_error = True
            log.error("alert_rules_report: missing required column: %s", missing)
            return ImportResult(rows=[], any_error=True)

        # Build rows per node to preserve the common output shape
        error_count = 0
        for _, r in df.iterrows():
            try:
                base_row = {
                    "name": self._normalize_text(r[norm_cols[col_name]]),
                    "owner": self._normalize_text(r[norm_cols[col_owner]]),
                    "assign_to": self._normalize_text(r[norm_cols[col_assign_to]]),
                    "visible_to_users": self._normalize_text(r[norm_cols[col_visible]]),
                }
            except Exception as exc:  # noqa: BLE001
                # Malformed row — record it and continue
                error_count += 1
                any_error = True
                log.warning("alert_rules_report: bad row encountered: %s", exc, exc_info=True)
                base_row = {
                    "name": "",
                    "owner": "",
                    "assign_to": "",
                    "visible_to_users": "",
                    "error": f"Malformed row: {exc}",
                }

            # Duplicate the row for each node so the table keeps siem/node context
            for node in nodes:
                enriched = {
                    "siem": getattr(node, "siem", getattr(node, "logpoint_identifier", "")),
                    "node": getattr(node, "name", getattr(node, "node", "")),
                    **base_row,
                }
                rows.append(enriched)

        log.info(
            "alert_rules_report: produced %d row(s) from sheet '%s' for %d node(s).",
            len(rows),
            sheet_name,
            len(nodes),
        )
        if error_count:
            log.warning("alert_rules_report: %d malformed row(s) were skipped/recorded.", error_count)

        return ImportResult(rows=rows, any_error=any_error)

    # ------------------------ helpers -------------------------------------

    @staticmethod
    def _normalize_text(value: Any) -> str:
        """Return a clean string for cell content."""
        if value is None:
            return ""
        s = str(value).strip()
        # Normalize common falsy literals
        if s.lower() in {"nan", "none", "null", "-"}:
            return ""
        return s

    @classmethod
    def _resolve_sheet_name(cls, sheet_names: Iterable[str]) -> Optional[str]:
        """
        Given the list of sheet names, find the Alert sheet using aliases.

        The match is case-insensitive. Returns the actual sheet name if found.
        """
        # Direct match first
        for s in sheet_names:
            if s.strip().lower() == cls.CANONICAL_SHEET.lower():
                return s

        # Alias match
        lowered = {s.lower(): s for s in sheet_names}
        for alias in cls.SHEET_ALIASES.keys():
            if alias in lowered:
                return lowered[alias]

        return None

    @staticmethod
    def _first_present(candidates: Tuple[str, ...], norm_cols: Mapping[str, str]) -> str:
        """
        Return the *normalized* key of the first candidate present in norm_cols.

        Parameters
        ----------
        candidates : Tuple[str, ...]
            Candidate names to try (already lowercase).
        norm_cols : Mapping[str, str]
            Mapping normalized_name -> actual DataFrame column name.

        Raises
        ------
        KeyError
            If none of the candidates are present.
        """
        for c in candidates:
            key = c.lower().strip()
            if key in norm_cols:
                return key
        raise KeyError(f"none of {candidates} found")
