# lp_tenant_importer_v2/importers/alert_rules_report.py
"""
Alert Rules XLSX Lister (report-only importer).

This importer reads the Alert Rules sheet from the tenant XLSX and produces
a tabular report with the following fields per row:
  - siem (node id)
  - node (node name)
  - name (Alert/Rule name)
  - owner
  - assign_to
  - visible_to_users

Notes
-----
* No API calls are made. This is a read-only, reporting-oriented importer.
* Sheet and column names are resolved using flexible aliases.
* The importer returns ImportResult to integrate with the common CLI pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter, ImportResult
from ..core.logging_utils import get_logger

log = get_logger(__name__)


def _norm_token(s: str) -> str:
    """Normalize labels for matching (lowercase, strip, collapse separators)."""
    return "".join(ch for ch in s.strip().lower().replace(" ", "_") if ch.isalnum() or ch == "_")


@dataclass(frozen=True)
class ColumnAlias:
    key: str                  # canonical key in our output (e.g. "name")
    aliases: Tuple[str, ...]  # acceptable header names in the XLSX


class AlertRulesXlsxLister(BaseImporter):
    """
    Read the XLSX and list Alert Rules user-related fields.

    This importer intentionally overrides :meth:`run_for_nodes` to avoid the
    generic create/update pipeline, since it only produces a report.
    """

    resource_name: str = "alert_rules_report"

    # Accept multiple sheet titles (flexible matching)
    SHEET_ALIASES: Tuple[str, ...] = (
        "Alert",
        "Alerts",
        "AlertRules",
        "Alert Rules",
        "Alert_Rules",
        "Alertrules",
    )

    # Flexible column headers (case/spacing/underscore-insensitive)
    COLS: Tuple[ColumnAlias, ...] = (
        ColumnAlias("name", ("alert name", "rule name", "name", "alert", "rule")),
        ColumnAlias("owner", ("owner", "alert_owner", "owner_user", "owner uuid", "owner_id")),
        ColumnAlias("assign_to", ("assign_to", "assigned_to", "assignee", "assign to", "assignment")),
        ColumnAlias(
            "visible_to_users",
            (
                "visible_to_users",
                "visible for",
                "visible_for",
                "visible_users",
                "visible to",
                "visible_for_users",
            ),
        ),
    )

    # What we will emit for missing data
    MISSING: str = "—"

    # --------------------------------------------------------------------- #
    # Public API (BaseImporter)
    # --------------------------------------------------------------------- #

    def run_for_nodes(
        self,
        client: Any,
        pool_uuid: str,
        nodes: Iterable[Any],
        xlsx_path: Path,
        dry_run: bool = False,
    ) -> ImportResult:
        """
        Load the workbook once, extract the Alert Rules sheet, and emit
        a row per rule per target node.
        """
        rows: List[Dict[str, Any]] = []
        any_error = False

        log.info(
            "%s: starting (xlsx=%s, nodes=%d)",
            self.resource_name,
            str(xlsx_path),
            len(list(nodes)),
        )

        try:
            sheet_name, df = self._load_alert_sheet(xlsx_path)
            if df is None:
                log.error(
                    "%s: could not find an Alert Rules sheet (aliases=%s)",
                    self.resource_name,
                    ", ".join(self.SHEET_ALIASES),
                )
                return ImportResult(rows=[], any_error=True)

            # Resolve columns using aliases
            col_map = self._resolve_columns(df)
            for key, col in col_map.items():
                log.debug("Resolved column '%s' -> '%s'", key, col if col else "<missing>")

            missing_keys = [k for k, v in col_map.items() if not v]
            if missing_keys:
                any_error = True
                log.warning(
                    "%s: some expected columns are missing in sheet '%s': %s",
                    self.resource_name,
                    sheet_name,
                    ", ".join(missing_keys),
                )

            # Build normalized view
            name_col = col_map.get("name")
            owner_col = col_map.get("owner")
            assign_col = col_map.get("assign_to")
            visible_col = col_map.get("visible_to_users")

            df_iter = df if name_col else pd.DataFrame()  # nothing to iterate if we don't have names

            for _, r in df_iter.iterrows():
                alert_name = self._safe_str(r.get(name_col)) if name_col else self.MISSING
                owner = self._safe_str(r.get(owner_col)) if owner_col else self.MISSING
                assign_to = self._safe_str(r.get(assign_col)) if assign_col else self.MISSING
                visible_to_users = self._safe_str(r.get(visible_col)) if visible_col else self.MISSING

                # Skip empty name lines (common in spreadsheets)
                if not alert_name or alert_name == self.MISSING:
                    continue

                for n in nodes:
                    rows.append(
                        {
                            "siem": getattr(n, "id", ""),
                            "node": getattr(n, "name", ""),
                            "sheet": sheet_name,
                            "name": alert_name,
                            "owner": owner,
                            "assign_to": assign_to,
                            "visible_to_users": visible_to_users,
                            # Report-only cosmetics (kept to fit the common table)
                            "result": "report",
                            "action": "list",
                            "status": self.MISSING,
                            "monitor_ok": self.MISSING,
                            "monitor_branch": self.MISSING,
                            "error": self.MISSING,
                        }
                    )

            log.info(
                "%s: produced %d row(s) from sheet '%s' for %d node(s).",
                self.resource_name,
                len(rows),
                sheet_name,
                len(list(nodes)),
            )

        except FileNotFoundError:
            any_error = True
            log.exception("%s: XLSX not found at %s", self.resource_name, str(xlsx_path))
        except Exception:
            any_error = True
            log.exception("%s: unexpected failure while reading XLSX", self.resource_name)

        return ImportResult(rows=rows, any_error=any_error)

    # --------------------------------------------------------------------- #
    # Helpers
    # --------------------------------------------------------------------- #

    def _load_alert_sheet(self, xlsx_path: Path) -> Tuple[str, Optional[pd.DataFrame]]:
        """
        Return (sheet_name, DataFrame) for the first sheet whose name matches
        one of SHEET_ALIASES. Returns (\"\", None) if not found.
        """
        xlsx_path = Path(xlsx_path)
        if not xlsx_path.exists():
            raise FileNotFoundError(str(xlsx_path))

        xl = pd.ExcelFile(xlsx_path)
        available = xl.sheet_names

        # Try exact/normalized match in order
        target_norms = [_norm_token(s) for s in self.SHEET_ALIASES]
        for sheet in available:
            if _norm_token(sheet) in target_norms:
                df = xl.parse(sheet)
                log.debug("Selected sheet '%s' out of available: %s", sheet, ", ".join(available))
                return sheet, df

        # Not found
        log.warning(
            "%s: no matching alert sheet. Available sheets: %s",
            self.resource_name,
            ", ".join(available),
        )
        return "", None

    def _resolve_columns(self, df: pd.DataFrame) -> Dict[str, Optional[str]]:
        """
        Find best-matching columns according to COLS. Matching is case/spacing
        insensitive and tries multiple aliases.
        """
        header_norm_map = {_norm_token(c): str(c) for c in df.columns}

        def pick(aliases: Iterable[str]) -> Optional[str]:
            for alias in aliases:
                norm = _norm_token(alias)
                if norm in header_norm_map:
                    return header_norm_map[norm]
            return None

        col_map: Dict[str, Optional[str]] = {}
        for col in self.COLS:
            col_map[col.key] = pick(col.aliases)

        return col_map

    @staticmethod
    def _safe_str(value: Any) -> str:
        """Return a clean string for CSV-like outputs."""
        if value is None:
            return ""
        s = str(value).strip()
        # Collapse Excel NaN-like strings
        if s.lower() in {"nan", "nat", "none"}:
            return ""
        return s
