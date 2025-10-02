# SPDX-License-Identifier: MIT
"""
AlertRules XLSX lister (report-only importer).

This importer does not call any Director API. It reads the Alert rules sheet
from the provided XLSX and produces a report table with:
  - name
  - owner
  - assign_to
  - visible_to_users

Design goals:
- PEP8 compliant, self-documented, robust logging.
- Sheet alias support (e.g., "Alert", "AlertRules", "Alert Rules", ...).
- Column alias support, including nested headers like "settings.assigned_to".
- Never mark the run as failed; this is a read-only report. Warnings are fine.

Usage (example):
  python -m lp_tenant_importer_v2.main \
    --tenant core \
    --tenants-file ../tenants.yml \
    --xlsx samples/core_config.xlsx \
    --no-verify \
    list-alert-users
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter, ImportResult

logger = logging.getLogger(__name__)


# Sheet aliases for Alert rules definition
SHEET_ALIASES: Tuple[str, ...] = (
    "Alert",
    "AlertRules",
    "Alert Rules",
    "alerts",
    "alert_rules",
    "Alert rules",
)

# Column alias map. All keys are our normalized target field names.
# All entries are matched against case-insensitive, trimmed column headers.
COLUMN_ALIASES: Dict[str, Tuple[str, ...]] = {
    "name": (
        "name",
        "rule_name",
        "title",
        "alert_name",
    ),
    "owner": (
        "owner",
        "owner name",
        "owner_name",
        "owner_user",
        "owner id",
        "owner_id",
        "owner uuid",
        "owner_uuid",
        "settings.owner",
        "settings.owner_id",
    ),
    "assign_to": (
        "assign_to",
        "assigned_to",
        "assignee",
        "assign to",
        "assigned to",
        "settings.assign_to",
        "settings.assigned_to",
    ),
    "visible_to_users": (
        "visible_to_users",
        "visible for",
        "visible_for",
        "visible users",
        "visible_users",
        "visible to",
        "visible to users",
        "settings.visible_to_users",
        "settings.visible_to",  # some sheets use a shorter name
    ),
}


def _normalize(s: str) -> str:
    """Normalize header strings for alias matching (case/space tolerant)."""
    # collapse all runs of whitespace to single spaces, lowercase
    return " ".join(s.strip().lower().split())


def _best_header(df: pd.DataFrame, candidates: Iterable[str]) -> Optional[str]:
    """
    Find the first present header in the dataframe among candidate aliases.
    Matching is case-insensitive on normalized header names.
    Returns the *actual* header in df.columns if found.
    """
    norm_map = { _normalize(col): col for col in df.columns }
    for cand in candidates:
        key = _normalize(cand)
        if key in norm_map:
            return norm_map[key]
    return None


@dataclass
class _ResolvedColumns:
    name: Optional[str]
    owner: Optional[str]
    assign_to: Optional[str]
    visible_to_users: Optional[str]


class AlertRulesXlsxLister(BaseImporter):
    """
    Report-only importer to list AlertRules user-related fields from XLSX.

    It overrides run_for_nodes to avoid the regular API import pipeline.
    """

    importer_key = "alert_rules_report"  # for logs / consistency
    element_key = "AlertRules"           # reuse generic naming in outputs

    def run_for_nodes(self, *args, **kwargs) -> ImportResult:
        """
        Scan the XLSX, resolve sheet/columns, and produce a list-only report.
        The ImportResult has any_error=False even if some columns are missing.
        """

        # keep backward compatibility with the generic main.py dispatcher
        if args or kwargs:
            logger.debug(
                "%s: run_for_nodes called with extra args by framework; ignored. "
                "args=%s kwargs=%s",
                self.importer_key, args, kwargs
            )        

        nodes = list(self.ctx.nodes or [])
        if not nodes:
            # Keep parity with other importers: read nodes from ctx
            nodes = [self.ctx.node]

        logger.info(
            "%s: starting (xlsx=%s, nodes=%d)",
            self.importer_key,
            self.ctx.xlsx_path,
            len(nodes),
        )

        try:
            xls = pd.ExcelFile(self.ctx.xlsx_path)
        except Exception as exc:  # pragma: no cover
            logger.exception("Failed to open XLSX '%s'", self.ctx.xlsx_path)
            # For a report-only command, still return a result but flag the error.
            rows = [
                self._format_row(
                    node=n, name="<xlsx open failed>", error=str(exc)
                )
                for n in nodes
            ]
            return ImportResult(rows=rows, any_error=True)

        # Pick the first matching sheet alias that exists.
        present_sheets = set(xls.sheet_names)
        sheet_name = next((s for s in SHEET_ALIASES if s in present_sheets), None)
        if sheet_name is None:
            logger.error(
                "%s: none of the expected sheets %s found in %s",
                self.importer_key, SHEET_ALIASES, self.ctx.xlsx_path
            )
            rows = [
                self._format_row(
                    node=n, name="<sheet not found>",
                    error=f"Expected one of {SHEET_ALIASES}"
                )
                for n in nodes
            ]
            return ImportResult(rows=rows, any_error=True)

        try:
            df = xls.parse(sheet_name=sheet_name)
        except Exception as exc:  # pragma: no cover
            logger.exception("Failed to parse sheet '%s'", sheet_name)
            rows = [
                self._format_row(node=n, name="<read failed>", error=str(exc))
                for n in nodes
            ]
            return ImportResult(rows=rows, any_error=True)

        # Resolve the interesting columns with aliasing (including nested names).
        resolved = _ResolvedColumns(
            name=_best_header(df, COLUMN_ALIASES["name"]),
            owner=_best_header(df, COLUMN_ALIASES["owner"]),
            assign_to=_best_header(df, COLUMN_ALIASES["assign_to"]),
            visible_to_users=_best_header(df, COLUMN_ALIASES["visible_to_users"]),
        )

        missing = [
            key for key, val in resolved.__dict__.items() if key != "name" and not val
        ]
        if missing:
            logger.warning(
                "%s: some expected columns are missing in sheet '%s': %s",
                self.importer_key, sheet_name, ", ".join(missing)
            )

        # Prepare rows for each rule, and duplicate across nodes (1:1 looks nicer).
        rows: List[Dict[str, str]] = []
        count_rules = 0

        for _, raw in df.iterrows():
            name_val = self._cell(raw, resolved.name)
            if not name_val:
                # skip empty lines or rules without a name
                continue

            owner_val = self._cell(raw, resolved.owner)
            assign_val = self._cell(raw, resolved.assign_to)
            visible_val = self._cell(raw, resolved.visible_to_users)

            for node in nodes:
                rows.append(
                    self._format_row(
                        node=node,
                        name=str(name_val),
                        owner=self._pretty(owner_val),
                        assign_to=self._pretty(assign_val),
                        visible_to_users=self._pretty(visible_val),
                    )
                )
            count_rules += 1

        logger.info(
            "%s: produced %d row(s) from sheet '%s' for %d node(s).",
            self.importer_key, count_rules, sheet_name, len(nodes)
        )

        # This is a report-only command -> never fail the run.
        return ImportResult(rows=rows, any_error=False)

    # --------------------------------------------------------------------- #
    # Helpers
    # --------------------------------------------------------------------- #

    @staticmethod
    def _cell(raw: pd.Series, col: Optional[str]) -> Optional[str]:
        """Safely extract a cell value as string if the column exists."""
        if not col:
            return None
        try:
            val = raw.get(col, None)
        except Exception:  # pragma: no cover
            return None
        return None if pd.isna(val) else str(val)

    @staticmethod
    def _pretty(val: Optional[str]) -> str:
        """Normalize/pretty print multi-values while staying lossless."""
        if val is None:
            return ""
        # keep as-is; if it's a JSON-ish string or comma list, let the user see it
        return val.strip()

    def _format_row(
        self,
        node,
        name: str,
        owner: str = "",
        assign_to: str = "",
        visible_to_users: str = "",
        error: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Produce a reporting row consistent with the framework's table renderer.
        We keep 'result'='report' and 'action'='list'. No API monitor columns.
        """
        # Framework expects node to expose .siem and .node (like other importers).
        siem = getattr(node, "siem", getattr(node, "logpoint_identifier", ""))
        node_name = getattr(node, "name", getattr(node, "node", ""))

        row = {
            "siem": siem,
            "node": node_name,
            "name": name,
            "result": "report",
            "action": "list",
            "status": "—",
            "monitor_ok": "—",
            "monitor_branch": "—",
            "error": error or "—",
            "corr": "—",
            # Extra informational fields (not part of the standard table header)
            "owner": owner or "",
            "assign_to": assign_to or "",
            "visible_to_users": visible_to_users or "",
        }
        logger.debug("row: %s", row)
        return row
