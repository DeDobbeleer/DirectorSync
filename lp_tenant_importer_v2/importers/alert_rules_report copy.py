# lp_tenant_importer_v2/importers/alert_rules_report.py
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter
from ..core.config import NodeRef
from ..core.logging_utils import get_logger

log = get_logger(__name__)


class AlertRulesXlsxLister(BaseImporter):
    """
    Read an XLSX sheet containing Alert Rules and produce a report-only table
    with the following columns per node:
      - name, owner, assign_to, visible_to_users
    No Director API calls are executed; this importer only emits rows for the
    standard reporting pipeline (utils.reporting.print_rows).

    Design goals:
      * English, PEP8, self-documented.
      * Error-safe: never crash the run because of missing sheet/columns;
        instead, log and skip rows that cannot be processed.
      * Full logging at DEBUG/INFO/WARNING/ERROR.
      * Tolerant header matching via column aliases.
      * Tolerant sheet selection via sheet aliases.
    """

    resource_name: str = "alert_rules_report"

    # Sheet aliases (first match wins, case-sensitive on dict keys that come from openpyxl)
    # Add/remove aliases here if your workbooks vary.
    sheet_names: Tuple[str, ...] = (
        "AlertRules",
        "Alert_Rules",
        "Alert",          # legacy
        "Alerts",         # legacy
        "Rules",          # if someone exported a trimmed view
    )

    # This is a reporting tool; we don't enforce required columns hard.
    required_columns: Tuple[str, ...] = tuple()

    # Column aliases (normalized compare: lowercase + spaces→underscore)
    _COL_ALIASES: Dict[str, Tuple[str, ...]] = {
        "name": (
            "name", "alert_name", "rule", "rule_name",
        ),
        "owner": (
            "owner", "owners",
        ),
        "assign_to": (
            "assign_to", "assigned_to", "assignee", "assign to",
        ),
        "visible_to_users": (
            "visible_to_users", "visible_to_users_list", "visible_to", "visible_for", "visible to users",
        ),
    }

    # --------------------- helpers ---------------------

    @staticmethod
    def _normalize_header(h: str) -> str:
        """Normalize a header for tolerant matching."""
        return str(h).strip().lower().replace(" ", "_")

    def _pick_col(self, df: pd.DataFrame, logical: str) -> Optional[str]:
        """
        Pick the first matching real column name for a logical field,
        using _COL_ALIASES and normalized comparison.
        """
        want = tuple(self._normalize_header(x) for x in self._COL_ALIASES.get(logical, (logical,)))
        for real in df.columns:
            if self._normalize_header(real) in want:
                return str(real)
        return None

    @staticmethod
    def _as_str(cell: Any) -> str:
        """Best-effort normalization of a scalar cell to a trimmed string."""
        if isinstance(cell, float):
            try:
                if pd.isna(cell):
                    return ""
            except Exception:
                pass
        if cell is None:
            return ""
        return str(cell).strip()

    @staticmethod
    def _flatten_visible(cell: Any) -> str:
        """
        Convert a 'visible_to_users' cell to a canonical ';' joined string.
        Accepts list/tuple, scalar, or NaN.
        """
        if isinstance(cell, float):
            try:
                if pd.isna(cell):
                    return ""
            except Exception:
                pass
        if cell is None:
            return ""
        if isinstance(cell, (list, tuple, set)):
            return ";".join(str(x).strip() for x in cell if str(x).strip())
        return str(cell).strip()

    # --------------------- main pipeline ---------------------

    def run_for_nodes(  # type: ignore[override]
        self,
        client: Any,              # unused (report-only)
        pool_uuid: str,           # unused (report-only)
        nodes: Iterable[NodeRef],
        xlsx_path: str,
        dry_run: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Read the workbook once, select the first existing alias sheet,
        and emit a row per alert rule, per node.
        """
        log.info("alert_rules_report: starting (xlsx=%s, nodes=%d)", xlsx_path, len(list(nodes)))

        try:
            sheets = self.load_xlsx(xlsx_path)
        except Exception as exc:  # pragma: no cover
            log.error("alert_rules_report: failed to load XLSX '%s': %s", xlsx_path, exc)
            return []

        # Choose first sheet that exists in the workbook
        chosen: Optional[str] = None
        for s in self.sheet_names:
            if s in sheets:
                chosen = s
                break

        if not chosen:
            log.warning(
                "alert_rules_report: no AlertRules sheet found among aliases %s in '%s' — nothing to report.",
                self.sheet_names, xlsx_path,
            )
            return []

        df = sheets[chosen].copy()
        df.columns = [str(c).strip() for c in df.columns]
        log.debug("alert_rules_report: using sheet '%s' with columns=%s", chosen, list(df.columns))

        # Resolve headers using aliases
        c_name = self._pick_col(df, "name")
        c_owner = self._pick_col(df, "owner")
        c_assign = self._pick_col(df, "assign_to")
        c_vis = self._pick_col(df, "visible_to_users")

        if not c_name:
            log.warning("alert_rules_report: no 'Name' column alias found on sheet '%s' — all rows skipped.", chosen)

        rows: List[Dict[str, Any]] = []
        nodes_list = list(nodes)

        for node in nodes_list:
            node_tag = f"{getattr(node, 'name', '')}|{getattr(node, 'id', '')}"

            for _, r in df.iterrows():
                name = self._as_str(r.get(c_name, "")) if c_name else ""
                if not name:
                    # The row does not represent a valid alert rule → skip silently.
                    continue

                owner = self._as_str(r.get(c_owner, "")) if c_owner else ""
                assign_to = self._as_str(r.get(c_assign, "")) if c_assign else ""
                visible = self._flatten_visible(r.get(c_vis, "")) if c_vis else ""

                rows.append(
                    {
                        # report identity
                        "siem": getattr(node, "id", ""),
                        "node": node_tag,
                        # business fields
                        "name": name,
                        "owner": owner or "—",
                        "assign_to": assign_to or "—",
                        "visible_to_users": visible or "—",
                        # standard report columns (no API pipeline here)
                        "result": "report",
                        "action": "list",
                        "status": "—",
                        "monitor_ok": "—",
                        "monitor_branch": "—",
                        "error": "",
                        "corr": "—",
                    }
                )

        log.info(
            "alert_rules_report: produced %d row(s) from sheet '%s' for %d node(s).",
            len(rows), chosen, len(nodes_list),
        )
        log.debug("alert_rules_report: first 3 rows preview: %s", rows[:3])
        return rows
