# lp_tenant_importer_v2/importers/alert_rules_report.py
from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter, ImportResult
from ..core.config import NodeRef
from ..core.director_client import DirectorClient

logger = logging.getLogger(__name__)


class AlertRulesXlsxLister(BaseImporter):
    """
    Lightweight report importer that reads Alert Rules from an XLSX workbook
    and outputs a table with: name, owner, assign_to, visible_to_users.

    This importer does NOT call any Director API endpoint; it runs locally
    and just emits "report/list" rows compatible with the global reporting
    table.

    Design notes:
      - We intentionally override `run_for_nodes` instead of using the generic
        diff/apply pipeline from BaseImporter. This keeps the code simple and
        fast for a read-only report.
      - We do NOT rely on `self.ctx`; the framework passes everything via the
        `run_for_nodes` parameters (client, pool_uuid, nodes, xlsx_path, dry_run).
    """

    # Human-friendly resource name (only used for logs).
    resource_name: str = "alert_rules_report"

    # Accept multiple possible sheet names (aliases) to be resilient across files.
    SHEET_ALIASES: Tuple[str, ...] = (
        "Alert",
        "MyAlertRules",
        "SharedAlertRules",
        "VendorAlertRules",
        "AlertRules",
        "Alerts",
    )

    # Column aliases, normalized to "lower snake case" during parsing.
    # We only *require* `name`; other fields are optional.
    COLUMN_ALIASES: Dict[str, Tuple[str, ...]] = {
        "name": ("name", "alert_name", "rule_name", "alert", "rule"),
        "owner": ("settings_user", "owner", "owner_login", "owner_user", "owner_name"),
        "assign_to": (
            "settings_assigned_to",
            "assign_to",
            "assigned_to",
            "assign",
            "assignee",
            "assignto",
            "assign_to_user",
        ),
        "visible_to_users": (
            "settings_visible_to",
            "visible_to_users",
            "visible_for",
            "visible_to",
            "visibles",
            "visibility_users",
            "users_visibility",
        ),
    }

    # ------------------------ helpers ---------------------------------

    @staticmethod
    def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
        """
        Make columns case/space-insensitive by converting to lower_snake_case and
        replacing punctuation that breaks attribute access ('.', '/', '-').
        """
        def norm(s: str) -> str:
            name = str(s).strip().lower()
            # normalize common separators to underscore
            for ch in (" ", "-", ".", "/"):
                name = name.replace(ch, "_")
            # collapse multiple underscores
            while "__" in name:
                name = name.replace("__", "_")
            return name

        df = df.copy()
        df.columns = [norm(c) for c in df.columns]
        return df

    def _resolve_colmap(self, df: pd.DataFrame) -> Dict[str, Optional[str]]:
        """
        Resolve actual column names present in the DataFrame for each canonical key.
        Returns a mapping: canonical -> actual_column_name_or_None.
        """
        cols = set(df.columns)
        colmap: Dict[str, Optional[str]] = {}

        for canonical, aliases in self.COLUMN_ALIASES.items():
            found = next((a for a in aliases if a in cols), None)
            colmap[canonical] = found

        # name must exist; others are optional
        if not colmap["name"]:
            raise ValueError(
                "Required column 'name' not found (checked aliases: "
                f"{', '.join(self.COLUMN_ALIASES['name'])})."
            )

        missing_optional = [
            key for key in ("owner", "assign_to", "visible_to_users")
            if colmap.get(key) is None
        ]
        if missing_optional:
            logger.warning(
                "alert_rules_report: some optional columns are missing in sheet: %s",
                ", ".join(missing_optional),
            )
        logger.debug("alert_rules_report: column resolution map: %s", colmap)
        return colmap

    @staticmethod
    def _pick_sheet(xl: Dict[str, pd.DataFrame], aliases: Iterable[str]) -> Tuple[str, pd.DataFrame]:
        """
        Pick the first available sheet among the provided aliases.
        """
        for name in aliases:
            if name in xl:
                return name, xl[name]
        raise KeyError(f"None of the expected sheets are present: {', '.join(aliases)}")

    @staticmethod
    def _parse_visible(value: object) -> Optional[str]:
        """
        Convert a cell into a normalized, comma-separated list string.
        Accepts lists, sets, tuples, or delimited strings; returns None if empty.
        """
        if value is None or (isinstance(value, float) and pd.isna(value)):
            return None

        if isinstance(value, (list, tuple, set)):
            items = [str(v).strip() for v in value if str(v).strip()]
            return ", ".join(items) if items else None

        s = str(value).strip()
        if not s:
            return None
        # Split on common delimiters and normalize
        parts: List[str] = []
        for piece in [p.strip() for d in (",", ";", "|") for p in s.split(d)]:
            if piece:
                parts.append(piece)
        return ", ".join(parts) if parts else None

    # ------------------------ main entry --------------------------------

    def run_for_nodes(
        self,
        client: DirectorClient,
        pool_uuid: str,
        nodes: List[NodeRef],
        xlsx_path: str,
        dry_run: bool,
        tenant_name: str = None,
    ) -> ImportResult:
        """
        Read the workbook once, then produce one report row per (node x alert).
        No API calls are executed.
        """
        node_count = len(nodes) if nodes else 0
        logger.info(
            "%s: starting (xlsx=%s, nodes=%s)",
            self.resource_name,
            xlsx_path,
            node_count,
        )

        # Load workbook
        try:
            xl = self.load_xlsx(xlsx_path)
        except Exception as exc:
            logger.error("Failed to read Excel file: %s", exc, exc_info=True)
            # Keep the contract: return a result object with a single error row per node
            rows: List[Dict[str, object]] = []
            for node in nodes or []:
                rows.append({
                    "siem": node.id if isinstance(node, NodeRef) else "",
                    "node": node.name if isinstance(node, NodeRef) else "",
                    "name": "<load_error>",
                    "result": "error",
                    "action": "load",
                    "status": "Failed",
                    "error": str(exc),
                })
            return ImportResult(rows=rows, any_error=True)

        # Pick sheet
        try:
            sheet_name, df = self._pick_sheet(xl, self.SHEET_ALIASES)
        except Exception as exc:
            logger.error("Sheet selection failed: %s", exc, exc_info=True)
            rows: List[Dict[str, object]] = []
            for node in nodes or []:
                rows.append({
                    "siem": node.id if isinstance(node, NodeRef) else "",
                    "node": node.name if isinstance(node, NodeRef) else "",
                    "name": "<sheet_error>",
                    "result": "error",
                    "action": "sheet",
                    "status": "Failed",
                    "error": str(exc),
                })
            return ImportResult(rows=rows, any_error=True)

        # Normalize columns and resolve alias mapping
        df = self._normalize_columns(df)
        try:
            colmap = self._resolve_colmap(df)
        except Exception as exc:
            logger.error("Column resolution failed: %s", exc, exc_info=True)
            rows: List[Dict[str, object]] = []
            for node in nodes or []:
                rows.append({
                    "siem": node.id if isinstance(node, NodeRef) else "",
                    "node": node.name if isinstance(node, NodeRef) else "",
                    "name": "<columns_error>",
                    "result": "error",
                    "action": "columns",
                    "status": "Failed",
                    "error": str(exc),
                })
            return ImportResult(rows=rows, any_error=True)

        # Build report rows
        out_rows: List[Dict[str, object]] = []
        alerts_count = 0

        name_col = colmap["name"]
        owner_col = colmap.get("owner")
        assign_col = colmap.get("assign_to")
        visible_col = colmap.get("visible_to_users")

        for rec in df.itertuples(index=False):
            rowd = rec._asdict() # safer access by normalized column name

            # Extract required name
            name = rowd.get(name_col)
            if name is None or (isinstance(name, float) and pd.isna(name)) or str(name).strip() == "":
                logger.debug("Skipping row with empty 'name'")
                continue

            # Optional fields
            owner = getattr(rec, owner_col) if owner_col else None
            assign_to = getattr(rec, assign_col) if assign_col else None
            visible = getattr(rec, visible_col) if visible_col else None
            visible = self._parse_visible(visible)

            alerts_count += 1

            # Emit one row per node for this alert
            for node in nodes or []:
                row = {
                    "siem": node.id,
                    "node": node.name,
                    "name": str(name).strip(),
                    "owner": None if owner is None or (isinstance(owner, float) and pd.isna(owner)) else str(owner).strip(),
                    "assign_to": None if assign_to is None or (isinstance(assign_to, float) and pd.isna(assign_to)) else str(assign_to).strip(),
                    "visible_to_users": visible,
                    "result": "report",
                    "action": "list",
                }
                out_rows.append(row)

        logger.info(
            "%s: produced %d row(s) from sheet '%s' for %d node(s).",
            self.resource_name,
            len(out_rows),
            sheet_name,
            node_count,
        )

        # No API errors possible here; if we reached this point, it's all good.
        return ImportResult(rows=out_rows, any_error=False)
