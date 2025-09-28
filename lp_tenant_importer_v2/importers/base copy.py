"""
BaseImporter — orchestrates load → validate → fetch → diff → plan → apply → report.

Concrete importers only implement resource-specific hooks for validation,
equality, and payload building. Everything else is handled here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.diff_engine import Decision, decide
from ..utils.validators import require_sheets, require_columns, ValidationError


@dataclass
class ImportResult:
    """Aggregate result for a run across multiple nodes."""
    rows: List[Dict[str, Any]]
    any_error: bool


class BaseImporter:
    """Abstract base class for all importers.

    Subclasses must set the class attributes below and implement the hook methods.

    Class Attributes:
        resource_name: Short resource identifier (e.g., "repos").
        sheet_names: Required Excel sheet names.
        required_columns: Required columns present in every sheet referenced.
        compare_keys: Keys used for subset comparison in the diff step.
    """
    resource_name: str = "resource"
    sheet_names: Tuple[str, ...] = ()
    required_columns: Tuple[str, ...] = ()
    compare_keys: Tuple[str, ...] = ()

    def load_xlsx(self, xlsx_path: str) -> Dict[str, pd.DataFrame]:
        """Load an Excel workbook into a dict of DataFrames keyed by sheet name.

        Raises:
            RuntimeError: If the file cannot be read.
        """
        from pathlib import Path
        p = Path(xlsx_path)
        if not p.is_file():
            raise FileNotFoundError(f"{xlsx_path}")
        try:
            xl = pd.read_excel(xlsx_path, sheet_name=None, engine="openpyxl")
        except Exception as exc:
            raise RuntimeError(f"Failed to read {xlsx_path}: {exc}") from exc
        return xl

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:
        """Validate presence of required sheets and columns."""
        require_sheets(sheets, self.sheet_names)
        for sheet in self.sheet_names:
            require_columns(sheets[sheet], self.required_columns)

    # ----- hooks to implement -----
    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        """Return a mapping ``name -> existing_obj`` for the node."""
        raise NotImplementedError

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        """Yield canonical desired rows parsed from the Excel sheets."""
        raise NotImplementedError

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        """Return the unique key (usually name) for a desired row."""
        raise NotImplementedError

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """Return the comparable subset for a desired row."""
        raise NotImplementedError

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Return the comparable subset for an existing object."""
        raise NotImplementedError

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        """Build the API create payload for a desired row."""
        raise NotImplementedError

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Build the API update payload for a desired row given the existing object."""
        raise NotImplementedError

    def apply(self, client: DirectorClient, pool_uuid: str, node: NodeRef, decision: Decision, existing_id: str | None) -> Dict[str, Any]:
        """Execute the decided operation (CREATE/UPDATE/NOOP/SKIP) on the API."""
        raise NotImplementedError

    # ----- pipeline -----
    def run_for_nodes(self, client: DirectorClient, pool_uuid: str, nodes: List[NodeRef], xlsx_path: str, dry_run: bool) -> ImportResult:
        """Run the importer for a set of nodes.

        Steps:
            1) Load and validate Excel sheets
            2) Fetch existing objects per node
            3) Diff desired vs existing to produce a plan
            4) Apply (unless dry-run), record results
        """
        sheets = self.load_xlsx(xlsx_path)
        self.validate(sheets)

        rows: List[Dict[str, Any]] = []
        any_error = False

        for node in nodes:
            try:
                existing_map = self.fetch_existing(client, pool_uuid, node)
            except Exception as exc:
                rows.append({"siem": node.id, "node": node.name, "result": "error", "action": "fetch", "error": str(exc)})
                any_error = True
                continue

            for desired in self.iter_desired(sheets):
                key = self.key_fn(desired)
                desired_canon = self.canon_desired(desired)
                existing_obj = existing_map.get(key)
                existing_canon = self.canon_existing(existing_obj) if existing_obj else None

                decision_cmp = decide(desired_canon, existing_canon, compare_keys=list(self.compare_keys))
                decision = Decision(
                    op=decision_cmp.op,
                    reason=decision_cmp.reason,
                    desired=desired,          # ← raw (payload shape), not canonical
                    existing=existing_canon,  # (unused by apply, keep as-is)
                )

                

                row = {
                    "siem": node.id,
                    "node": node.name,
                    "name": key,
                    "result": decision.op.lower(),
                    "action": decision.reason,
                }

                if dry_run or decision.op in ("NOOP", "SKIP"):
                    rows.append(row)
                    continue


                try:
                    res = self.apply(
                        client, pool_uuid, node, decision, existing_obj.get("id") if existing_obj else None
                    )
                    # Use the actual monitor flag from DirectorClient, do NOT recompute it
                    row.update({"status": res.get("status"), "monitor_ok": res.get("monitor_ok")})
                except Exception as exc:
                    row.update({"status": "Failed", "error": str(exc)})
                    any_error = True

                rows.append(row)

        return ImportResult(rows=rows, any_error=any_error)
