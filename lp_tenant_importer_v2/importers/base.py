"""
BaseImporter — orchestrates load → validate → fetch → diff → plan → apply → report
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
    rows: List[Dict[str, Any]]
    any_error: bool


class BaseImporter:
    # to be set by concrete importers
    resource_name: str = "resource"
    sheet_names: Tuple[str, ...] = ()
    required_columns: Tuple[str, ...] = ()
    compare_keys: Tuple[str, ...] = ()

    def load_xlsx(self, xlsx_path: str) -> Dict[str, pd.DataFrame]:
        try:
            xl = pd.read_excel(xlsx_path, sheet_name=None, engine="openpyxl")
        except Exception as exc:
            raise RuntimeError(f"Failed to read {xlsx_path}: {exc}") from exc
        return xl

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:
        require_sheets(sheets, self.sheet_names)
        for sheet in self.sheet_names:
            require_columns(sheets[sheet], self.required_columns)

    # ----- hooks to implement -----
    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        raise NotImplementedError

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        raise NotImplementedError

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        raise NotImplementedError

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def apply(self, client: DirectorClient, pool_uuid: str, node: NodeRef, decision: Decision, existing_id: str | None) -> Dict[str, Any]:
        raise NotImplementedError

    # ----- pipeline -----
    def run_for_nodes(self, client: DirectorClient, pool_uuid: str, nodes: List[NodeRef], xlsx_path: str, dry_run: bool) -> ImportResult:
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

                decision = decide(desired_canon, existing_canon, compare_keys=list(self.compare_keys))

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
                    res = self.apply(client, pool_uuid, node, decision, existing_obj.get("id") if existing_obj else None)
                    row.update({"status": res.get("status"), "monitor_ok": res.get("status") == "Success"})
                except Exception as exc:
                    row.update({"status": "Failed", "error": str(exc)})
                    any_error = True

                rows.append(row)

        return ImportResult(rows=rows, any_error=any_error)
