# lp_tenant_importer_v2/importers/alert_rules_report.py
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple
import pandas as pd

from .base import BaseImporter
from ..core.config import NodeRef
from ..core.logging_utils import get_logger

log = get_logger(__name__)


class AlertRulesXlsxLister(BaseImporter):
    """
    Report-only importer that reads the 'AlertRules' sheet in the XLSX and
    emits rows showing Name / Owner / Assign_to / Visible_to_Users.
    No API calls are made; this class simply formats a report.
    """

    # Nom logique de la ressource (juste pour les logs)
    resource_name: str = "alert_rules_report"

    # On lit la feuille des alertes (comme les autres importers d'alert rules)
    sheet_names: Tuple[str, ...] = ("AlertRules",)

    # On ne force pas de colonnes obligatoires ici: c'est un rapport tolérant
    required_columns: Tuple[str, ...] = tuple()

    def run_for_nodes(
        self,
        client: Any,
        pool_uuid: str,
        nodes: Iterable[NodeRef],
        xlsx_path,
        dry_run: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Contrairement aux importers « CRUD », on ne contacte pas le Director.
        On lit l'XLSX et on génère des lignes prêtes pour utils.reporting.print_rows.
        """
        # Charge toutes les feuilles via le helper de BaseImporter
        sheets = self.load_xlsx(xlsx_path)
        sheet_name = self.sheet_names[0]
        if sheet_name not in sheets:
            raise ValueError(f"Sheet '{sheet_name}' not found in {xlsx_path}")

        df = sheets[sheet_name].copy()
        df.columns = [str(c).strip() for c in df.columns]

        # Alias tolérants aux variations de casse / espaces / underscores
        aliases = {
            "name": ["Name", "Alert Name", "Rule", "Rule Name"],
            "owner": ["Owner"],
            "assign_to": ["Assign_to", "Assigned_to", "Assign To"],
            "visible_to_users": ["Visible_to_users", "Visible_to_Users", "Visible To Users", "Visible_for", "visible_for"],
        }

        def pick_col(logical: str) -> str | None:
            want = [s.lower().replace(" ", "_") for s in aliases.get(logical, [])]
            for real in df.columns:
                norm = real.lower().replace(" ", "_")
                if norm in want:
                    return real
            return None

        c_name = pick_col("name")
        c_owner = pick_col("owner")
        c_assign = pick_col("assign_to")
        c_vis = pick_col("visible_to_users")

        rows: List[Dict[str, Any]] = []
        nodes_list = list(nodes)
        for node in nodes_list:
            node_tag = f"{node.name}|{node.id}"
            for _, r in df.iterrows():
                name = str(r.get(c_name, "")).strip() if c_name else ""
                if not name:
                    continue  # skip lignes vides

                owner = (str(r.get(c_owner, "")).strip() if c_owner else "")
                assign_to = (str(r.get(c_assign, "")).strip() if c_assign else "")

                raw_vis = r.get(c_vis, "")
                if isinstance(raw_vis, float) and pd.isna(raw_vis):
                    visible = ""
                elif isinstance(raw_vis, list):
                    visible = ";".join(map(str, raw_vis))
                else:
                    visible = str(raw_vis).strip()

                rows.append(
                    {
                        "siem": node.id,
                        "node": node_tag,
                        "name": name,
                        "owner": owner or "—",
                        "assign_to": assign_to or "—",
                        "visible_to_users": visible or "—",
                        # Champs classiques de la table (pas de pipeline API ici)
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
            "alert_rules_report: produced %d rows for %d node(s)",
            len(rows),
            len(nodes_list),
        )
        return rows
