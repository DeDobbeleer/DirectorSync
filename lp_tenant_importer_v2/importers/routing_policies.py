# lp_tenant_importer_v2/importers/routing_policies.py
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple
import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import require_sheets, require_columns, ValidationError
from ..utils.diff_engine import Decision
from ..core.logging_utils import get_logger

log = get_logger(__name__)


class RoutingPoliciesImporter:
    """
    Importer for Routing Policies (API 2.7).

    Excel sheet: 'RoutingPolicy'
    Required columns:
      - cleaned_policy_name  (unique policy name)
      - catch_all            (boolean-like)
      - rule_type            (e.g. 'contains', 'equals'...) — may be blank if no rule
      - key                  (e.g. 'eventId', 'host')      — may be blank if no rule
      - value                (e.g. '1234', 'srv-*')        — may be blank if no rule
      - repo                 (destination repo name)
      - drop                 ('store' or 'drop')           — default to 'store' if empty
      - active               (ignored in payload; kept for compatibility/validation)
    """

    # ---- BaseImporter-like contract (kept for harmony) ----
    resource_name: str = "routing_policies"
    sheet_names: Tuple[str, ...] = ("RoutingPolicy",)
    required_columns: Tuple[str, ...] = (
        "cleaned_policy_name",
        "catch_all",
        "rule_type",
        "key",
        "value",
        "repo",
        "drop",
    )
    # Fields compared when deciding NOOP/UPDATE
    compare_keys: Tuple[str, ...] = ("catch_all", "routing_criteria")

    RESOURCE = "RoutingPolicy"  # configapi path (singular in Director)

    # ------------------------- helpers -------------------------

    @staticmethod
    def _as_bool(x: Any) -> bool:
        if isinstance(x, bool):
            return x
        s = str(x).strip().lower()
        return s in {"1", "true", "yes", "y", "on"}

    @staticmethod
    def _split_multi(v: Any) -> List[str]:
        """
        Split multi-values in a single cell on '|' or ','.
        Returns a *single-item* list if no separator is present.
        """
        if v is None:
            return [""]
        s = str(v).strip()
        if not s:
            return [""]
        # Prefer '|' for clarity in XLSX; accept ',' as well
        parts = [p.strip() for p in s.replace(",", "|").split("|")]
        return [p for p in parts if p != ""]

    @staticmethod
    def _canon_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Canonicalize routing rules ignoring order and normalizing strings.
        Sort key = (type, key, value, repo, drop).
        """
        def _norm(s: Any) -> str:
            return str(s or "").strip()

        key_fn = lambda r: (
            _norm(r.get("type")).lower(),
            _norm(r.get("key")).lower(),
            _norm(r.get("value")),
            _norm(r.get("repo")).lower(),
            _norm(r.get("drop")).lower(),
        )
        return sorted(
            [
                {
                    "type": _norm(r.get("type")),
                    "key": _norm(r.get("key")),
                    "value": _norm(r.get("value")),
                    "repo": _norm(r.get("repo")),
                    "drop": (_norm(r.get("drop")) or "store"),
                }
                for r in rules
                # ignore fully empty rule rows (no type/key/value and no repo)
                if any(str(r.get(k) or "").strip() for k in ("type", "key", "value", "repo", "drop"))
            ],
            key=key_fn,
        )

    # --------------------- BaseImporter hooks ---------------------

    def load_xlsx(self, xlsx_path: str) -> Dict[str, pd.DataFrame]:
        # Minimal inline loader to avoid importing BaseImporter directly here.
        try:
            xl = pd.read_excel(xlsx_path, sheet_name=None, engine="openpyxl")
        except Exception as exc:
            raise RuntimeError(f"Failed to read {xlsx_path}: {exc}") from exc
        return xl

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:
        # Accept the canonical sheet name; if you also want to accept 'RP', uncomment the alias block.
        require_sheets(sheets, self.sheet_names)
        sheet = sheets[self.sheet_names[0]]
        require_columns(sheet, self.required_columns)

        # Optional: stricter hints for common mistakes
        missing = [c for c in self.required_columns if c not in sheet.columns]
        if missing:
            raise ValidationError(f"Missing columns on sheet '{self.sheet_names[0]}': {', '.join(missing)}")

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        log.info("fetch_existing: start [node=%s|%s]", node.name, node.id)
        data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or {}
        # Normalise server responses: support either {"routing_policies":[...]} or {"data":[...]} or a raw list
        if isinstance(data, dict):
            items = data.get("routing_policies") or data.get("data") or data.get("RoutingPolicy") or []
            if isinstance(items, dict):
                # some versions returned {"routing_policies": {"data":[...]}}
                items = items.get("data", [])
        elif isinstance(data, list):
            items = data
        else:
            items = []

        result: Dict[str, Dict[str, Any]] = {}
        for it in items or []:
            name = str((it or {}).get("policy_name") or "").strip()
            if name:
                result[name] = it
        log.info("fetch_existing: found %d policies [node=%s|%s]", len(result), node.name, node.id)
        return result

    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        sheet_name = self.sheet_names[0]
        if sheet_name not in sheets:
            # Give a very explicit message (évite le "Validation error:" vide)
            raise ValidationError(f"Sheet '{sheet_name}' not found in workbook")

        df = sheets[sheet_name].copy()

        # Row-level validation + shaping
        for idx, row in df.iterrows():
            try:
                policy_name = str(row.get("cleaned_policy_name") or "").strip()
                if not policy_name:
                    raise ValidationError(f"Row {idx+2}: empty 'cleaned_policy_name'")

                catch_all = self._as_bool(row.get("catch_all"))

                # Multi-valued cells supported (split by '|' or ',')
                types = self._split_multi(row.get("rule_type"))
                keys = self._split_multi(row.get("key"))
                vals = self._split_multi(row.get("value"))
                repos = self._split_multi(row.get("repo"))
                drops = self._split_multi(row.get("drop"))

                max_len = max(len(types), len(keys), len(vals), len(repos), len(drops))
                # Pad all lists to the same length
                def pad(ls: List[str]) -> List[str]:
                    return ls + [""] * (max_len - len(ls))

                types, keys, vals, repos, drops = map(pad, (types, keys, vals, repos, drops))

                rules: List[Dict[str, Any]] = []
                for i in range(max_len):
                    rule = {
                        "type": types[i],
                        "key": keys[i],
                        "value": vals[i],
                        "repo": repos[i],
                        "drop": drops[i] or "store",
                    }
                    # Skip fully empty rule lines (policy can rely on catch_all)
                    if any(str(rule.get(k) or "").strip() for k in ("type", "key", "value", "repo", "drop")):
                        rules.append(rule)

                desired = {
                    "policy_name": policy_name,
                    "catch_all": catch_all,
                    "routing_criteria": rules,
                }
                # yield canonical shape ready for diff/payload
                yield desired

            except ValidationError:
                # re-raise with context kept
                raise
            except Exception as exc:
                # Contextful error (sheet + row number)
                raise ValidationError(f"Sheet '{sheet_name}' row {idx+2}: {exc}") from exc

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return str(desired_row.get("policy_name") or "").strip()

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "catch_all": bool(desired_row.get("catch_all")),
            "routing_criteria": self._canon_rules(desired_row.get("routing_criteria") or []),
        }

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        if not existing_obj:
            return {}
        return {
            "catch_all": bool(existing_obj.get("catch_all")),
            "routing_criteria": self._canon_rules(existing_obj.get("routing_criteria") or []),
        }

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "policy_name": self.key_fn(desired_row),
            "catch_all": bool(desired_row.get("catch_all")),
            "routing_criteria": self._canon_rules(desired_row.get("routing_criteria") or []),
        }

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        # For PUT, Director expects the same structure as POST (id is in URL)
        return self.build_payload_create(desired_row)

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision: Decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        op = decision.op
        name = self.key_fn(decision.desired)
        if op == "CREATE":
            log.info("apply: CREATE policy=%s [node=%s|%s]", name, node.name, node.id)
            payload = self.build_payload_create(decision.desired)
            return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
        if op == "UPDATE":
            log.info("apply: UPDATE policy=%s id=%s [node=%s|%s]", name, existing_id, node.name, node.id)
            payload = self.build_payload_update(decision.desired, {})
            if not existing_id:
                raise ValidationError(f"Cannot UPDATE policy={name}: missing existing id")
            return client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)
        if op in ("NOOP", "SKIP"):
            log.debug("apply: %s policy=%s [node=%s|%s]", op, name, node.name, node.id)
            return {"status": "—", "monitor_ok": None}
        raise ValidationError(f"Unsupported decision op: {op}")
