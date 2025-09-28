# lp_tenant_importer_v2/importers/routing_policies.py
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd

from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..core.logging_utils import get_logger
from ..importers.base import BaseImporter
from ..utils.diff_engine import Decision
from ..utils.validators import ValidationError, require_columns, require_sheets

log = get_logger(__name__)


class RoutingPoliciesImporter(BaseImporter):
    """
    Importer for Routing Policies (Director API 2.7).

    Excel:
      - Sheet name: "RoutingPolicy" (preferred). "RP" is also accepted for backward compatibility.
      - Expected columns (one row per rule; rows are grouped by policy):
          * cleaned_policy_name  (policy identifier; required)
          * catch_all            (boolean-like; can be repeated across rows of the same policy)
          * rule_type            (criterion type; e.g., contains/equals/...; may be empty if relying on catch_all)
          * key                  (normalized field name; may be empty if relying on catch_all)
          * value                (value/pattern; may be empty if relying on catch_all)
          * repo                 (destination repository name; required when a rule is defined)
          * drop                 ('store' or 'drop'; defaults to 'store' if empty)

    API model:
      {
        "policy_name": "<string>",
        "catch_all": <bool>,
        "routing_criteria": [
          {"type": "<str>", "key": "<str>", "value": "<str>", "repo": "<str>", "drop": "store|drop"},
          ...
        ]
      }

    Notes:
      - The canonical comparison ignores rule order and normalizes strings.
      - The payload for UPDATE is the same as for CREATE (id travels in URL).
      - We do not translate repo names to IDs here (Director accepts repo name in criteria).
    """

    # ---- wiring ----
    RESOURCE: str = "RoutingPolicies"  # configapi resource segment
    SHEET_NAMES: Tuple[str, ...] = ("RoutingPolicy", "RP")
    REQUIRED_COLUMNS: Tuple[str, ...] = (
        "cleaned_policy_name",
        "catch_all",
        "rule_type",
        "key",
        "value",
        "repo",
        "drop",
    )
    # Fields used by the diff engine to decide NOOP/UPDATE
    COMPARE_KEYS: Tuple[str, ...] = ("catch_all", "routing_criteria")

    # ------------- helpers -------------

    @staticmethod
    def _to_bool(x: Any) -> bool:
        if isinstance(x, bool):
            return x
        s = str(x).strip().lower()
        return s in {"1", "true", "yes", "y", "on"}

    @staticmethod
    def _norm(x: Any) -> str:
        return str(x or "").strip()

    @classmethod
    def _canon_rules(cls, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Canonicalize a list of rule dicts:
          - normalize strings
          - default drop -> 'store'
          - ignore entirely empty rows
          - sort by (type, key, value, repo, drop)
        """
        canon: List[Dict[str, Any]] = []
        for r in rules or []:
            t = cls._norm(r.get("type"))
            k = cls._norm(r.get("key"))
            v = cls._norm(r.get("value"))
            repo = cls._norm(r.get("repo"))
            drop = cls._norm(r.get("drop")) or "store"
            if not any([t, k, v, repo, drop]):
                continue
            canon.append({"type": t, "key": k, "value": v, "repo": repo, "drop": drop})

        def sort_key(it: Dict[str, Any]):
            return (
                it["type"].lower(),
                it["key"].lower(),
                it["value"],
                it["repo"].lower(),
                it["drop"].lower(),
            )

        return sorted(canon, key=sort_key)

    # ------------- BaseImporter overrides -------------

    def load_xlsx(self, xlsx_path: str) -> Dict[str, pd.DataFrame]:
        """Read all sheets; keep API consistent with BaseImporter contract."""
        try:
            return pd.read_excel(xlsx_path, sheet_name=None, engine="openpyxl")
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"Failed to read {xlsx_path}: {exc}") from exc

       
    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:
        """Check sheet presence and required columns (accepts RoutingPolicy or RP)."""
        # Pick the first available sheet name from the allowed list.
        sheet_name = next((s for s in self.SHEET_NAMES if s in sheets), None)
        if not sheet_name:
            found = ", ".join(sorted(sheets.keys())) or "none"
            expected = ", ".join(self.SHEET_NAMES)
            raise ValidationError(
                f"Missing sheet: expected one of [{expected}]; found: {found}"
            )
        # Keep the choice for subsequent steps (iter_desired, etc.)
        self._selected_sheet = sheet_name  # type: ignore[attr-defined]
        log.info("routing_policies: using sheet '%s'", sheet_name)
        require_columns(sheets[sheet_name], self.REQUIRED_COLUMNS)    

    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """Fetch existing policies from Director and index them by policy_name."""
        log.info("fetch_existing: start [node=%s|%s]", node.name, node.id)
        raw = client.list_resource(pool_uuid, node.id, self.RESOURCE) or {}

        # Director responses can be a list or a dict with various keys
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = (
                raw.get("routing_policies")
                or raw.get("data")
                or raw.get("RoutingPolicy")
                or raw
            )
            if isinstance(items, dict):
                items = items.get("data", [])
        else:
            items = []

        result: Dict[str, Dict[str, Any]] = {}
        for it in items or []:
            name = self._norm((it or {}).get("policy_name"))
            if name:
                result[name] = it

        log.info("fetch_existing: found %d policies [node=%s|%s]", len(result), node.name, node.id)
        return result

    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        """Yield one desired policy object per `cleaned_policy_name`."""
        # Reuse the sheet chosen during validate(); fallback just in case.
        sheet_name = getattr(self, "_selected_sheet", None) or \
                     next((s for s in self.SHEET_NAMES if s in sheets), None)
        if not sheet_name:
            expected = ", ".join(self.SHEET_NAMES)
            raise ValidationError(f"Sheet not found. Expected one of: {expected}")

        df = sheets[sheet_name].copy()
        if df.empty:
            return

        # Group all rows that belong to the same policy
        if "cleaned_policy_name" not in df.columns:
            raise ValidationError(f"Missing 'cleaned_policy_name' on sheet '{sheet_name}'")

        for policy_name, grp in df.groupby("cleaned_policy_name", dropna=False):
            name = self._norm(policy_name)
            if not name:
                # Add row number hint for the first faulty row
                first_idx = int(grp.index.min())
                raise ValidationError(
                    f"Sheet '{sheet_name}' row {first_idx + 2}: empty 'cleaned_policy_name'"
                )

            # catch_all can be repeated; normalize to any truthy value among rows
            catch_all = any(self._to_bool(x) for x in grp["catch_all"].tolist())

            rules: List[Dict[str, Any]] = []
            for idx, row in grp.iterrows():
                try:
                    rule_type = self._norm(row.get("rule_type"))
                    key = self._norm(row.get("key"))
                    value = self._norm(row.get("value"))
                    repo = self._norm(row.get("repo"))
                    drop = self._norm(row.get("drop")) or "store"

                    # Skip fully empty rule line (policy may rely only on catch_all)
                    if not any([rule_type, key, value, repo, drop]):
                        continue

                    # If a rule is provided, repo should be present
                    if not repo:
                        raise ValidationError("missing 'repo' for a rule")

                    rules.append(
                        {
                            "type": rule_type,
                            "key": key,
                            "value": value,
                            "repo": repo,
                            "drop": drop,
                        }
                    )
                except ValidationError as ve:
                    raise ValidationError(
                        f"Sheet '{sheet_name}' policy '{name}' row {idx + 2}: {ve}"
                    ) from ve
                except Exception as exc:  # pragma: no cover
                    raise ValidationError(
                        f"Sheet '{sheet_name}' policy '{name}' row {idx + 2}: {exc}"
                    ) from exc

            yield {
                "policy_name": name,
                "catch_all": bool(catch_all),
                "routing_criteria": rules,
            }

    # ---- diff / canonicalization ----

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return self._norm(desired_row.get("policy_name"))

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

    # ---- payloads & apply ----

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "policy_name": self.key_fn(desired_row),
            "catch_all": bool(desired_row.get("catch_all")),
            "routing_criteria": self._canon_rules(desired_row.get("routing_criteria") or []),
        }

    def build_payload_update(
        self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        # Same structure as POST; id is passed in URL by the client
        return self.build_payload_create(desired_row)

    def apply(  # noqa: D401 (docstring inherited from BaseImporter)
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
            log.info(
                "apply: CREATE policy=%s [node=%s|%s]", name, node.name, node.id
            )
            payload = self.build_payload_create(decision.desired)
            return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)

        if op == "UPDATE":
            if not existing_id:
                raise ValidationError(f"Cannot UPDATE policy={name}: missing existing id")
            log.info(
                "apply: UPDATE policy=%s id=%s [node=%s|%s]", name, existing_id, node.name, node.id
            )
            payload = self.build_payload_update(decision.desired, {})
            return client.update_resource(
                pool_uuid, node.id, self.RESOURCE, existing_id, payload
            )

        if op in ("NOOP", "SKIP"):
            log.debug("apply: %s policy=%s [node=%s|%s]", op, name, node.name, node.id)
            # Keep return shape compatible with BaseImporter/reporting
            return {"status": "—", "monitor_ok": None}

        raise ValidationError(f"Unsupported decision op: {op}")
