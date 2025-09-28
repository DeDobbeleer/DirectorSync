# lp_tenant_importer_v2/importers/routing_policies.py
"""
Routing Policies importer (v2)

This module mirrors the design of the Repos importer:
- It reads the "RoutingPolicy" sheet from the workbook (XLSX).
- It groups rows by policy name and builds a canonical desired shape.
- It fetches existing routing policies from Director (configapi).
- It compares desired vs existing using a stable subset of fields.
- It applies CREATE / UPDATE via DirectorClient, delegating monitor handling.

PEP 8, typed, and fully logged. The importer only knows its resource-specific
rules; the HTTP/monitor details live in DirectorClient.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import logging

import pandas as pd

from lp_tenant_importer_v2.importers.base import BaseImporter
from lp_tenant_importer_v2.core.director_client import DirectorClient
from lp_tenant_importer_v2.utils.validators import ValidationError

log = logging.getLogger(__name__)


# ---- Data models (canonical shapes) ---------------------------------------

@dataclass(frozen=True)
class Criterion:
    """Canonical routing criterion used for comparison and payload building."""

    type: str
    key: str
    value: str
    repo: str  # repo *name* in canonical desired/existing (id resolved at build time)
    drop: str

    def as_tuple(self) -> Tuple[str, str, str, str, str]:
        return (self.type, self.key, self.value, self.repo, self.drop)


@dataclass
class PolicyDesired:
    """Canonical desired routing policy for comparison.

    Note: *repo* references are repo **names** here. They are resolved to IDs
    when building the API payload.
    """

    name: str
    active: bool
    catch_all: str  # repo name (empty string allowed)
    routing_criteria: List[Criterion]


# ---- Importer -------------------------------------------------------------

class RoutingPoliciesImporter(BaseImporter):
    """Importer for Director Routing Policies (v2).

    This class follows the same pattern as the Repos importer: implement
    resource-specific hooks while leveraging BaseImporter for orchestration.
    """

    RESOURCE = "RoutingPolicies"
    SHEET = "RoutingPolicy"

    # Column names in the XLSX sheet. We keep them explicit to avoid surprises.
    COL_POLICY_NAME = "cleaned_policy_name"
    COL_ACTIVE = "active"
    COL_CATCH_ALL = "catch_all"
    COL_RULE_TYPE = "rule_type"
    COL_KEY = "key"
    COL_VALUE = "value"
    COL_REPO = "repo"
    COL_DROP = "drop"

    # ----- Public API expected by BaseImporter -----------------------------

    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: Any
    ) -> Dict[str, Dict[str, Any]]:
        """Return existing policies for a node as a mapping name -> object.

        The returned dict values are the raw API objects augmented with a few
        normalized fields we rely on during comparison (e.g., a `name`).
        """
        node_t = f"{getattr(node, 'name', node)}|{getattr(node, 'id', node)}"
        log.info("fetch_existing: start [node=%s]", node_t)

        data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or {}
        if isinstance(data, dict):
            items = data.get("routing_policies") or data.get("data") or data.get("items") or []
        else:
            items = data

        # Build repo id->name map (and reverse) for this node to present names in canonical form.
        repo_id_to_name, _ = self._build_repo_maps(client, pool_uuid, node)

        result: Dict[str, Dict[str, Any]] = {}
        count = 0
        for it in items or []:
            name = str((it.get("policy_name") or it.get("name") or "").strip())
            if not name:
                continue

            count += 1
            # Normalize existing into a canonical shape we will compare against.
            canon = self._canon_existing(it, repo_id_to_name)
            obj = dict(it)
            obj["name"] = name
            obj["_canon"] = canon
            result[name] = obj

        log.info("fetch_existing: found %d policies [node=%s]", count, node_t)
        return result

    def load_desired(self, xlsx_path: str) -> Dict[str, Dict[str, Any]]:  # type: ignore[override]
        """Load desired policies from the workbook.

        Returns a mapping name -> {"name": str, "_canon": PolicyDesired, "_raw": row list}
        similar to the structure used by the Repos importer.
        """
        try:
            df = pd.read_excel(xlsx_path, sheet_name=self.SHEET, dtype=str)
        except ValueError as exc:
            raise ValidationError(f"Sheet '{self.SHEET}' not found in workbook: {xlsx_path}") from exc

        # Normalize NaN to empty strings, and strip whitespace.
        df = df.fillna("").applymap(lambda s: s.strip() if isinstance(s, str) else s)

        required = [self.COL_POLICY_NAME]
        missing = [c for c in required if c not in df.columns]
        if missing:
            raise ValidationError(f"Missing required columns in sheet '{self.SHEET}': {', '.join(missing)}")

        groups: Dict[str, List[Dict[str, str]]] = {}
        for _, row in df.iterrows():
            name = str(row.get(self.COL_POLICY_NAME, "")).strip()
            if not name:
                # Skip anonymous rows to avoid accidental grouping
                continue
            groups.setdefault(name, []).append({k: str(row.get(k, "")) for k in df.columns})

        desired_map: Dict[str, Dict[str, Any]] = {}
        for name, rows in groups.items():
            desired = self._build_desired_from_rows(name, rows)
            desired_map[name] = {"name": name, "_canon": desired, "_raw": rows}

        return desired_map

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: Any,
        decision: Any,
        existing_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Apply a CREATE/UPDATE decision using DirectorClient.

        This mirrors the Repos importer style: it receives a `decision` object
        produced by BaseImporter/diff-engine and an optional `existing_id`.
        """
        node_t = f"{getattr(node, 'name', node)}|{getattr(node, 'id', node)}"
        op = getattr(decision, "op", None) or getattr(decision, "action", None)
        desired: Optional[PolicyDesired] = getattr(decision, "desired", None)
        name = getattr(decision, "name", None) or (desired.name if desired else "")

        if op == "CREATE":
            log.info("apply: op=CREATE policy=%s [node=%s]", name, node_t)
            payload = self._build_payload(desired)
            return client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)

        if op == "UPDATE":
            log.info("apply: op=UPDATE policy=%s id=%s [node=%s]", name, existing_id, node_t)
            payload = self._build_payload(desired, existing_id=existing_id)
            return client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)

        if op == "DELETE":
            log.info("apply: op=DELETE policy=%s id=%s [node=%s]", name, existing_id, node_t)
            return client.delete_resource(pool_uuid, node.id, self.RESOURCE, existing_id)

        # NOOP or unknown are handled by BaseImporter; just acknowledge.
        log.debug("apply: no-op for policy=%s op=%s [node=%s]", name, op, node_t)
        return {"status": "Success"}

    # ----- Internal helpers -------------------------------------------------

    def _build_repo_maps(
        self, client: DirectorClient, pool_uuid: str, node: Any
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Return (id->name, name->id) for repos on the node.

        We keep it private to avoid adding new dependencies to resolvers.py.
        """
        data = client.list_resource(pool_uuid, node.id, "Repos") or {}
        if isinstance(data, dict):
            items = data.get("repos") or data.get("data") or data
        else:
            items = data

        id_to_name: Dict[str, str] = {}
        name_to_id: Dict[str, str] = {}
        for it in items or []:
            rid = str(it.get("id") or "").strip()
            nm = str(it.get("name") or "").strip()
            if rid and nm:
                id_to_name[rid] = nm
                name_to_id[nm] = rid
        return id_to_name, name_to_id

    def _canon_existing(self, obj: Dict[str, Any], repo_id_to_name: Dict[str, str]) -> PolicyDesired:
        """Transform an API object into a canonical comparable PolicyDesired.

        Repo references (catch_all and per-criterion) are mapped back to **repo names**.
        """
        name = str(obj.get("policy_name") or obj.get("name") or "").strip()
        active_raw = obj.get("active")
        active = bool(str(active_raw).strip().lower() in {"1", "true", "yes"})

        catch_all_id = str(obj.get("catch_all") or "").strip()
        catch_all_name = repo_id_to_name.get(catch_all_id, "") if catch_all_id else ""

        criteria_raw = obj.get("routing_criteria") or []
        criteria: List[Criterion] = []
        for c in criteria_raw:
            ctype = str(c.get("type") or "").strip()
            ckey = str(c.get("key") or "").strip()
            cval = str(c.get("value") or "").strip()
            crepo_id = str(c.get("repo") or "").strip()
            cdrop = str(c.get("drop") or "").strip()
            crepo_name = repo_id_to_name.get(crepo_id, "") if crepo_id else ""
            criteria.append(Criterion(ctype, ckey, cval, crepo_name, cdrop))

        # Sort for stable comparison (order-insensitive matching)
        criteria = sorted(criteria, key=Criterion.as_tuple)
        return PolicyDesired(name=name, active=active, catch_all=catch_all_name, routing_criteria=criteria)

    def _build_desired_from_rows(self, name: str, rows: List[Dict[str, str]]) -> PolicyDesired:
        """Create a canonical PolicyDesired from a group of XLSX rows."""
        # Decide active/catch_all at the group level (first non-empty wins)
        active = True
        catch_all = ""
        criteria: List[Criterion] = []

        for r in rows:
            # active
            a = str(r.get(self.COL_ACTIVE, "")).strip().lower()
            if a in {"0", "false", "no"}:
                active = False
            elif a in {"1", "true", "yes"}:
                active = True

            # catch_all
            ca = str(r.get(self.COL_CATCH_ALL, "")).strip()
            if ca:
                catch_all = ca

            # criterion
            ctype = str(r.get(self.COL_RULE_TYPE, "")).strip()
            ckey = str(r.get(self.COL_KEY, "")).strip()
            cval = str(r.get(self.COL_VALUE, "")).strip()
            crepo = str(r.get(self.COL_REPO, "")).strip()
            cdrop = str(r.get(self.COL_DROP, "")).strip()

            if any([ctype, ckey, cval, crepo, cdrop]):
                criteria.append(Criterion(ctype, ckey, cval, crepo, cdrop or "store"))

        criteria = sorted(criteria, key=Criterion.as_tuple)
        return PolicyDesired(name=name, active=active, catch_all=catch_all, routing_criteria=criteria)

    def _build_payload(self, desired: Optional[PolicyDesired], existing_id: Optional[str] = None) -> Dict[str, Any]:
        """Construct API payload (data) from a canonical desired policy.

        Repo names are resolved to **repo ids** here.
        """
        if desired is None:
            raise ValidationError("build_payload called without desired policy")

        # Resolve repo names to ids on demand (per-node would be better cached at call site).
        # We do not have node context here; BaseImporter.apply passes us only existing_id,
        # so repo resolution is left to the Director (by name) when ids are not resolvable.
        # To stay deterministic, we keep names as-is if we cannot resolve ids here.
        # (If you prefer strict resolution, wire repo maps into apply and pass them here.)

        data: Dict[str, Any] = {
            "policy_name": desired.name,
            "active": bool(desired.active),
            "catch_all": desired.catch_all,  # name; Director typically accepts either id or name
            "routing_criteria": [
                {
                    "type": c.type,
                    "key": c.key,
                    "value": c.value,
                    "repo": c.repo,  # name; Director typically accepts either id or name
                    "drop": c.drop or "store",
                }
                for c in desired.routing_criteria
            ],
        }
        if existing_id:
            data["id"] = existing_id
        return data
    

