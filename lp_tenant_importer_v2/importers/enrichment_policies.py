from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd

from lp_tenant_importer_v2.importers.base import BaseImporter
from lp_tenant_importer_v2.core.config import NodeRef
from lp_tenant_importer_v2.core.director_client import DirectorClient
from lp_tenant_importer_v2.utils.validators import ValidationError


log = logging.getLogger(__name__)

# Whitelisted keys we keep from the XLSX for API payloads
_ALLOWED_RULE_KEYS = ("category", "operation", "prefix", "event_key", "source_key", "type")
_ALLOWED_CRITERIA_KEYS = ("type", "key", "value")


@dataclass(frozen=True)
class _Key:
    policy: str
    index: int


class EnrichmentPoliciesImporter(BaseImporter):
    """Importer for Enrichment Policies (Director API 2.7.0).

    Rules enforced:
      - Each *specification* MUST contain `source` and at least one `criteria` object.
      - `rules` are optional.
      - Diff is performed on a canonical subset (order-insensitive for rules/criteria).

    XLSX sheets required: EnrichmentPolicy, EnrichmentRules, EnrichmentCriteria.
    We aggregate rows by policy_name and keep all spec_index blocks in `specifications`.
    """

    resource_name: str = "enrichment_policies"
    sheet_names: Tuple[str, ...] = ("EnrichmentPolicy", "EnrichmentRules", "EnrichmentCriteria")
    required_columns: Tuple[str, ...] = ("policy_name", "spec_index")  # validated per sheet by BaseImporter
    compare_keys: Tuple[str, ...] = ("specifications",)  # add "description" if you want description changes to trigger UPDATE

    # ---------------------------------------------------------------------
    # Existing state
    # ---------------------------------------------------------------------
    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        """Return name -> object for EnrichmentPolicy from the node."""
        path = client.configapi(pool_uuid, node.id, "EnrichmentPolicy")
        data = client.get_json(path) or []
        if isinstance(data, dict) and "data" in data:
            data = data.get("data") or []
        out: Dict[str, Dict[str, Any]] = {}
        if not isinstance(data, list):
            log.warning("fetch_existing: unexpected list payload type from %s: %s", path, type(data))
            return out
        for item in data:
            try:
                name = str(item.get("name") or "").strip()
                if name:
                    out[name] = item
            except Exception as exc:
                log.debug("fetch_existing: skipping malformed item: %s (err=%s)", item, exc)
        return out

    # ---------------------------------------------------------------------
    # Desired state from XLSX
    # ---------------------------------------------------------------------
    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        ep = sheets["EnrichmentPolicy"].copy()
        rules = sheets["EnrichmentRules"].copy()
        crit = sheets["EnrichmentCriteria"].copy()

        # Normalize headers
        for df in (ep, rules, crit):
            df.columns = [str(c).strip() for c in df.columns]

        # Column presence checks
        for req in ("policy_name", "spec_index", "source"):
            if req not in ep.columns:
                raise ValidationError(f"EnrichmentPolicy: missing required column '{req}'")
        for req in ("policy_name", "spec_index"):
            if req not in rules.columns:
                raise ValidationError(f"EnrichmentRules: missing required column '{req}'")
            if req not in crit.columns:
                raise ValidationError(f"EnrichmentCriteria: missing required column '{req}'")

        # Types for grouping
        ep["spec_index"] = ep["spec_index"].astype(int)
        rules["spec_index"] = rules["spec_index"].astype(int)
        crit["spec_index"] = crit["spec_index"].astype(int)

        def _key(sr: pd.Series) -> _Key:
            return _Key(policy=str(sr["policy_name"]).strip(), index=int(sr["spec_index"]))

        # Index rules/criteria by (policy_name, spec_index)
        rules_by_key: Dict[_Key, List[Dict[str, Any]]] = {}
        for _, r in rules.iterrows():
            k = _key(r)
            rr = {kf: r.get(kf) for kf in _ALLOWED_RULE_KEYS if kf in r and pd.notna(r.get(kf))}
            if "prefix" in rr:
                rr["prefix"] = bool(rr["prefix"])  # ensure real bool
            if rr.get("operation") is None:
                rr["operation"] = "Equals"
            rules_by_key.setdefault(k, []).append(rr)

        crit_by_key: Dict[_Key, List[Dict[str, Any]]] = {}
        for _, c in crit.iterrows():
            k = _key(c)
            cc = {kf: c.get(kf) for kf in _ALLOWED_CRITERIA_KEYS if kf in c}
            # Enforce presence of the `value` key (empty string allowed by contract)
            if "value" not in cc or pd.isna(cc.get("value")):
                cc["value"] = ""
            if not str(cc.get("type") or "").strip() or not str(cc.get("key") or "").strip():
                raise ValidationError(
                    f"EnrichmentCriteria: missing type/key for policy='{k.policy}' spec_index={k.index}"
                )
            crit_by_key.setdefault(k, []).append(cc)

        # Aggregate by policy_name → one desired row per policy
        desired_by_policy: Dict[str, Dict[str, Any]] = {}
        for policy_name, grp in ep.groupby(ep["policy_name"].map(lambda v: str(v).strip())):
            specs: List[Dict[str, Any]] = []
            description = ""
            for _, row in grp.sort_values("spec_index").iterrows():
                k = _key(row)
                source = str(row["source"]).strip()
                if not source:
                    raise ValidationError(
                        f"EnrichmentPolicy: missing 'source' for policy='{k.policy}' spec_index={k.index}"
                    )
                if not description:
                    description = str(row.get("description") or "").strip()

                # Attach rules (optional) and validate according to category
                spec_rules = rules_by_key.get(k, [])
                for rr in spec_rules:
                    cat = str(rr.get("category") or "").strip()
                    if cat not in {"simple", "type_based"}:
                        raise ValidationError(
                            f"EnrichmentRules: invalid category '{cat}' policy='{k.policy}' spec_index={k.index}"
                        )
                    if cat == "simple" and not str(rr.get("event_key") or "").strip():
                        raise ValidationError(
                            f"EnrichmentRules: missing event_key for simple rule policy='{k.policy}' spec_index={k.index}"
                        )
                    if cat == "type_based" and not str(rr.get("type") or "").strip():
                        raise ValidationError(
                            f"EnrichmentRules: missing type for type_based rule policy='{k.policy}' spec_index={k.index}"
                        )
                    rr["operation"] = "Equals"  # enforce

                # Attach criteria (required ≥1)
                spec_criteria = crit_by_key.get(k, [])
                if not spec_criteria:
                    raise ValidationError(
                        f"EnrichmentPolicy: criteria required but not found for policy='{k.policy}' spec_index={k.index}"
                    )

                specs.append({"source": source, "rules": spec_rules, "criteria": spec_criteria})

            desired = {"name": policy_name, "specifications": specs}
            if description:
                desired["description"] = description
            desired_by_policy[policy_name] = desired

        for row in desired_by_policy.values():
            yield row

    # ---------------------------------------------------------------------
    # Canonicalization for diff (order-insensitive)
    # ---------------------------------------------------------------------
    @staticmethod
    def _canon_rule(rr: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: rr.get(k) for k in _ALLOWED_RULE_KEYS if k in rr}
        if "prefix" in out:
            out["prefix"] = bool(out["prefix"])  # ensure bool
        if out.get("operation") is None:
            out["operation"] = "Equals"
        return out

    @staticmethod
    def _canon_criteria(cc: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: cc.get(k, "") for k in _ALLOWED_CRITERIA_KEYS}
        if out.get("value") is None:
            out["value"] = ""
        return out

    @classmethod
    def _canon_spec(cls, spec: Dict[str, Any]) -> Dict[str, Any]:
        src = str(spec.get("source") or "").strip()
        crules = [cls._canon_rule(r) for r in (spec.get("rules") or [])]
        ccrit = [cls._canon_criteria(c) for c in (spec.get("criteria") or [])]
        crules_sorted = sorted(crules, key=lambda d: json.dumps(d, sort_keys=True))
        ccrit_sorted = sorted(ccrit, key=lambda d: json.dumps(d, sort_keys=True))
        return {"source": src, "rules": crules_sorted, "criteria": ccrit_sorted}

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return str(desired_row.get("name") or "").strip()

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        specs = desired_row.get("specifications") or []
        cspecs = [self._canon_spec(s) for s in specs]
        cspecs_sorted = sorted(cspecs, key=lambda s: (s.get("source"), json.dumps(s, sort_keys=True)))
        out = {"specifications": cspecs_sorted}
        # If you also want description to matter, uncomment:
        # if desired_row.get("description"):
        #     out["description"] = desired_row["description"]
        return out

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any] | None:
        if not existing_obj:
            return None
        specs = existing_obj.get("specifications") or []
        cspecs = [self._canon_spec(s) for s in specs]
        cspecs_sorted = sorted(cspecs, key=lambda s: (s.get("source"), json.dumps(s, sort_keys=True)))
        out = {"specifications": cspecs_sorted}
        # Same optional description handling as above
        # if existing_obj.get("description"):
        #     out["description"] = existing_obj["description"]
        return out

    # ---------------------------------------------------------------------
    # Payload builders
    # ---------------------------------------------------------------------
    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "name": desired_row["name"],
            "specifications": desired_row["specifications"],
        }
        if desired_row.get("description"):
            payload["description"] = desired_row["description"]
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        # PUT accepts the same body shape as POST
        return self.build_payload_create(desired_row)

    # ---------------------------------------------------------------------
    # EnrichmentSource checks — ONLY the List endpoint; match on `source_name`
    # ---------------------------------------------------------------------
    @staticmethod
    def _list_enrichment_sources(client: DirectorClient, pool_uuid: str, node: NodeRef) -> List[str]:
        """Collect available enrichment sources on the node.

        Endpoint used: /configapi/{pool}/{node}/EnrichmentSource (GET)
        We extract *only* the `source_name` field (exact match, case-sensitive).
        """
        path = client.configapi(pool_uuid, node.id, "EnrichmentSource")
        data = client.get_json(path) or []
        if isinstance(data, dict) and "data" in data:
            data = data.get("data") or []
        names: List[str] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    n = item.get("source_name")
                    if isinstance(n, str) and n:
                        names.append(n)
        unique = sorted(set(names))
        log.debug("EnrichmentSource list on %s: %s", node.name, unique)
        return unique

    def _ensure_sources(self, client: DirectorClient, pool_uuid: str, node: NodeRef, desired_row: Dict[str, Any]) -> Tuple[bool, List[str]]:
        want = {str(spec.get("source") or "").strip() for spec in desired_row.get("specifications", [])}
        want = {w for w in want if w}
        have = set(self._list_enrichment_sources(client, pool_uuid, node))
        missing = sorted(want - have)
        return (len(missing) == 0), missing

    # ---------------------------------------------------------------------
    # Apply
    # ---------------------------------------------------------------------
    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        desired = decision.desired or {}

        # Pre-flight source validation (strict)
        ok, missing = self._ensure_sources(client, pool_uuid, node, desired)
        if not ok:
            msg = f"Missing enrichment sources: {', '.join(missing)}"
            log.error("%s — pool=%s node=%s policy=%s", msg, pool_uuid, node.name, desired.get("name"))
            return {"status": "Skipped", "error": msg}

        resource = "EnrichmentPolicy"
        if decision.op == "CREATE":
            payload = self.build_payload_create(desired)
            path = client.configapi(pool_uuid, node.id, resource)
            resp = client.post_json(path, {"data": payload}) 
        elif decision.op == "UPDATE":
            payload = self.build_payload_update(desired, decision.existing or {})
            if not existing_id:
                # Try to recover the id (race/first-run) — else fallback to create
                listing = client.get_json(client.configapi(pool_uuid, node.id, resource)) or []
                if isinstance(listing, dict) and "data" in listing:
                    listing = listing.get("data") or []
                if isinstance(listing, list):
                    for it in listing:
                        if str(it.get("name") or "").strip() == desired.get("name"):
                            existing_id = it.get("id")
                            break
            if not existing_id:
                path = client.configapi(pool_uuid, node.id, resource)
                resp = client.post_json(path, payload)
            else:
                path = client.configapi(pool_uuid, node.id, f"{resource}/{existing_id}")
                resp = client.put_json(path, {"data": payload})
        else:
            # NOOP/SKIP should not call apply
            return {"status": "Success", "monitor_ok": True}

        # Monitoring: prefer job id, then monitor URL, else infer success from status
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        monitor_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
        mon_ok = True
        last: Dict[str, Any] = {}
        branch = "none"
        if job_id and getattr(client.options, "monitor_enabled", True):
            branch = "job"
            mon_ok, last = client.monitor_job(pool_uuid, node.id, job_id)
        elif monitor_path and getattr(client.options, "monitor_enabled", True):
            branch = "url"
            mon_ok, last = client.monitor_job_url(monitor_path)
        else:
            status = str((resp or {}).get("status") or "").lower()
            mon_ok = status in {"ok", "success", "completed", ""}

        result: Dict[str, Any] = {"status": "Success" if mon_ok else "Failed", "monitor_ok": mon_ok, "monitor_branch": branch}
        if not mon_ok:
            result["error"] = last.get("message") or last.get("status") or "monitor failed"
        return result
