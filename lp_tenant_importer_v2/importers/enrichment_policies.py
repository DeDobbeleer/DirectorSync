from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

import json
import logging

import pandas as pd

from .base import BaseImporter
from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError


log = logging.getLogger(__name__)


_ALLOWED_RULE_KEYS = ("category", "operation", "prefix", "event_key", "source_key", "type")
_ALLOWED_CRITERIA_KEYS = ("type", "key", "value")


@dataclass(frozen=True)
class _SpecKey:
    policy: str
    index: int


class EnrichmentPoliciesImporter(BaseImporter):
    """Importer for Enrichment Policies (EP).

    Contract enforced (Director API 2.7.0):
    - Each *specification* **must** include `source` and **≥1** `criteria` object.
    - `rules` may be omitted or be an empty list.

    Comparison is performed on the canonical subset of fields under `specifications`.
    """

    resource_name: str = "enrichment_policies"
    sheet_names: Tuple[str, ...] = ("EnrichmentPolicy", "EnrichmentRules", "EnrichmentCriteria")
    # Only the columns common to *all* three sheets should be listed here, because
    # BaseImporter.validate() applies the same set to every sheet.
    required_columns: Tuple[str, ...] = ("policy_name", "spec_index")
    compare_keys: Tuple[str, ...] = ("specifications",)  # description comparison is optional

    # ---------------------- Fetch existing ---------------------------------
    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: NodeRef) -> Dict[str, Dict[str, Any]]:
        """Return a mapping `name -> existing_obj` for this node.
        We rely on the Director *configapi* list endpoint for `EnrichmentPolicy`.
        """
        path = client.configapi(pool_uuid, node.id, "EnrichmentPolicy")
        data = client.get_json(path) or []
        out: Dict[str, Dict[str, Any]] = {}
        if isinstance(data, dict) and "data" in data:
            data = data.get("data") or []
        if not isinstance(data, list):
            log.warning("fetch_existing: unexpected payload type for %s: %s", path, type(data))
            return out
        for item in data:
            try:
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                out[name] = item
            except Exception as exc:
                log.debug("fetch_existing: skipping malformed item: %s (err=%s)", item, exc)
        return out

    # ---------------------- Desired state from XLSX ------------------------
    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        ep = sheets["EnrichmentPolicy"].copy()
        rules = sheets["EnrichmentRules"].copy()
        crit = sheets["EnrichmentCriteria"].copy()

        # Normalize column names (strip spaces)
        for df in (ep, rules, crit):
            df.columns = [str(c).strip() for c in df.columns]

        # Required columns per sheet
        for req_col in ("policy_name", "spec_index", "source"):
            if req_col not in ep.columns:
                raise ValidationError(f"EnrichmentPolicy: missing required column '{req_col}'")
        for req_col in ("policy_name", "spec_index"):
            if req_col not in rules.columns:
                raise ValidationError(f"EnrichmentRules: missing required column '{req_col}'")
            if req_col not in crit.columns:
                raise ValidationError(f"EnrichmentCriteria: missing required column '{req_col}'")

        # Cast for stable grouping
        ep["spec_index"] = ep["spec_index"].astype(int)
        rules["spec_index"] = rules["spec_index"].astype(int)
        crit["spec_index"] = crit["spec_index"].astype(int)

        # Index helpers
        def _key(df_row: pd.Series) -> Tuple[str, int]:
            return (str(df_row["policy_name"]).strip(), int(df_row["spec_index"]))

        rules_by_key: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        for _, r in rules.iterrows():
            k = _key(r)
            rr = {kf: r.get(kf) for kf in _ALLOWED_RULE_KEYS if kf in r and pd.notna(r.get(kf))}
            if "prefix" in rr:
                rr["prefix"] = bool(rr["prefix"])  # normalize to real boolean
            if rr.get("operation") is None:
                rr["operation"] = "Equals"
            rules_by_key.setdefault(k, []).append(rr)

        crit_by_key: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        for _, c in crit.iterrows():
            k = _key(c)
            cc = {kf: c.get(kf) for kf in _ALLOWED_CRITERIA_KEYS if kf in c}
            if "value" not in cc or pd.isna(cc.get("value")):
                cc["value"] = ""
            if not str(cc.get("type") or "").strip() or not str(cc.get("key") or "").strip():
                raise ValidationError(
                    f"EnrichmentCriteria: invalid row (missing type/key) for policy='{k[0]}' spec_index={k[1]}"
                )
            crit_by_key.setdefault(k, []).append(cc)

        # >>> Aggregate by POLICY (one desired row per policy_name) <<<
        desired_by_policy: Dict[str, Dict[str, Any]] = {}
        for policy_name, grp in ep.groupby(ep["policy_name"].map(lambda v: str(v).strip())):
            specs: List[Dict[str, Any]] = []
            description = ""
            for _, e in grp.sort_values("spec_index").iterrows():
                p = str(e["policy_name"]).strip()
                idx = int(e["spec_index"]).__int__() if hasattr(e["spec_index"], "__int__") else int(e["spec_index"])  # safe cast
                source = str(e["source"]).strip()
                if not source:
                    raise ValidationError(f"EnrichmentPolicy: missing 'source' for policy='{p}' spec_index={idx}")
                if not description:
                    description = str(e.get("description") or "").strip()

                spec_rules = rules_by_key.get((p, idx), [])
                for rr in spec_rules:
                    cat = str(rr.get("category") or "").strip()
                    if cat not in {"simple", "type_based"}:
                        raise ValidationError(f"EnrichmentRules: invalid category '{cat}' policy='{p}' spec_index={idx}")
                    if cat == "simple" and not str(rr.get("event_key") or "").strip():
                        raise ValidationError(f"EnrichmentRules: missing event_key (simple) policy='{p}' spec_index={idx}")
                    if cat == "type_based" and not str(rr.get("type") or "").strip():
                        raise ValidationError(f"EnrichmentRules: missing type (type_based) policy='{p}' spec_index={idx}")
                    rr["operation"] = "Equals"
                spec_criteria = crit_by_key.get((p, idx), [])
                if not spec_criteria:
                    raise ValidationError(
                        f"EnrichmentPolicy: criteria required but not found for policy='{p}' spec_index={idx}"
                    )
                specs.append({"source": source, "rules": spec_rules, "criteria": spec_criteria})

            desired = {"name": policy_name, "specifications": specs}
            if description:
                desired["description"] = description
            desired_by_policy[policy_name] = desired

        for row in desired_by_policy.values():
            yield row

    # ---------------------- Canonicalization for diff ----------------------
    @staticmethod
    def _canon_rule(rr: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: rr.get(k) for k in _ALLOWED_RULE_KEYS if k in rr}
        # Normalize booleans/strings
        if "prefix" in out:
            out["prefix"] = bool(out["prefix"])  # ensure true boolean
        if out.get("operation") is None:
            out["operation"] = "Equals"
        return out

    @staticmethod
    def _canon_criteria(cc: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: cc.get(k, "") for k in _ALLOWED_CRITERIA_KEYS}
        # `value` key must exist; empty string is allowed
        if out.get("value") is None:
            out["value"] = ""
        return out

    @classmethod
    def _canon_spec(cls, spec: Dict[str, Any]) -> Dict[str, Any]:
        src = str(spec.get("source") or "").strip()
        rules = spec.get("rules") or []
        criteria = spec.get("criteria") or []
        crules = [cls._canon_rule(r) for r in rules]
        ccrit = [cls._canon_criteria(c) for c in criteria]
        # Sort for order-insensitive comparison
        crules_sorted = sorted(crules, key=lambda d: json.dumps(d, sort_keys=True))
        ccrit_sorted = sorted(ccrit, key=lambda d: json.dumps(d, sort_keys=True))
        return {"source": src, "rules": crules_sorted, "criteria": ccrit_sorted}

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return str(desired_row.get("name") or "").strip()

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        specs = desired_row.get("specifications") or []
        cspecs = [self._canon_spec(s) for s in specs]
        # Sort specs by (source, json)
        cspecs_sorted = sorted(
            cspecs, key=lambda s: (s.get("source"), json.dumps(s, sort_keys=True))
        )
        out = {"specifications": cspecs_sorted}
        # If you want description diffs to matter, uncomment next line
        # if desired_row.get("description"): out["description"] = desired_row["description"]
        return out

    def canon_existing(self, existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        if not existing_obj:
            return None  # BaseImporter expects None to mean Not Found
        specs = existing_obj.get("specifications") or []
        cspecs = [self._canon_spec(s) for s in specs]
        cspecs_sorted = sorted(
            cspecs, key=lambda s: (s.get("source"), json.dumps(s, sort_keys=True))
        )
        out = {"specifications": cspecs_sorted}
        # Same note as canon_desired about description
        # if existing_obj.get("description"): out["description"] = existing_obj["description"]
        return out

    # ---------------------- Payload builders ------------------------------
    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "name": desired_row["name"],
            "specifications": desired_row["specifications"],
        }
        if desired_row.get("description"):
            payload["description"] = desired_row["description"]
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing_obj: Dict[str, Any]) -> Dict[str, Any]:
        # Same payload shape as create; Director accepts PUT with full object
        return self.build_payload_create(desired_row)

    # ---------------------- EnrichmentSource checks ------------------------
    @staticmethod
    def _list_enrichment_sources(client: DirectorClient, pool_uuid: str, node: NodeRef) -> List[str]:
        path = client.configapi(pool_uuid, node.id, "EnrichmentSource")
        data = client.get_json(path) or []
        names: List[str] = []
        if isinstance(data, dict) and "data" in data:
            data = data.get("data") or []
        if isinstance(data, list):
            for item in data:
                # accept {"name": "..."} or plain strings just in case
                if isinstance(item, str):
                    names.append(item)
                elif isinstance(item, dict) and item.get("name"):
                    names.append(str(item["name"]))
        return list(sorted(set(names)))

    @staticmethod
    def _refresh_enrichment_sources(client: DirectorClient, pool_uuid: str, node: NodeRef) -> None:
        path = client.configapi(pool_uuid, node.id, "EnrichmentSource/refreshlist")
        try:
            client.post_json(path, {})
        except Exception as exc:
            log.warning("refreshlist failed on %s/%s: %s", pool_uuid, node.id, exc)

    def _ensure_sources(self, client: DirectorClient, pool_uuid: str, node: NodeRef, desired_row: Dict[str, Any]) -> Tuple[bool, List[str]]:
        want = {str(spec.get("source") or "").strip() for spec in desired_row.get("specifications", [])}
        want = {w for w in want if w}
        have = set(self._list_enrichment_sources(client, pool_uuid, node))
        missing = sorted(want - have)
        if not missing:
            return True, []
        # Try refresh then re-check
        self._refresh_enrichment_sources(client, pool_uuid, node)
        have = set(self._list_enrichment_sources(client, pool_uuid, node))
        missing = sorted(want - have)
        return (len(missing) == 0), missing

    # ---------------------- Apply -----------------------------------------
    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: str | None,
    ) -> Dict[str, Any]:
        desired = decision.desired or {}
        ok, missing = self._ensure_sources(client, pool_uuid, node, desired)
        if not ok:
            # We mark as "Skipped" via the status, but BaseImporter already set result from the diff
            msg = f"Missing enrichment sources: {', '.join(missing)}"
            log.error("%s — pool=%s node=%s policy=%s", msg, pool_uuid, node.name, desired.get("name"))
            return {"status": "Skipped", "error": msg}

        resource = "EnrichmentPolicy"
        if decision.op == "CREATE":
            payload = self.build_payload_create(desired)
            path = client.configapi(pool_uuid, node.id, resource)
            resp = client.post_json(path, payload)
        elif decision.op == "UPDATE":
            payload = self.build_payload_update(desired, decision.existing or {})
            if not existing_id:
                # Defensive: attempt to re-read list to find id, then fallback to create
                listing = client.get_json(client.configapi(pool_uuid, node.id, resource)) or []
                if isinstance(listing, dict) and "data" in listing:
                    listing = listing.get("data") or []
                for it in listing if isinstance(listing, list) else []:
                    if str(it.get("name") or "").strip() == desired.get("name"):
                        existing_id = it.get("id")
                        break
            if not existing_id:
                # No id found — perform a create to converge
                path = client.configapi(pool_uuid, node.id, resource)
                resp = client.post_json(path, payload)
            else:
                path = client.configapi(pool_uuid, node.id, f"{resource}/{existing_id}")
                resp = client.put_json(path, payload)
        else:
            # NOOP or SKIP shouldn't reach here due to BaseImporter branching,
            # but we return a minimal success dict just in case.
            return {"status": "Success", "monitor_ok": True}

        # --- Monitoring: prefer job id, fallback to monitor URL, then success flags
        job_id = client._extract_job_id(resp)  # type: ignore[attr-defined]
        monitor_path = client._extract_monitor_path(resp)  # type: ignore[attr-defined]
        mon_branch = "none"
        mon_ok = True
        last = {}
        if job_id and getattr(client.options, "monitor_enabled", True):
            mon_branch = "job"
            mon_ok, last = client.monitor_job(pool_uuid, node.id, job_id)
        elif monitor_path and getattr(client.options, "monitor_enabled", True):
            mon_branch = "url"
            mon_ok, last = client.monitor_job_url(monitor_path)
        else:
            # Best-effort: treat absence of monitor hints as success unless status says otherwise
            status = str((resp or {}).get("status") or "").lower()
            mon_ok = status in {"ok", "success", "completed", ""}

        result: Dict[str, Any] = {
            "status": "Success" if mon_ok else "Failed",
            "monitor_ok": mon_ok,
            "monitor_branch": mon_branch,
        }
        if not mon_ok:
            # Provide some context if monitoring failed
            result["error"] = (last.get("message") or last.get("status") or "monitor failed")
        return result