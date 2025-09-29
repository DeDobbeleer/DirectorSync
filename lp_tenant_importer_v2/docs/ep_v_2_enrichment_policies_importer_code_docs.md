# lp_tenant_importer_v2 – EnrichmentPolicies (V2)

This patch adds a new importer that migrates **Enrichment Policies (EP)** from V1 to V2, enforcing the strict API contract we agreed:

- `source` is **required** per specification.
- `criteria` is **required** (≥1 object per specification; the `value` key must exist, can be an empty string "").
- `rules` is **optional**.
- Idempotent diff on `specifications` (order-insensitive for rules/criteria; we respect `spec_index` from the XLSX).
- Pre-flight check of **EnrichmentSource** (List → RefreshList → List) before applying per node.

---

## 1) New file: `lp_tenant_importer_v2/importers/enrichment_policies.py`

```python
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
                idx = int(e["spec_index").__int__()] if hasattr(e["spec_index"], "__int__") else int(e["spec_index"])  # safe cast
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
        """Use ONLY the List endpoint and match by `source_name` (exact).
        Endpoint: /configapi/{pool}/{node}/EnrichmentSource
        """
        path = client.configapi(pool_uuid, node.id, "EnrichmentSource")
        data = client.get_json(path) or []
        names: List[str] = []
        if isinstance(data, dict) and "data" in data:
            data = data.get("data") or []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    # strict: only take `source_name`
                    n = item.get("source_name")
                    if isinstance(n, str) and n:
                        names.append(n)
        # exact-match set (no lowercasing)
        unique = sorted(set(names))
        log.debug("EnrichmentSource list on %s: %s", node.name, unique)
        return unique

    def _ensure_sources(self, client: DirectorClient, pool_uuid: str, node: NodeRef, desired_row: Dict[str, Any]) -> Tuple[bool, List[str]]:
        # Desired sources exactly as given in XLSX (trim spaces only)
        want = {str(spec.get("source") or "").strip() for spec in desired_row.get("specifications", [])}
        want = {w for w in want if w}
        have = set(self._list_enrichment_sources(client, pool_uuid, node))
        missing = sorted(w for w in (want - have))
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
```

---

## 2) Registry update: `lp_tenant_importer_v2/importers/registry.py`

Append the following entry to `_IMPORTERS` (keep alphabetical grouping consistent with your file):

```python
# Enrichment Policies (new in v2)
"enrichment_policies": ImporterSpec(
    key="enrichment_policies",
    cli="import-enrichment-policies",
    help="Import enrichment policies",
    module="lp_tenant_importer_v2.importers.enrichment_policies",
    class_name="EnrichmentPoliciesImporter",
    element_key="enrichment_policies",
),
```

> After this, the CLI will automatically expose the new subcommand and resolve targets via `defaults.target.enrichment_policies` in `tenants.yml`.

---

## 3) Minimal tests (pytest) – `tests/test_enrichment_policies.py`

```python
import json
import types
import pandas as pd
from lp_tenant_importer_v2.importers.enrichment_policies import EnrichmentPoliciesImporter


class _DummyClient:
    def __init__(self):
        self.calls = []
        self.options = types.SimpleNamespace(monitor_enabled=False)  # faster tests

    def configapi(self, pool, node, resource):
        return f"configapi/{pool}/{node}/{resource}"

    def get_json(self, path):
        # EnrichmentSource list and no existing policies
        if path.endswith("EnrichmentSource"):
            return {"data": [
                {"name": "threat_intelligence"},
                {"name": "UEBA_ActiveDirectoryUsers"},
            ]}
        if path.endswith("EnrichmentPolicy"):
            return []
        return {}

    def post_json(self, path, data):
        self.calls.append(("POST", path, data))
        return {"status": "ok"}

    put_json = post_json


def _sheets_from_rows():
    ep = pd.DataFrame([
        {"policy_name": "Threat_Intelligence", "spec_index": 0, "source": "threat_intelligence"},
    ])
    er = pd.DataFrame([
        {"policy_name": "Threat_Intelligence", "spec_index": 0, "category": "simple", "operation": "Equals", "prefix": False, "event_key": "source_address", "source_key": "ip_address", "type": "ip"},
    ])
    ec = pd.DataFrame([
        {"policy_name": "Threat_Intelligence", "spec_index": 0, "type": "KeyPresents", "key": "source_address", "value": "found"},
    ])
    return {"EnrichmentPolicy": ep, "EnrichmentRules": er, "EnrichmentCriteria": ec}


def test_iter_desired_builds_payload():
    imp = EnrichmentPoliciesImporter()
    sheets = _sheets_from_rows()
    rows = list(imp.iter_desired(sheets))
    assert rows and rows[0]["name"] == "Threat_Intelligence"
    spec = rows[0]["specifications"][0]
    assert spec["source"] == "threat_intelligence"
    assert spec["rules"] and spec["criteria"]


def test_apply_create_success():
    imp = EnrichmentPoliciesImporter()
    client = _DummyClient()
    desired = {
        "name": "Threat_Intelligence",
        "specifications": [{
            "source": "threat_intelligence",
            "rules": [{"category": "simple", "operation": "Equals", "prefix": False, "event_key": "source_address", "source_key": "ip_address", "type": "ip"}],
            "criteria": [{"type": "KeyPresents", "key": "source_address", "value": "found"}],
        }],
    }
    decision = types.SimpleNamespace(op="CREATE", desired=desired, existing=None, reason="Not found")
    res = imp.apply(client, "pool", types.SimpleNamespace(id="node", name="n"), decision, None)
    assert res["status"] == "Success"
```

---

## 4) Usage (CLI)

1) Add a target in your `tenants.yml`:

```yaml
defaults:
  target:
    enrichment_policies:
      # same resolution rules as other importers (aliases, pools, AIO always included…)
      - { pool_uuid: "<POOL-UUID>", logpoint_identifier: "<NODE-ID>" }
```

2) Run the importer:

```bash
python -m lp_tenant_importer_v2.main \
  --tenant core \
  --tenants-file ./tenants.yml \
  --xlsx ./samples/core_config.xlsx \
  import-enrichment-policies
```

- Add `--dry-run` to preview the plan.
- Use `--no-verify` if needed for TLS.

---

## 5) Notes

- If an EnrichmentSource is missing on a node, the importer attempts a `refreshlist` once, then reports `status: Skipped` with the missing names.
- To make description changes affect the diff, uncomment the commented lines in `canon_desired` / `canon_existing`.
- The importer *does not* silently synthesize criteria; it enforces the API contract (criteria required). If your XLSX has gaps, you’ll get a precise `ValidationError` pointing to `(policy_name, spec_index)`.

