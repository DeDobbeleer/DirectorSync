# DirectorSync v3 — Test Plan

**Status:** Draft v0.9  
**Date:** 2025‑10‑07 (Europe/Paris)  
**Audience:** Engineering, QA, DevOps  
**Author:** (TBD)

---

## 1. Objectives
Ensure DirectorSync v3 (DSv3) is functionally equivalent to v2, deterministic, secure, and maintainable. The plan defines test types, data strategy, execution workflow (local & CI), quality gates, and acceptance criteria per importer.

---

## 2. Scope
**In scope:** config loader, profile DSL + linter, generic importer lifecycle, Director client behavior (HTTP + monitor), logging/redaction, reporting, CLI behavior, and migration parity (v2↔v3) for all importers.  
**Out of scope:** UI/GUI, live performance benchmarking beyond smoke KPIs (optional later).

---

## 3. Test Types & Coverage Targets
| Test Type        | Purpose | Target Coverage |
|------------------|---------|-----------------|
| Unit             | Guard individual functions/classes (deterministic transforms, mapping, diff, prechecks, linter, config merge, logger redaction). | ≥85% for core modules |
| Contract (v2↔v3) | Validate parity on golden datasets per importer (counts + normalized payloads + idempotence). | 100% status parity per dataset; 100% idempotence |
| Integration      | Exercise Generic Importer + Director Client against a fake API/VCR (timeouts, retries, pagination, monitor). | Critical paths covered |
| E2E Smoke        | CLI happy path with minimal profiles & sample sheet; verify artifacts and exit code. | Always green before release |
| Security/Logging | Ensure secrets redaction, no plaintext token leaks in console/files. | 0 leaks |
| Performance (opt)| Baseline timings for large sheets & inventory caches; regression guardrails. | No >20% regression vs. baseline |

---

## 4. Unit Tests — Details
1. **Config Loader**: precedence (CLI > ENV > YAML > defaults), env interpolation `${VAR}`, type coercion (bool/int), required fields validation, strict/permissive modes.  
2. **Profile Loader & Linter**: inheritance merge, required sections, placeholder validation, allowed transforms, `resolve` references to known inventories, precheck field existence.  
3. **Transforms**: `norm_str`, `split`, `uniq`, `sort`, `csv`, `to_bool`, `to_int` — determinism and error behavior.  
4. **Prechecks**: `non_empty`, `must_exist_many`, `unique_in_sheet` severities (`skip|error|warn`).  
5. **Diff Engine**: `list_as_sets`, `ignore_fields`, stability (no oscillation), deep nested payload handling.  
6. **Generic Importer Core**: decision matrix (CREATE/UPDATE/UNCHANGED/SKIP/ERROR/EXCEPTION), row‑level isolation, error wrapping.  
7. **Logging & Redaction**: console/file sinks, rotating policies, contextual fields, masking patterns (Authorization, token, password, api_key).  
8. **Reporting**: row results schema, summary counts, JSON artifact structure and determinism.

---

## 5. Contract Tests (v2 ↔ v3)
**Goal:** demonstrate behavioral parity and idempotence per importer.

### 5.1 Golden Datasets
- One dataset per importer (e.g., `repositories`, `normalization_policies`, `processing_policies`, `routing_policies`, `syslog_collectors`, `device_groups`, `devices`, `alert_rules`).  
- Content: input sheets (XLSX/CSV), expected normalized payloads, expected statuses.  
- Storage: versioned under `tests/contract/<importer>/golden/`.

### 5.2 Parity Metrics
- **Status parity:** counts match for `CREATED`, `UPDATED`, `UNCHANGED`, `SKIP`, `ERROR`.  
- **Payload parity:** compare **normalized** payloads (after `ignore_fields` and set‑lists).  
- **Idempotence:** a second run on the post‑apply state results in 100% `UNCHANGED`.

### 5.3 Comparator Rules
- Normalize lists as sets per profile, drop ignored fields, sort dict keys before compare, stringify scalars consistently.  
- Whitelist acceptable differences (e.g., server‑assigned `id`, timestamps) via `ignore_fields` only.

---

## 6. Integration Tests
Use a **Fake Director API** (in‑process server) or **VCR recordings**.

Scenarios:
- **Happy path CRUD** per importer with pagination on `list` endpoints.  
- **Network anomalies:** timeouts, 5xx with retries, 4xx without retries.  
- **Auth failures:** invalid token → verify error mapping and redaction.  
- **Monitor polling:** job life‑cycle to `ok_states`/`fail_states`.  
- **Inventory caching:** repeated `resolve` queries are cached per `{pool_uuid, node}`.

Outputs: structured logs (DEBUG files + INFO console), JSON report, deterministic exit codes.

---

## 7. E2E Smoke Tests
- Minimal `_defaults.yml` + `repositories.yml` + tiny sheet.  
- Run CLI end‑to‑end (`dry_run=true` and real run when a fake server is present).  
- Assert success exit code, presence of logs & JSON artifact, 100% predictable statuses.

---

## 8. Test Data Management
- **Synthetic**: targeted edge cases (missing columns, bad transforms, duplicates).  
- **Anonymized realistic**: optional; ensure no PII/secrets.  
- **Versioning**: golden files are immutable; changes require explicit review and checksum update.  
- **Determinism**: random seeds fixed; timestamps mocked.

---

## 9. Tooling & Execution
- **Runner:** `pytest` with `-q` default; markers for `unit`, `contract`, `integration`, `smoke`.  
- **Coverage:** `coverage.py` or pytest‑cov; thresholds enforced in CI.  
- **Linters:** ruff for style/quality (PEP‑8), optional mypy for typing (informative).  
- **Isolation:** tmp directories for logs/artifacts; environment variables sandboxed.

---

## 10. CI Pipeline
Stages (fail‑fast per stage):
1) **Lint** (ruff + optional type check).  
2) **Unit** (fast, parallel).  
3) **Contract** (medium; importer subsets in parallel).  
4) **Integration** (uses fake API/VCR).  
5) **Reports & Artifacts**: publish coverage, JUnit XML, HTML coverage, JSON run artifacts, zipped logs.

**Matrix:** Python 3.11 and 3.12; Ubuntu (primary), Windows (smoke), macOS (optional).  
**Gates:** block merge if coverage < threshold or any contract test fails.

---

## 11. Acceptance Criteria
- Unit coverage ≥85% on core modules (config, profiles, importer, client, logging).  
- Contract parity achieved for each importer on its golden dataset; idempotence verified.  
- Integration tests cover CRUD, errors, retries, monitor, pagination, redaction.  
- E2E smoke always green.  
- No secret leakage detected in logs.  
- CI pipeline green across the matrix.

---

## 12. Risks & Mitigations
- **Drift between v2 and v3 behaviors** → strict contract tests, reviewer checklist, side‑by‑side runs.  
- **Flaky tests due to timeouts** → higher timeouts in CI, retry logic, local fake server.  
- **Golden file brittleness** → stable comparators and explicit `ignore_fields`.  
- **Performance regressions** → baseline timings and budget (≤20% regression trigger).

---

## 13. Roles & Responsibilities (RACI)
- **Spec owner:** defines acceptance criteria and maintains golden datasets.  
- **Dev owner:** implements and maintains importer logic and profiles.  
- **QA owner:** curates test suites, monitors CI health, validates releases.  
- **Reviewer(s):** cross‑team code review (Director API, Security).

---

## 14. Schedule & Milestones
- M0: Test plan approved; CI skeleton in place; unit tests green for config/profiles core.  
- M1: Repositories migrated with passing contract/integration; smoke green.  
- M2+: Each importer migrated sequentially with gates: parity + idempotence + integration.  
- GA: All importers migrated; CI green; performance baseline acceptable.

---

## 15. Appendices
### A) Golden Dataset Layout (per importer)
```
/tests/contract/<importer>/
  golden/
    input.xlsx (or .csv)
    expected_payloads.json      # normalized
    expected_statuses.json      # row-level statuses
    comparator_rules.yml        # ignore_fields, list_as_sets overrides (if any)
```

### B) Comparator Normalization Rules
- Drop `ignore_fields`, sort dictionaries by key, cast lists marked as sets, stringify scalar numerics consistently.  
- For nested arrays-of-objects, apply normalization recursively.

### C) Exit Codes Policy
- `0` if no `ERROR/EXCEPTION`; non‑zero otherwise; allow override for CI diagnostic modes.

---

**End of Document**

