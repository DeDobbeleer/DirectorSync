# DirectorSync v3 — Importer Acceptance Checklist

**Status:** Template v0.9  
**Date:** 2025‑10‑07 (Europe/Paris)  
**Audience:** Engineering, QA, Reviewers  
**Usage:** Duplicate per importer (repositories, normalization_policies, processing_policies, routing_policies, syslog_collectors, device_groups, devices, alert_rules) and fill.

---

## A. Metadata
- Importer name: ______________________  
- Profile file: ________________________  
- Dataset tag (golden): ________________  
- Reviewer(s): _________________________  
- Date: ________________________________

---

## B. Profile Validity
- [ ] Profile lints clean (permissive).  
- [ ] Profile lints clean (**strict**).  
- [ ] Required sections present (`endpoint`, `identity`, `xlsx.mapping`, `payload`).  
- [ ] Inheritance chain validated (no cycles; depth ≤ limit).  
- [ ] Endpoint placeholders resolvable from runtime context.  
- [ ] Allowed transforms only; parameters valid.  
- [ ] Resolve section references known inventories.  
- [ ] Prechecks reference existing logical fields.  
- [ ] Diff rules reference existing fields.

---

## C. Test Datasets
- [ ] Golden input present (XLSX/CSV).  
- [ ] Expected normalized payloads present.  
- [ ] Expected statuses present.  
- [ ] Comparator rules present (if overrides needed).  
- [ ] Edge cases covered (missing columns, duplicates, bad transforms, empty rows).

---

## D. Unit Tests
- [ ] Mapping determinism validated (same input → same mapped output).  
- [ ] Transforms behavior validated (`norm_str`, `split`, `uniq`, `sort`, `csv`, `to_bool`, `to_int`).  
- [ ] Prechecks severity behavior: `skip|error|warn`.  
- [ ] Diff normalization (`list_as_sets`, `ignore_fields`) stable and idempotent.

---

## E. Contract Tests (v2 ↔ v3)
- [ ] **Status parity** achieved (counts match for CREATED/UPDATED/UNCHANGED/SKIP/ERROR).  
- [ ] **Payload parity** (normalized) for updated/created rows.  
- [ ] **Idempotence** verified (second run → 100% UNCHANGED).  
- [ ] Any intentional deviations documented and approved.

---

## F. Integration Tests
- [ ] CRUD happy path with pagination on `list`.  
- [ ] Network anomalies: timeouts + retries, 5xx retry, 4xx no retry.  
- [ ] Auth failure mapping and redaction.  
- [ ] Monitor polling to `ok_states`/`fail_states` (if applicable).  
- [ ] Inventory caching exercised (resolve).

---

## G. Logging & Reporting
- [ ] Console INFO..CRITICAL present and readable.  
- [ ] File logs (action‑based + time‑rotated) include DEBUG traces.  
- [ ] **No secret leakage** in any logs (Authorization, token, password, api_key).  
- [ ] JSON report artifact generated and schema‑valid.  
- [ ] Exit code policy honored (0 when no ERROR/EXCEPTION).

---

## H. Rollout Readiness
- [ ] Feature flag/engine switch wired (v2↔v3).  
- [ ] Shadow run results recorded for at least N executions (N≥3).  
- [ ] Stakeholder sign‑off (CS/Support if applicable).  
- [ ] Runbook updated (how to enable/disable v3 per importer).  
- [ ] Known issues documented with mitigations.

---

## I. Sign‑Off
- Owner: ____________________  (date) ________  
- QA: _______________________  (date) ________  
- Security (if needed): ______ (date) ________  
- Product (if needed): _______ (date) ________

---

**End of Checklist**

