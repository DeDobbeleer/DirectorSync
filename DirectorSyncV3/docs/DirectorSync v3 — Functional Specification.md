# DirectorSync v3 — Functional Specification

**Status:** Draft v0.9  
**Date:** 2025‑10‑07 (Europe/Paris)  
**Audience:** Product, Engineering, QA, DevOps  
**Author:** (TBD)

---

## 1. Purpose & Scope
DirectorSync v3 ("DSv3") provides a robust, declarative, and testable framework to import tenant resources into Logpoint Director using YAML **profiles** and a unified **configuration** layer. DSv3 maintains feature parity with v2 while improving consistency, observability, and maintainability.

### In Scope
- Declarative profiles (YAML) to define how each Director resource is read, mapped, diffed, and applied.
- A "Generic Importer" that executes profiles uniformly.
- A configuration loader with clear precedence (CLI > ENV > YAML > defaults).
- Unified logging (console & files), secret redaction, and structured reporting.
- Test strategy (unit, contract, integration) and migration plan from v2.

### Out of Scope (Non‑Goals)
- UI/GUI.  
- Real‑time streaming imports.  
- Major behavior changes that would break v2 parity (unless explicitly accepted).

---

## 2. Stakeholders & Users
- **Primary users:** SIEM Engineers, Customer Success, MSSP integrators.
- **Internal stakeholders:** Product Management, Platform/Director teams, QA, Support.

---

## 3. Glossary
- **Profile:** YAML document describing endpoints, identity, XLSX mapping, transforms, prechecks, diff strategy, payload templating, and optional hooks.
- **Generic Importer:** Engine that executes a profile end‑to‑end (parse → resolve → diff → apply → report).
- **Row:** One logical resource instance parsed from input (e.g., one repository).
- **Natural Key:** Fields uniquely identifying a resource (e.g., name or node+name).
- **Apply Mode:** Either CRUD (create/update) or action (invoke a specific API action).

---

## 4. System Overview
DSv3 reads configuration, loads the relevant resource **profile**, parses inputs (XLSX/CSV), resolves dependencies (names → ids) via the Director API, performs **prechecks**, compares desired vs. current resources using a deterministic **diff**, then **applies** changes (create/update/action). It logs context‑rich traces and produces a machine‑readable report.

---

## 5. High‑Level Requirements
### 5.1 Functional
1. **Configuration Loader** merges settings from **CLI > ENV > YAML > defaults**, supports env interpolation (e.g., `${DIRECTOR_TOKEN}`), and basic type coercion (bool/int).  
2. **Profile DSL** supports: endpoints, identity, XLSX mapping with transforms, prechecks, diff rules (lists as sets, ignored fields), payload templating, and optional hooks.  
3. **Generic Importer** provides a fixed lifecycle: load → parse → resolve → precheck → list remote → diff → create/update/action → monitor → report.  
4. **Director Client**: HTTP with timeouts, retries, structured errors, secret redaction, and unified monitor handling.  
5. **CLI**: backward‑compatible commands/flags; optional hidden engine switch to pilot v3 during migration.  
6. **Reporting**: per‑row status (`CREATED`, `UPDATED`, `UNCHANGED`, `SKIP`, `ERROR`, `EXCEPTION`) + summary.

### 5.2 Non‑Functional
- **Reliability:** row‑level isolation (one failing row never aborts the whole run).  
- **Observability:** console INFO→CRITICAL; file DEBUG with action‑based and time‑rotated logs; correlation with `run_id`, `tenant`, `pool`, `profile`.  
- **Security:** never log secrets in clear; redact tokens/passwords; TLS verification configurable.  
- **Performance:** single remote listing per profile run when safe; caching for dependency lookups.  
- **Maintainability:** PEP‑8, docstrings, small focused modules, declarative profiles.

---

## 6. Configuration Loader — Specification
### 6.1 Source Precedence (highest first)
1) **CLI overrides** (e.g., `--tenant`, `--pool`, `--dry-run`, `--config`).  
2) **Environment variables** with prefix `DSYNC_` and nested keys via `__` (double underscore). Example: `DSYNC_DIRECTOR__BASE_URL` → `director.base_url`.  
3) **YAML file**: first existing among `./directorsync.yml`, `~/.config/directorsync/config.yml`, `/etc/directorsync/config.yml` (or a path supplied via `--config`).  
4) **Built‑in defaults**.

### 6.2 Configuration Schema (sections and keys)
- **app**: `run_id: string|null` (auto if null), `dry_run: bool`, `concurrency: int`.  
- **director**: `base_url: string`, `token: string` (secret), `verify_tls: bool`, `timeout_sec: int`, `retries: int`.  
- **profiles**: `search_paths: [string]`, `defaults: string` (default profile name).  
- **logging**: `base_dir: string`, `console_level: enum[INFO..CRITICAL]`, `file_level: enum[DEBUG..CRITICAL]`.  
- **inputs**: `xlsx_path: string`, `sheet_overrides: map<string,string>`.  
- **context**: `tenant: string`, `pool_uuid: string`.

### 6.3 Transformations & Validation
- **Env interpolation**: replace values like `${ENV_NAME}` with environment contents when present (useful for secrets).  
- **Type coercion**: booleans (`1/true/yes/y/on` → true) and integers for `timeout_sec`, `retries`, `concurrency`.  
- **Required for real apply**: `director.base_url`, `context.tenant`, `context.pool_uuid` (tolerate missing in `dry_run`).  
- **Strict mode (optional)**: reject unknown keys; default is permissive with warnings.

### 6.4 Output Contract
A typed configuration object accessible to all modules, with `run_id` always set (auto‑generated if absent).

---

## 7. Profile DSL — Specification
### 7.1 File Organization & Inheritance
- Profiles live under one or more **search paths** (configurable).  
- A profile may declare `extends: "_defaults"` (or any base) to reuse common settings.  
- Deep merge semantics for inheritance; child values override parent.

### 7.2 Required Sections (per profile)
- **resource** (string): logical name (e.g., `repositories`).  
- **endpoint** (map): URLs with placeholders, e.g., `list`, `create`, `update`, optional `action`. Placeholders include `{pool_uuid}`, `{node_id}`, `{id}`.  
- **identity** (map): `id_field`, `name_field`, `natural_key: [fields...]`.

### 7.3 XLSX Mapping
- **xlsx.sheet** (string) and `required_columns: [string...]` (advisory if using CSV/DF adapters).  
- **xlsx.mapping**: logical_field → one of:  
  - `{ col: "Name", transform: [ ... ] }`  
  - `{ expr: "${node}|${node_id}", transform: [ ... ] }`  
- **Column aliases** (optional) may be declared for resilience (e.g., `name: [repo, repository]`).

### 7.4 Transforms (allow‑list)
- `norm_str` (trim + collapse spaces), `split` (with `sep`), `uniq`, `sort`, `csv` (with `sep`), `to_bool`, `to_int`.  
- Transform lists are applied left‑to‑right; each transform must be deterministic and side‑effect‑free.

### 7.5 Dependency Resolution (optional `resolve`)
- Map logical names to **inventories**: e.g., resolve policy names to IDs.  
- Support `from` (inventory type), `lookup` (single), `lookup_many` (list).  
- Resolution happens **before** prechecks and payload rendering; failures should be expressible as `SKIP` with reason.

### 7.6 Prechecks
- Declarative checks evaluated on the **mapped** row:  
  - `non_empty(field)`  
  - `must_exist_many(field)`  
  - `unique_in_sheet(field)` (informational unless the adapter enforces it).  
- On failure, the row is marked `SKIP` with a human‑readable reason.

### 7.7 Diff Rules
- `list_as_sets: [field, ...]` — ignore list order by comparing as sets.  
- `ignore_fields: [id, updated_at, ...]` — drop fields from comparisons.  
- The comparison must be **stable and idempotent** (no oscillation between runs).

### 7.8 Payload Templating
- The `payload` section is a nested map; strings may include `${logical_field}` placeholders that are substituted from the mapped row after resolution and prechecks.

### 7.9 Hooks (optional)
- Profiles may reference **named hooks** for exceptional logic (e.g., AlertRules expansion).  
- Hooks are discoverable and must be pure functions at row‑level: `preprocess_row`, `post_payload`, `pre_apply`, `post_apply` (names reserved).  
- Hook use is discouraged unless strictly necessary; prefer declarative constructs.

### 7.10 Status Semantics
- `CREATED`: resource absent remotely; create succeeded.  
- `UPDATED`: resource present; diff non‑empty; update succeeded.  
- `UNCHANGED`: resource present; diff empty.  
- `SKIP`: precheck failed or explicit profile condition; must include a `reason`.  
- `ERROR`: profile/validation issue; row not applied.  
- `EXCEPTION`: unexpected runtime error; row not applied.

---

## 8. Generic Importer — Lifecycle & Contracts
1. **Load Profile** (by name) and validate mandatory sections.  
2. **Acquire Input Rows** (adapter: XLSX/CSV/DF).  
3. **Map Rows** via `xlsx.mapping` + transforms.  
4. **Resolve Dependencies** (if any).  
5. **Run Prechecks** → mark `SKIP` when failing.  
6. **List Remote Resources** once; index by `natural_key`.  
7. For each row:  
   7.1 Build **desired payload**;  
   7.2 Compute **diff** vs. remote (with rules);  
   7.3 Decide **create/update/unchanged**;  
   7.4 **Apply** using endpoints;  
   7.5 **Monitor** if async (job polling);  
   7.6 Emit **row result**.
8. **Report Summary**: counts per status, timings, and optional JSON artifact.

**Error Isolation:** Any exception during a row produces an `EXCEPTION` result with a message; the run continues.

---

## 9. Director API Client — Requirements
- Methods: `get_json(url)`, `post_json(url, payload)`, `put_json(url, payload)`, plus optional `invoke_action(url, payload)`.
- Timeouts and retry policy (configurable from `director.timeout_sec` and `director.retries`).
- TLS verification controlled by `director.verify_tls`.
- Logging: request method+path, correlation id, durations; **never** log full payloads containing secrets unredacted.  
- Monitoring: unified polling for job‑based operations (configurable fields if needed in profiles’ defaults).

---

## 10. CLI — Commands & Flags
- Preserve the v2 commands/flags visible to users.  
- Add an **internal** `--engine=v2|v3` (or env `DSYNC_ENGINE`) for migration and A/B tests.  
- Minimal global flags: `--config`, `--tenant`, `--pool`, `--dry-run`, `--log-level` (console only), plus importer‑specific options when applicable.

---

## 11. Logging & Observability
- **Sinks:** console (INFO→CRITICAL), **action‑based** file per run (DEBUG), **time‑rotated** app log (DEBUG).  
- **Context:** `run_id`, `action` (importer/profile), `tenant`, `pool`, `profile`.  
- **Format:** timestamp (UTC ISO‑8601), level, logger, context, message.  
- **Redaction:** bearer tokens, API keys, passwords, generic `token`/`password` fields.  
- **Metrics (optional):** counts per status, durations per phase.

---

## 12. Reporting
- **Human‑readable table** (console) with key columns: natural key, status, reason/error.  
- **JSON artifact** (file) including per‑row results and a run summary (counts + timings).  
- **Exit code** policy: `0` if no `ERROR/EXCEPTION`; non‑zero otherwise (configurable fail‑fast is out of scope for v3 MVP).

---

## 13. Testing Strategy
### 13.1 Unit Tests
- Config loader: precedence, env interpolation, type coercion, required fields.  
- Profile loader: inheritance, transforms, payload templating, diff rules.  
- Importer core: status decisions (created/updated/unchanged/skip) with fake client.  
- Redaction filter: ensure secrets never leak to logs.

### 13.2 Contract Tests (v2 ↔ v3)
- For each importer, build a **golden dataset**; compare v2 outputs vs. v3 results (counts and comparable payloads).  
- Idempotence: second run yields 100% `UNCHANGED`.

### 13.3 Integration Tests
- Mock Director API or VCR recordings.  
- Network error scenarios (timeouts, retries) and monitor polling.

**Coverage Target:** ≥80% for core modules.

---

## 14. Migration Plan (v2 → v3)
1. **Freeze v2** as `v2‑lts` (bugfix‑only).  
2. Add hidden **engine switch** to run specific importers via v3.  
3. Migrate in order: **repositories → normalization → processing → routing → syslog → device_groups → devices → alert_rules**.  
4. Shadow runs: v3 computes, v2 applies; compare.  
5. Promote importer to v3 default when contract tests pass; keep v2 fallback temporarily.  
6. Deprecate v2 once all importers are migrated and stable.

---

## 15. Acceptance Criteria
- **Functional parity** with v2 per importer on reference datasets.  
- **Idempotence** verified.  
- **Logging** present (three sinks) with redaction.  
- **Config loader** precedence honored; required values enforced.  
- **Profiles** are deterministic and documented.  
- **QA sign‑off** on contract and integration suites.

---

## 16. Security & Compliance
- Secrets are never logged; redaction patterns reviewed by Security.  
- TLS settings default to secure values (`verify_tls: true`).  
- Config files may reference environment variables for secrets.  
- Optional: SBOM and dependency scanning as part of CI (out of MVP scope).

---

## 17. Risks & Mitigations
- **Risk:** Incomplete parity for edge‑case importers (e.g., AlertRules).  
  **Mitigation:** Hooks + extended contract tests and pilot migrations.  
- **Risk:** Performance regressions due to additional abstraction.  
  **Mitigation:** Cache inventories; measure with integration tests.  
- **Risk:** Config drift across environments.  
  **Mitigation:** Single loader with clear precedence; JSON report artifacts archived per run.

---

## 18. Open Questions
- Do we need a profile‑level `update_strategy` (`replace|merge|patch`) for complex payloads in MVP?  
- Which exact fields are required for monitor polling per resource (or rely on defaults only)?  
- Should `unique_in_sheet` be enforced by the importer adapter or remain advisory?

---

## 19. Versioning & Release Management
- Semantic versioning for DSv3 (e.g., 3.0.0‑alpha, 3.0.0).  
- CHANGELOG with migration notes per importer.  
- Feature flags (engine switch) documented and time‑boxed.

---

## 20. Appendices
### 20.1 Status Taxonomy (row‑level)
`CREATED`, `UPDATED`, `UNCHANGED`, `SKIP`, `ERROR`, `EXCEPTION`.

### 20.2 Error Taxonomy
- **ProfileValidationError** (invalid/missing keys).  
- **TransformError** (invalid transform parameters or values).  
- **DependencyResolutionError** (missing referenced resources).  
- **HttpError** (client timeout, 4xx/5xx).  
- **UnexpectedError** (catch‑all, logged with stack trace, redacted).

### 20.3 Minimal Profile Schema (informative)
- `resource: string`  
- `endpoint: { list: string, create: string, update: string, action?: string }`  
- `identity: { id_field: string, name_field: string, natural_key: [string...] }`  
- `xlsx: { sheet?: string, required_columns?: [string...], mapping: { logical: { col?: string, expr?: string, transform?: [ transform | {fn: string, ...} ] } } }`  
- `resolve?: { logical: { from: string, lookup?: {by: string, using: string}, lookup_many?: {by: string, using: string} } }`  
- `prechecks?: [ { type: string, field: string } ]`  
- `diff?: { list_as_sets?: [string...], ignore_fields?: [string...] }`  
- `payload: object`  
- `hooks?: { preprocess_row?: string, post_payload?: string, pre_apply?: string, post_apply?: string }`

---

**End of Document**

