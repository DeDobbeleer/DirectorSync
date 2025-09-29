# DirectorSync v2 — Framework Deep Dive
**Status:** Living document — initial version _29 Sep 2025_  
**Scope:** Architecture, common trunk modules, importer algorithms (migrated modules), error handling, testing, and extensibility.

> This document complements, but does not replace, the short Developer Guide.  
> Audience: developers and advanced operators extending or running DirectorSync.

---

## 1) Executive Summary

DirectorSync v2 is a refactor of the v1 importer tool that preserves the **same user-facing CLI and inputs** while consolidating cross-cutting logic into a **common trunk**. The goals are:
- **Maintainability:** No duplicate plumbing across importers.
- **Idempotence & Safety:** Every run yields deterministic **NOOP/CREATE/UPDATE/SKIP** outcomes.
- **Observability:** Clear logs, structured results, and monitor-aware statuses.
- **Extensibility:** New importers are thin; behavior can be expressed declaratively (profiles) and registered centrally.

---

## 2) End-to-End Flow (Data → API)

```
+-------------------------+      +--------------------+      +-------------------+
|  Inputs (XLSX + YAML)   |      |   Common Trunk     |      |   Director APIs   |
|  - Excel workbooks      | ---> |  BaseImporter      | ---> |  /configapi/...   |
|  - tenants.yml          |      |    + diff engine   |      |  /monitorapi/...  |
|  - .env (URL, token)    |      |  DirectorClient    |      |                   |
+-------------------------+      +--------------------+      +-------------------+

Per command & per node:
  1) parse/normalize rows     4) fetch existing state
  2) validate inputs          5) canonicalize & diff
  3) resolve targets          6) apply (POST/PUT) + monitor
                              7) report (table/json)
```

**Invariant:** End users keep v1 habits (same flags, same spreadsheet format). All improvements are internal to v2.

---

## 3) Configuration Model

### 3.1 .env
- `LP_DIRECTOR_URL` — Director base URL.
- `LP_DIRECTOR_API_TOKEN` — Bearer token, masked in logs.
- `LP_TENANTS_FILE` — Path to the tenants descriptor (YAML).

### 3.2 tenants.yml (targets resolution)
- v2 resolves node targets **only** from the **global** section:
  ```yaml
  defaults:
    target:
      repos: ["backends"]
      routing_policies: ["backends"]
      normalization_policies: ["backends"]
      # new importers will add their own keys here
  ```
- Per-tenant overrides of `defaults.target` are ignored (warned), which eliminates inconsistent targeting.

### 3.3 Input XLSX conventions
- **Sheet names & required columns** are resource-specific.
- Multi-value cells accept **`|`** and **`,`** separators; values are trimmed.
- Empty sentinels: `""`, `nan`, `none`, `null`, `-` → treated as empty.
- Builders coerce types as required by the API (e.g., CSV strings vs arrays).

---

## 4) Common Trunk Modules

### 4.1 `core.director_client`
Responsibilities:
- **HTTP JSON** wrappers (`get_json`, `post_json`, `put_json`, `delete_json`), with retries, timeouts, and TLS options.
- **Path builders:** `configapi(pool_uuid, node_id, resource)`, `monitorapi(pool_uuid, node_id, job_id)`.
- **Monitor:** poll `/monitorapi/.../orders/{job_id}` until terminal state; return uniform statuses and messages.
- **Generic resource helpers:**  
  `list_resource`, `list_subresource`, `create_resource`, `update_resource`, `delete_resource` — thin adapters around JSON calls + monitor.

Design notes:
- Accept **heterogeneous shapes** from APIs: list responses may be raw lists or wrapped under `data/items/results`.
- **Log safety:** tokens masked; request/response bodies summarized at INFO, full payloads gated by DEBUG.

### 4.2 `core.config`
- Loads `.env`; parses `tenants.yml`.
- Validates structure and **resolves targets** from global `defaults.target.*`.
- Exposes node references (pool UUID, node ID, friendly name) used by the pipeline.

### 4.3 `importers.base`
Defines the importer lifecycle and overridable hooks:

- **Class attributes**
  - `resource_name`: registry key (e.g., `"repos"`).
  - `sheet_names`: tuple of accepted sheet names.
  - `required_columns`: XLSX columns that must be present.
  - `compare_keys`: fields participating in equality.

- **Core methods**
  - `validate(sheets)`: shape checks (`validators`).
  - `iter_desired(sheets)`: parse/normalize rows → desired objects.
  - `key_fn(desired_row)`: stable key (usually the `name`).
  - `fetch_existing(client, pool, node)`: list current objects; preload caches if needed.
  - `canon_desired(row) / canon_existing(obj)`: **canonical forms** for comparison (e.g., lists sorted; IDs mapped to names).
  - `build_payload_create(row) / build_payload_update(row, existing)`: API payloads.
  - `apply(client, pool, node, decision, existing_id)`: perform POST/PUT with monitor; may **SKIP** if pre-flight fails.

- **Orchestration**
  The base class coordinates **load → validate → fetch → diff → apply → report**, using `utils.diff_engine` for decisions and `utils.reporting` for output.

### 4.4 Utilities (`utils.*`)
- **`diff_engine`**: computes `NOOP/CREATE/UPDATE/SKIP` by comparing canonical desired/existing dictionaries; supports nested list comparisons using **order-insensitive** strategies when appropriate.
- **`validators`**: asserts sheet and column presence with clear error messages.
- **`resolvers`**: minimal caches (e.g., name↔ID maps per node).
- **`reporting`**: renders table or JSON; merges monitor results.
- **`logging_utils`** (in `core`): sets log format, levels, and masks sensitive fields.

---

## 5) Registry & Profiles

### 5.1 Importer Registry (`importers/registry.py`)
- Central **directory** for importers: each entry declares
  - `key` (internal), `cli` (subcommand), `module`, `class_name`,
  - `help` text and `element_key` (used to pick targets from `defaults.target.*`).
- The CLI (`main.py`) **autogenerates commands** from the registry and routes to a common handler, so adding an importer is declarative.

**Current entries (migrated):**
- `repos` → `import-repos` (targets: `backends`)
- `routing_policies` → `import-routing-policies` (targets: `backends`)
- `normalization_policies` → `import-normalization-policies` (targets: `backends`)

### 5.2 Resource Profiles (declarative)
Two forms coexist:
- **Python profile** for Repos (see `utils/resource_profiles.py`): encapsulates parse rules, equality, and payload shaping.
- **YAML profiles** (`resources/profiles.yml`): a generalized format to describe resources (columns, mappings, equality strategies, lookups). This is the target for converging future importers.

**Roadmap:** migrate Routing Policies and Normalization Policies to declarative profiles to reduce imperative code.

---

## 6) Algorithms — Migrated Importers (Complete)

> The following describe the exact behavior at the time of writing. Any API changes or new edge cases should be reflected here.

### 6.1 Repos

**Inputs (sheet `Repo`):**
- Key columns (typical): `name`, `storage_paths` (multi), `retention_days` (multi), optional HA fields (paired lists).
- Multi-values can use `|` or `,`. Pairs must align index-wise (`path[i]` ↔ `retention[i]`).

**Pre-flight:**
- Verify that every desired `path` exists in the node’s `RepoPaths` inventory; if not, **SKIP** with reason.

**Fetch existing:**
- `list_resource(..., "Repos")` (naming simplified). Normalize shapes (raw list vs wrapped).

**Canonicalization:**
- `hiddenrepopath`: **order-insensitive** list of dicts; compare by keys `{path, retention}`.
- `repoha`: optional **order-insensitive** list of dicts; compare by keys `{ha_li, ha_day}`.
- Scalar `name` compared directly.

**Decision:**
- If all canonical fields match → **NOOP**. Else, choose **CREATE** or **UPDATE** depending on existence by `name`.

**Payload:**
- `POST/PUT` with list-of-dicts for `hiddenrepopath`, optional `repoha`.
- Types are coerced (e.g., integers for retention fields).

**Apply & Monitor:**
- `create_resource` / `update_resource`; if job returned, monitor until terminal; merge final status into the report.

**Edge cases:**
- Mismatched list lengths (`storage_paths` vs `retention_days`) → validation error.
- Unknown repo path → **SKIP** with reason.
- Partial updates are handled by sending the **full desired** state (source of truth).

---

### 6.2 Routing Policies

**Inputs (sheet `RoutingPolicy`):**
- Columns: `policy_name`, `rule_type`, `key`, `value`, `repo`, `drop`, `catch_all`, `active`.
- Rows are **grouped by `policy_name`**; multi-value columns are zipped into **criteria** list.

**Lookups:**
- Resolve repo **names → IDs** per node, both for each criterion and for `catch_all`.

**Fetch existing:**
- `list_resource(..., "RoutingPolicy")`.

**Canonicalization:**
- `routing_criteria`: list of dicts compared **order-insensitively** by keys `{type,key,value,repo}`; `drop` is compared as a value.
- Scalars: `active` (boolean-ish), `catch_all` (repo ID) compared directly.

**Decision:**
- **NOOP** when the canonical criteria set + scalars match.
- **CREATE** when policy absent; **UPDATE** when present but different.

**Payload:**
- Minimal, documented fields only: `policy_name`, `routing_criteria`, `catch_all`, `active` (coerced to the API-expected shape).  
- Repos are **IDs** at payload time.

**Apply & Monitor:**
- POST/PUT via `DirectorClient`, wait for monitor (if any).

**Edge cases:**
- Unknown repo in criteria or catch-all → **SKIP** with explicit reason.
- Empty policy (no criteria, no catch-all) → **SKIP**.

---

### 6.3 Normalization Policies

**Inputs (sheet `NormalizationPolicy`):**
- Columns: `policy_name`, `normalization_packages` (names), `compiled_normalizer` (names).  
- An entirely empty row (both lists empty) → **SKIP**.

**Dependencies:**
- Preload `NormalizationPackage` inventory (name↔ID).
- Preload `CompiledNormalizers` inventory (names).
- If any referenced package or compiled is missing → **SKIP** with reason.

**Fetch existing:**
- `list_resource(..., "NormalizationPolicy")`.  
- If list views omit `compiled_normalizer`, perform best-effort detail GET by ID and merge.

**Canonicalization (comparison is by NAMES):**
- Map existing `normalization_packages` **IDs → names** using cache.
- For both fields, sort lists; compare by names.

**Decision:**
- `NOOP` if both lists match by name.
- `CREATE` or `UPDATE` otherwise.

**Payload (CSV contract):**
- The API expects **CSV strings**, not JSON arrays:
  - **POST**: `{ name, norm_packages: "ID1,ID2" | "", compiled_normalizer: "C1,C2" | "" }`
  - **PUT**: `{ norm_packages: "ID1,ID2" | "", compiled_normalizer: "C1,C2" | "" }`
- Empty lists become empty strings to **clear** the fields.

**Apply & Monitor:**
- Use generic helpers; monitor when applicable.

**Edge cases:**
- Package/compiled missing → SKIP (never attempt partial payload).
- Inconsistent API shapes (list/dict wrapping) are tolerated by list helpers.

---

## 7) Error Handling & SKIP Policy

**Categories:**
- **VALIDATION ERROR** (e.g., missing sheet/columns) → abort command with clear message.
- **SKIP** (non-fatal, per-row): missing dependencies, intentionally empty config, unknown repos, invalid references.
- **FAIL** (fatal per-row): network/HTTP errors that prevent certainty; surfaced with context.
- **NOOP**: explicit when desired == existing.

**Principles:**
- Prefer **SKIP** over FAIL when the issue is input/data completeness (operator can fix and re-run).
- Aggregate errors per resource to avoid cascading aborts.

---

## 8) Observability & Logging

- Levels: `DEBUG` (deep payloads), `INFO` (pipeline milestones, counts), `WARNING` (SKIPs), `ERROR` (failures).
- Tokens are masked in all log lines.
- Reports: **table** (human) and **json** (machine), always including a `status` per item. Monitor terminal states (e.g., `Created`, `Updated`, `Noop`, `Skipped`) are propagated.

---

## 9) Performance & Scaling

- **Caching:** name↔ID maps and inventories are kept per node for the duration of a run.
- **Batching:** where APIs support it, can be explored in future importers (current ones operate item-wise).
- **Detail calls:** used only when list views are incomplete (e.g., NP compiled). Prefer minimal footprints.

---

## 10) Security

- Secrets only in `.env` and process memory; redact from logs.
- HTTPS verification enabled by default; `--no-verify` is available for lab use only (surfaces a warning).
- Excel/YAML inputs are trusted only after validation; no dynamic code execution.

---

## 11) Testing Strategy

- **Unit tests:** parsing, canonicalization, and diff decisions. Include CSV vs array edge cases for NP.
- **Contract tests:** recorded API fixtures covering list vs wrapped shapes and missing fields.
- **Idempotence tests:** second run after apply yields 100% NOOP.
- **Dry-run parity:** dry-run decision set equals apply decision set (minus monitor statuses).

---

## 12) CLI & Operations Runbook

**Pattern:**
```
python -m lp_tenant_importer_v2.main \
  --tenant <tenant_name> \
  --tenants-file ./tenants.yml \
  --xlsx ./samples/<file>.xlsx \
  <command> [--dry-run] [--format table|json] [--no-verify]
```

**Examples (migrated):**
- `import-repos`
- `import-routing-policies`
- `import-normalization-policies`

**Typical flow:**
1. Run with `--dry-run` and review plan.
2. Run without `--dry-run` to apply.
3. Re-run to confirm **NOOP** (idempotence).

**Troubleshooting:**
- CSV vs Arrays (NP): ensure payload builders emit CSV strings.
- Unknown repo/package/compiled: create them first or fix names; re-run.
- TLS issues: use `--no-verify` temporarily in lab, never in production.

---

## 13) Extensibility — Adding a New Importer

**Checklist:**
1. Define sheet and required columns (add to `profiles.yml` if declarative).
2. Implement `validate`, `iter_desired`, and canonicalization rules.
3. Implement `fetch_existing` (and preload caches if dependencies exist).
4. Choose equality keys and list comparison strategy (order-insensitive where natural).
5. Build payloads (respect API quirks: CSV vs arrays vs nested dicts).
6. Implement `apply` with SKIP logic for missing dependencies.
7. Register it in `importers/registry.py` with `element_key` and `cli`.
8. Add tests (parsing, diff, CSV quirks, idempotence).
9. Update docs: this deep dive + short Developer Guide.

**Design patterns:**
- Prefer **name-based** comparisons, convert to IDs only at payload time.
- When list views are incomplete, **fallback to GET detail** for comparison only.
- Keep importer code thin; move stable behavior into **profiles**.

---

## 14) Roadmap & Change Log

- **Migrated now:** Repos, Routing Policies, Normalization Policies.
- **Next candidates:** Processing Policies, Devices, Device Groups, Syslog Collectors, Alerts.
- **Breaking changes tracker:**  
  - NP payloads -> **CSV** strings (v2) — documented and implemented.

A table of migrated modules is maintained in the short Developer Guide and mirrored here.

---

## 15) Appendices

### A) Current Sheet Specifications (Required Columns)
| Resource | Sheet | Required Columns |
|---------|-------|------------------|
| Repos | `Repo` | `name`, `storage_paths`, `retention_days` *(+ optional HA fields)* |
| Routing Policies | `RoutingPolicy` | `policy_name`, `rule_type`, `key`, `value`, `repo`, `drop`, `catch_all`, `active` |
| Normalization Policies | `NormalizationPolicy` | `policy_name`, `normalization_packages`, `compiled_normalizer` |

> Multi-values accept `|` or `,`. Empty cells are skipped after normalization.

### B) API Surfaces (Abstracted by `director_client`)
- Repos: `Repos` resource (+ `RepoPaths` pre-flight list).
- Routing Policies: `RoutingPolicy` resource.
- Normalization Policies: `NormalizationPolicy`, `NormalizationPackage`, `NormalizationPackage/CompiledNormalizers`.

> Exact URLs are built with `configapi(pool_uuid, node_id, <Resource or Subpath>)` and may differ by Director version; the client tolerates `data/items/results` wrappers.

### C) Status Reference
- **NOOP** — existing config already matches desired state.
- **CREATE** — resource not found; POST will be issued.
- **UPDATE** — resource found but differs; PUT will be issued.
- **SKIP** — input/dependency invalid; nothing applied; a human-readable reason is recorded.

---

_This document is versioned with the repository and should be updated whenever:_
- A new importer is migrated or substantially changed.
- An API contract changes (e.g., NP CSV fields).
- A new equality or validation rule is introduced.
