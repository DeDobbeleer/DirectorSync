# DirectorSync v3 — Profile DSL Specification

**Status:** Draft v0.9  
**Date:** 2025‑10‑07 (Europe/Paris)  
**Audience:** Engineering, QA, Tech Writing  
**Author:** (TBD)

---

## 1. Goals
Define a concise, deterministic, and extensible **declarative language** (YAML) to describe how a Director resource is **read**, **mapped**, **validated**, **diffed**, and **applied** by the Generic Importer. The DSL must be:
- **Predictable** (idempotent runs; stable diffs),
- **Safe** (clear prechecks; never crashes a run),
- **Maintainable** (small, obvious building blocks),
- **Evolvable** (versioned; backward‑compatible where possible).

---

## 2. File Organization
- Profiles live under **one or more search paths** (config.profiles.search_paths).  
- Each profile is a YAML file named `<resource>.yml` (e.g., `repositories.yml`).  
- A special base file `_defaults.yml` defines global defaults for common sections.  
- **Versioning:** each profile includes `version: 1` (DSL version), for forward evolution.

---

## 3. Inheritance & Merge Semantics
- Optional `extends: "_defaults"` (or another profile name).  
- **Deep merge** rules: maps merge recursively; scalars/lists **override**.  
- **No cycles**: loaders must detect and reject circular inheritance.  
- Guidance: keep `_defaults.yml` minimal (diff rules, monitor defaults, header normalization).

---

## 4. Required Sections & Types
A valid profile MUST declare at least:
- `resource: string` — human‑readable name (e.g., `repositories`).
- `endpoint: map` — REST paths with Python `str.format` placeholders:  
  - Required: `list`, `create`, `update`  
  - Optional: `action` (for non‑CRUD operations)
- `identity: map` — fields used to identify remote objects:  
  - `id_field: string` (default: `id`)  
  - `name_field: string` (default: `name`)  
  - `natural_key: [string, ...]` — fields composing the unique logical key
- `xlsx: map` — input parsing spec (works with XLSX/CSV/DF adapters):  
  - `sheet: string` (advisory)  
  - `required_columns: [string, ...]` (advisory)  
  - `column_aliases: { logical: [alias1, alias2, ...] }` (optional)  
  - `mapping: map` (see §5)
- `payload: object` — nested map/list with `${placeholder}` strings (see §8).

Optional sections:
- `resolve: map` (dependency resolution, §6)  
- `prechecks: [check, ...]` (§7)  
- `diff: { list_as_sets?: [string...], ignore_fields?: [string...] }` (§9)  
- `monitor: { job_field, ok_states, fail_states }` (fallbacks provided by `_defaults`)  
- `hooks: { preprocess_row?, post_payload?, pre_apply?, post_apply? }` (§10)

**Types:** YAML scalars (string/number/bool), sequences (list), and mappings (map). All transforms and hooks must be pure functions (no global side effects).

---

## 5. Mapping Rules (xlsx.mapping)
Each **logical field** is described by one of:
- **Column mapping**: `{ col: "Name", transform?: [ ... ] }`
- **Expression mapping**: `{ expr: "${node}|${node_id}", transform?: [ ... ] }`

### 5.1 Transforms (allow‑list)
Transforms are applied **left‑to‑right**:
- `norm_str` — trim and collapse whitespace (no case‑fold by default).  
- `split` — `{ fn: "split", sep: ";" }` → `["a","b"]`.  
- `uniq` — remove duplicates while keeping first occurrence.  
- `sort` — lexical sort (stable).  
- `csv` — join arrays into `"a,b"` (configurable `sep`).  
- `to_bool` — truthy strings (`1/true/yes/y/on`).  
- `to_int` — strict integer conversion (errors if non‑numeric).

**Constraints**
- Transforms must be **deterministic** and **total** (error → `TransformError` → row `ERROR`, not crash).  
- Only allow documented transforms; custom ones must be implemented as **hooks**.

### 5.2 Expression Semantics
- `${field}` placeholders refer to **mapped input** only within the same row context.  
- Missing variables substitute to empty string; profiles should guard via prechecks if needed.  
- Expressions are for strings; do not coerce types implicitly (use transforms).

---

## 6. Dependency Resolution (`resolve`)
Allows mapping **names to IDs** by querying Director inventories before building payloads.

Example:
```yaml
resolve:
  node_id:
    from: "nodes"
    lookup: { by: "name", using: "${node}" }
  policy_ids:
    from: "processing_policies"
    lookup_many: { by: "name", using: "${policies}" }
```

**Semantics**
- `from`: inventory name (implementation‑defined; must be documented by the adapter).  
- `lookup`: single result; sets the logical field to a scalar id or null.  
- `lookup_many`: list result; sets the logical field to `[id, ...]` (order not guaranteed).  
- Failures do **not** crash the run: combine with prechecks to decide **SKIP** vs **ERROR** (see §7).

**Caching**
- Inventory results SHOULD be cached per run and per `{pool_uuid, node}` for performance.

---

## 7. Prechecks
Declarative validations evaluated **after mapping & resolve** and **before payload**:
- `non_empty`: `{ type: "non_empty", field: "name" }`  
- `must_exist_many`: `{ type: "must_exist_many", field: "policy_ids" }`  
- `unique_in_sheet`: `{ type: "unique_in_sheet", field: "name" }` (advisory unless the adapter enforces it)

**Severity** (optional): `severity: skip|error|warn` (default: `skip`).  
- `skip`: mark row `SKIP` with `reason`.  
- `error`: mark row `ERROR` with `error` message.  
- `warn`: continue but annotate row with `warning` (shown in report).

---

## 8. Payload Templating
- `payload` is a JSON‑like YAML object where strings may contain `${logical_field}`.  
- Substitution occurs **after** mapping, resolve, and prechecks.  
- Nested lists and maps are supported.  
- The resulting payload must be **serializable** and **consistent** with the Director API expectations.

---

## 9. Diff Strategy
- `list_as_sets`: compare the specified list fields as **sets** (order ignored).  
- `ignore_fields`: drop fields entirely from comparisons (e.g., `id`, `updated_at`).  
- Diff is performed on **normalized** (comparable) payloads to ensure idempotence.  
- Profiles must avoid fields with nondeterministic content (timestamps) unless ignored.

---

## 10. Hooks (escape hatch)
Profiles MAY declare optional hooks by **qualified name** (`module:function` or `profile_local_name`):
- `preprocess_row(mapped) -> mapped` — adjust mapped/resolve result before prechecks.  
- `post_payload(payload, mapped) -> payload` — adjust final payload.  
- `pre_apply(ctx, payload) -> (payload, meta)` — last gate before HTTP.  
- `post_apply(ctx, response) -> response` — normalize / annotate result.

**Constraints**
- Hooks must be **pure** at row level (no shared mutable state).  
- Hooks must be **deterministic**, and any failure becomes `ERROR` for that row.  
- Use hooks sparingly; prefer declarative specs for maintainability.

---

## 11. Apply Mode & Monitor
- `apply.mode: "crud" | "action"`  
  - `crud`: use `list/create/update` endpoints.  
  - `action`: call `action` endpoint with profile‑defined action body (outside MVP unless needed).
- `monitor`: defaults from `_defaults.yml` (e.g., `job_field`, `ok_states`, `fail_states`). Profiles may override when resource‑specific.

---

## 12. Status Model (row‑level)
- `CREATED` — resource was absent, create succeeded.  
- `UPDATED` — resource existed and differed; update succeeded.  
- `UNCHANGED` — resource existed and matched desired state.  
- `SKIP` — precheck failed or explicit profile rule; includes human‑readable `reason`.  
- `ERROR` — profile/validation issue (e.g., bad transform).  
- `EXCEPTION` — unexpected runtime error (caught and reported).

---

## 13. Linting & Validation
A **profile linter** SHALL verify:
- Presence of required sections (`endpoint`, `identity`, `mapping`, `payload`).  
- Endpoint placeholders are resolvable from runtime context.  
- `natural_key` fields exist in mapped output.  
- Transforms are from the allow‑list; parameters are supported.  
- `resolve` entries reference known inventories.  
- `prechecks` reference existing logical fields.  
- No unknown top‑level keys (when strict mode is enabled).

**Error Codes** (examples):
- `DS-PROFILE-001` Missing required section  
- `DS-PROFILE-002` Unknown transform  
- `DS-PROFILE-003` Invalid endpoint placeholder  
- `DS-PROFILE-004` Precheck references unknown field

---

## 14. Examples
### 14.1 Minimal Repositories Profile
```yaml
version: 1
extends: "_defaults"
resource: "repositories"
endpoint:
  list:   "/api/director/v2/pools/{pool_uuid}/configapi/repositories"
  create: "/api/director/v2/pools/{pool_uuid}/configapi/repositories"
  update: "/api/director/v2/pools/{pool_uuid}/configapi/repositories/{id}"
identity:
  id_field: "id"
  name_field: "name"
  natural_key: ["name"]
xlsx:
  sheet: "Repositories"
  required_columns: ["name", "path", "type"]
  mapping:
    name: { col: "name", transform: ["norm_str"] }
    path: { col: "path" }
    type: { col: "type", transform: ["norm_str"] }
prechecks:
  - { type: "non_empty", field: "name" }
  - { type: "non_empty", field: "path" }
payload:
  name: "${name}"
  path: "${path}"
  type: "${type}"
```

### 14.2 Processing Policies with Resolve
```yaml
version: 1
extends: "_defaults"
resource: "processing_policies"
endpoint:
  list:   "/api/director/v2/pools/{pool_uuid}/nodes/{node_id}/configapi/processing_policies"
  create: "/api/director/v2/pools/{pool_uuid}/nodes/{node_id}/configapi/processing_policies"
  update: "/api/director/v2/pools/{pool_uuid}/nodes/{node_id}/configapi/processing_policies/{id}"
identity:
  id_field: "id"
  name_field: "name"
  natural_key: ["node_tag", "name"]
xlsx:
  sheet: "ProcessingPolicies"
  mapping:
    node_tag: { expr: "${node}|${node_id}", transform: ["norm_str"] }
    name:     { col: "policy_name", transform: ["norm_str"] }
    nproc:    { col: "nproc", transform: [{ fn: "split", sep: ";" }, "uniq", "sort"] }
    eproc:    { col: "eproc", transform: [{ fn: "split", sep: ";" }, "uniq", "sort"] }
    rproc:    { col: "rproc", transform: [{ fn: "split", sep: ";" }, "uniq", "sort"] }
resolve:
  node_id:
    from: "nodes"
    lookup: { by: "name", using: "${node}" }
  nproc_ids:
    from: "normalization_policies"
    lookup_many: { by: "name", using: "${nproc}" }
  eproc_ids:
    from: "event_processors"
    lookup_many: { by: "name", using: "${eproc}" }
  rproc_ids:
    from: "routing_policies"
    lookup_many: { by: "name", using: "${rproc}" }
prechecks:
  - { type: "must_exist_many", field: "nproc_ids" }
  - { type: "must_exist_many", field: "eproc_ids" }
  - { type: "must_exist_many", field: "rproc_ids" }
diff:
  list_as_sets: ["normalization_policy_ids", "event_processor_ids", "routing_policy_ids"]
payload:
  name: "${name}"
  normalization_policy_ids: "${nproc_ids}"
  event_processor_ids: "${eproc_ids}"
  routing_policy_ids: "${rproc_ids}"
```

---

## 15. Security & Compliance
- Profiles must not embed secrets.  
- If a payload field references secrets at runtime, redaction rules in logging MUST hide them.

---

## 16. Acceptance Criteria (DSL)
- Profiles validate with a linter; errors provide actionable messages.  
- Mapping + resolve + prechecks produce deterministic outputs on the same inputs.  
- Diff strategy yields idempotent behavior (second run → `UNCHANGED`).  
- Hooks remain optional and limited; most resources are expressible declaratively.

---

## 17. Open Issues
- Do we need `update_strategy: replace|merge|patch` in MVP or later?  
- Should `unique_in_sheet` be hard‑enforced by adapters?  
- How to standardize inventory names (`nodes`, `repositories`, etc.) across Director versions?

---

**End of Document**

