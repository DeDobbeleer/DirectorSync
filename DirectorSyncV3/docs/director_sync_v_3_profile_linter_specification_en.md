# DirectorSync v3 — Profile Linter Specification

**Status:** Draft v0.9  
**Date:** 2025‑10‑07 (Europe/Paris)  
**Audience:** Engineering, QA, Tech Writing  
**Author:** (TBD)

---

## 1. Purpose
Define a deterministic, actionable linter for DSv3 **Profile DSL** files to prevent runtime surprises, enforce conventions, and provide human‑readable diagnostics with stable error codes.

---

## 2. Scope & Non‑Goals
**In scope:** structural validation, semantics of placeholders, transform allow‑list, resolve targets, precheck references, diff rules, hooks signature presence (by name only), inheritance cycles, and version compatibility.  
**Out of scope:** contacting Director API, executing transforms, or mutating profiles.

---

## 3. Operating Modes
- **Permissive** (default): warns on unknown keys; continues if non‑critical checks fail.  
- **Strict**: unknown keys and non‑critical violations become errors.  
- **CI mode**: strict + JSON (and optional SARIF) output with stable codes.

---

## 4. Inputs & Outputs
**Input:** one or more profile files (`*.yml`) plus optional base `_defaults.yml`.  
**Output:**
- **Console report**: grouped by file, with levels `INFO/WARN/ERROR`.  
- **Machine‑readable**: JSON diagnostics array `{file, line, col, level, code, message, hint}`; optional SARIF.

Exit codes: `0` (no ERROR), `1` (ERROR present).

---

## 5. Validation Phases
### 5.1 YAML & Version
- Parse YAML; top‑level must be a **map**.  
- `version` required; must be a supported DSL version (currently `1`).

**Errors**  
- `DS-LINT-001` Invalid YAML or top‑level type.  
- `DS-LINT-002` Unsupported or missing `version`.

### 5.2 Inheritance
- `extends` optional; must reference an accessible profile file (including `_defaults`).  
- **Deep‑merge** semantics (maps merge; lists/scalars override).  
- Detect cycles; max depth configurable (default 5).

**Errors**  
- `DS-LINT-010` Unknown `extends` reference.  
- `DS-LINT-011` Inheritance cycle detected.  
- `DS-LINT-012` Excessive inheritance depth.

### 5.3 Required Sections & Types
- Required: `resource:string`, `endpoint:map`, `identity:map`, `xlsx:map`, `payload:map|list|scalar`.  
- `endpoint` must include `list`, `create`, `update` (strings).  
- `identity` must include `id_field`, `name_field`, `natural_key:list[string]`.

**Errors**  
- `DS-LINT-020` Missing required section.  
- `DS-LINT-021` Invalid type for required section.

### 5.4 Endpoint Placeholders
- Validate that each endpoint string placeholders `{...}` are among the **allowed context keys**: `{pool_uuid}`, `{node_id}`, `{id}`, and any profile‑declared dynamic context keys.  
- Prohibit unused placeholders and unmatched braces.

**Errors**  
- `DS-LINT-030` Unknown endpoint placeholder.  
- `DS-LINT-031` Malformed endpoint placeholder.  
- `DS-LINT-032` Unused/undefined dynamic placeholder.

### 5.5 XLSX Mapping
- `xlsx.sheet`: string (optional).  
- `required_columns`: list[string] (optional, advisory).  
- `column_aliases`: map[logical]→list[string] (optional).  
- `mapping`: required map[logical]→(col|expr).  
- For each logical field:
  - Either `col` **or** `expr` (mutually exclusive).  
  - `transform` (optional) must be a list; each entry either a string or map with `fn`.

**Errors**  
- `DS-LINT-040` Missing `mapping` or empty mapping.  
- `DS-LINT-041` Field must specify exactly one of `col` or `expr`.  
- `DS-LINT-042` Invalid transform specification.

### 5.6 Transforms Allow‑List
Allowed: `norm_str`, `split` (requires `sep`), `uniq`, `sort`, `csv` (optional `sep`), `to_bool`, `to_int`.  
Prohibit unknown transforms and unsupported parameters.

**Errors**  
- `DS-LINT-050` Unknown transform.  
- `DS-LINT-051` Unsupported parameter for transform.

### 5.7 Resolve Section
- For each entry: must include `from:string` and either `lookup` or `lookup_many`.  
- `lookup{by,using}` or `lookup_many{by,using}` are mandatory.  
- Inventory names (`from`) must be **recognized** by the runtime contract (documented list; linter configurable).

**Errors**  
- `DS-LINT-060` Resolve entry missing `from`/`lookup(_many)`.  
- `DS-LINT-061` Unknown inventory name.

### 5.8 Prechecks
- Each precheck: `{type, field}`; `type` in `{non_empty, must_exist_many, unique_in_sheet}`.  
- Optional `severity` in `{skip, error, warn}`; default `skip`.

**Errors**  
- `DS-LINT-070` Unknown precheck type.  
- `DS-LINT-071` Precheck references unknown logical field.

### 5.9 Diff Rules
- `diff.list_as_sets`: list[string]; fields must exist in payload or mapped logicals.  
- `diff.ignore_fields`: list[string].

**Warnings**  
- `DS-LINT-080` Diff references unknown field (permissive mode only).  
- (Strict → becomes `DS-LINT-020` missing/invalid section error if critical.)

### 5.10 Hooks
- `hooks` keys allowed: `preprocess_row`, `post_payload`, `pre_apply`, `post_apply`.  
- Values must be non‑empty strings (qualified names recommended: `module:function`).  
- Linter checks **presence format only** (no import/exec).

**Errors**  
- `DS-LINT-090` Unknown hook name.  
- `DS-LINT-091` Invalid hook reference format.

### 5.11 Unknown Keys & Conventions
- Flag unknown top‑level keys; in permissive mode → `WARN`, strict → `ERROR`.  
- Recommend naming conventions: kebab‑case for resources, snake_case for logical fields (advisory).

**Codes**  
- `DS-LINT-100` Unknown top‑level key.  
- `DS-LINT-101` Naming convention warning.

---

## 6. Configuration & CLI
- `--strict` to fail on WARN‑grade issues.  
- `--format json|text|sarif` output format (default `text`).  
- `--inventories <file>` injects the list of known inventory names for `resolve` validation.  
- `--allow-transform <name>` extend the allow‑list (temporary escape hatch).  
- `--max-depth <n>` set inheritance depth limit.  
- `--no-defaults` skip auto‑loading `_defaults.yml`.

---

## 7. Examples (Diagnostics)
- `ERROR DS-LINT-041: mapping.name -> specify either 'col' or 'expr', not both (file: repositories.yml:23)`  
- `WARN  DS-LINT-080: diff.list_as_sets references unknown field 'tags' (file: processing_policies.yml:48)`

---

## 8. Acceptance Criteria
- Linter detects all listed conditions with stable codes and precise locations.  
- Strict/permissive behaviors match spec; CI mode produces JSON/SARIF.  
- No false positives on provided example profiles; clear, actionable messages.

---

**End of Document**

