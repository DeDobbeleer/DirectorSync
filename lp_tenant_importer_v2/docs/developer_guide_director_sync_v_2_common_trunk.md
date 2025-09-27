# Developer Guide — DirectorSync (v2, Common Trunk)

> Status: Draft (focused on **Repos** as the canonical example; other importers will follow the same pattern)
> Audience: Developers building, extending, or operating the DirectorSync importer tool

---

## 1. Overview
DirectorSync is a command-line tool that synchronizes configuration data ("resources") into Logpoint Director via its HTTP APIs. The v2 refactor preserves the **same end-user CLI and inputs** as v1 while moving shared plumbing into a **common trunk** for maintainability and faster feature work.

**Key goals**
- Eliminate redundancy across importers (Repos, Routing Policies, Normalization Policies, Processing Policies, Devices, Device Groups, Syslog Collectors, Alerts).
- Keep the CLI and input files identical for users.
- Provide strong logging, validation, and a clear decision model (**NOOP / CREATE / UPDATE / SKIP**).
- Make importer behavior **declarative** via **resource profiles** (built-in defaults + optional YAML overrides).

**Scope of this guide**
- Architecture and repository structure
- Configuration and inputs
- Common trunk modules
- Resource profiles (declarative behavior)
- Detailed reference for **Repos**
- Testing, packaging, and migration notes

---

## 2. Repository Structure
```
lp_tenant_importer_v2/
├─ __init__.py
├─ main.py                     # CLI (same commands/flags as v1)
├─ core/
│  ├─ __init__.py
│  ├─ logging_utils.py         # logger setup and helpers
│  ├─ config.py                # .env + tenants.yml loader, target resolver (global-only)
│  └─ director_client.py       # generic JSON HTTP client + monitor + generic resource helpers
├─ importers/
│  ├─ __init__.py
│  ├─ base.py                  # shared pipeline: load→validate→fetch→diff→apply→report
│  └─ repos.py                 # canonical resource importer (uses resource profile)
└─ utils/
   ├─ __init__.py
   ├─ diff_engine.py           # NOOP/CREATE/UPDATE/SKIP decision helper
   ├─ validators.py            # XLSX sheet/column validation
   ├─ resolvers.py             # simple in-memory caches for lookups
   └─ reporting.py             # uniform table/json output
```

> The initial v2 release ships **Repos** fully migrated onto the common trunk. Other importers will follow the same profile-driven pattern.

---

## 3. Configuration & Inputs
### 3.1 Environment (.env)
Required variables:
- `LP_DIRECTOR_URL` — Director base URL.
- `LP_DIRECTOR_API_TOKEN` — API token (Bearer).
- `LP_TENANTS_FILE` — Path to `tenants.yml`.

### 3.2 Tenants file (tenants.yml)
Top-level keys: `tenants`, `defaults`.

- **Targets come from global defaults only**. Per-tenant overrides (`tenant.defaults.target`) are ignored (a warning is logged).
- Roles: `backends`, `search_heads`, `all_in_one`.
- For each CLI command, DirectorSync resolves target nodes from `defaults.target.<element>`.

**Sketch**
```yaml
tenants:
  core:
    pool_uuid: "..."
    siems:
      backends:     [{ id: "...", name: "BE-1" }]
      search_heads: [{ id: "...", name: "SH-1" }]
      all_in_one:   []

defaults:
  target:
    repos: ["backends"]
    routing_policies: ["backends"]
    normalization_policies: ["backends"]
    processing_policies: ["backends"]
    devices: ["backends"]
    device_groups: ["backends"]
    syslog_collectors: ["backends"]
    alerts: ["search_heads"]
```

### 3.3 Excel (XLSX) conventions
- Sheets and columns depend on the resource **profile**.
- Multi-value cells are supported via separators **`|`** or **`,`**.
- **All parsed cell values are normalized to string**. Numeric fields required by the API are cast back (e.g., retention days → integer) at payload-build time.
- Paths are normalized (trimmed) and may be post-processed by the profile (e.g., ensure trailing slash).

---

## 4. Common Trunk (Core Modules)
### 4.1 `core/director_client.py`
- JSON-first HTTP helpers: `get_json`, `post_json`, `put_json`, `delete_json`.
- Path builders: `configapi(pool_uuid, node_id, resource)`, `monitorapi(pool_uuid, node_id, job_id)`.
- Job monitor: `monitor_job(...)` polls `/monitorapi/.../orders/{job_id}` until success/failure or timeout.
- **Generic resource helpers**:
  - `list_resource(pool, node, resource)`
  - `list_subresource(pool, node, resource, subpath)`
  - `create_resource(pool, node, resource, payload, monitor=True)`
  - `update_resource(pool, node, resource, resource_id, payload, monitor=True)`
  - `delete_resource(pool, node, resource, resource_id, monitor=True)`

### 4.2 `core/config.py`
- Loads `.env` (required vars) and parses `tenants.yml`.
- Resolves target nodes from **global** `defaults.target.<element>` only (per-tenant target overrides are ignored with a warning).

### 4.3 `importers/base.py`
Orchestrates the standard pipeline:
1) Load Excel sheets
2) Validate required sheets/columns
3) Fetch existing objects from API
4) Diff desired vs existing → decision (`NOOP`, `CREATE`, `UPDATE`, `SKIP`)
5) Apply changes (unless dry-run)
6) Report (table/json)

### 4.4 Utility modules
- `diff_engine.py` — subset comparison and human-readable reasons.
- `validators.py` — sheet/column presence checks.
- `reporting.py` — compact CLI table and JSON output.
- `resolvers.py` — tiny per-node caches for lookups.

---

## 5. Resource Profiles (Declarative Behavior)
A **resource profile** defines—declaratively—how to parse XLSX, how to construct **documented** API payloads (POST/PUT), how to canonicalize GET responses for comparison, and which pre-flight verifications to run.

Profiles have **built-in defaults in code** (Python dict). An optional YAML file can override parts of a profile for environment-specific needs.

**Common profile sections**
- `xlsx`: sheet name, required columns, aliases, parsing (split/normalize/coerce), validations.
- `mapping`: XLSX→API field mapping, including list builders.
- `compare`: equality rules used for NOOP vs UPDATE (list-of-dicts compared unordered by key).
- `verify`: pre-flight checks (e.g., verifying repo paths exist on the node).

> **API whitelist**: Only fields **documented** for POST/PUT are sent. Extra fields returned by GET are **ignored** for payloads and for equality (unless explicitly included by the profile).

---

## 6. Module Reference — Repos (Canonical Example)
The **Repos** importer demonstrates the full profile-driven workflow. The only fields sent are those documented by the Director API 2.7 for POST/PUT.

### 6.1 Profile — Defaults (embedded)
```yaml
resource: "Repos"

xlsx:
  sheet: "Repo"
  columns:
    name:
      required: true
      aliases: ["cleaned_repo_name"]
      normalize: { strip: true }
    storage_paths:
      required: true
      split_on: ["|", ","]
      normalize:
        trim_each: true
        ensure_trailing_slash: true
    retention_days:
      required: true
      split_on: ["|", ","]
      normalize: { trim_each: true }
      validate: { same_length_as: "storage_paths" }
    repoha_li:
      required: false
      split_on: ["|", ","]
      normalize: { trim_each: true }
    repoha_day:
      required: false
      split_on: ["|", ","]
      normalize: { trim_each: true }

mapping:
  api_fields:
    post: ["name", "hiddenrepopath", "repoha"]
    put:  ["id", "hiddenrepopath", "repoha"]
  builders:
    hiddenrepopath:
      from: ["storage_paths", "retention_days"]
      op: "zip_list_of_dict"       # -> [{"path": <str>, "retention": <int>}]
      keys: ["path", "retention"]
    repoha:
      from: ["repoha_li", "repoha_day"]
      op: "zip_list_of_dict"       # -> [{"ha_li": <str>, "ha_day": <int>}]
      keys: ["ha_li", "ha_day"]

compare:
  eq_fields: ["hiddenrepopath", "repoha"]
  list_dict_unordered:
    hiddenrepopath: { key_fields: ["path"], value_fields: ["retention"] }
    repoha:         { key_fields: ["ha_li"], value_fields: ["ha_day"] }

verify:
  repo_paths:
    enabled: true
    source: "Repos/RepoPaths"
    list_field_candidates: ["0.paths", "paths"]   # tolerate list-of-dict or plain dict shapes
```

**Notes**
- **All parsed cell values are strings**. The builder casts numeric fields (e.g., `retention`, `ha_day`) to int for payloads because the API requires numeric types; they remain strings inside the Excel parsing layer.
- GET often returns `repopath` while POST/PUT expect `hiddenrepopath`. The importer canonicalizes GET → `{ name, hiddenrepopath, repoha }` for correct comparison.

### 6.2 XLSX → API mapping
| XLSX column        | Transform                                                | API field / shape                         |
|--------------------|----------------------------------------------------------|-------------------------------------------|
| `name` \| alias `cleaned_repo_name` | `strip()`                                             | `data.name` (string)                      |
| `storage_paths`    | split on `|`/`,` → trim → **ensure trailing '/'**        | `data.hiddenrepopath[*].path` (string)    |
| `retention_days`   | split on `|`/`,` → trim → **cast to int** (builder step) | `data.hiddenrepopath[*].retention` (int)  |
| `repoha_li`        | split on `|`/`,` → trim                                  | `data.repoha[*].ha_li` (string, optional) |
| `repoha_day`       | split on `|`/`,` → trim → **cast to int** (builder step) | `data.repoha[*].ha_day` (int, optional)   |

**Validation**
- `len(storage_paths) == len(retention_days)` is required; otherwise the row is rejected with a validation error.

### 6.3 Equality (NOOP vs UPDATE)
- Compare only `hiddenrepopath` and `repoha`.
- **Order-insensitive** on list-of-dicts: items are matched by key (`path` for `hiddenrepopath`, `ha_li` for `repoha`) and value differences (e.g., `retention`, `ha_day`) trigger UPDATE.

### 6.4 Pre-flight verification — RepoPaths
- The importer retrieves available repository paths from `configapi/.../Repos/RepoPaths`.
- Response shapes tolerated:
  - `[{ "paths": ["/a/", "/b/"] }]` **or** `{ "paths": ["/a/", "/b/"] }`.
- If any desired path is missing from the node’s RepoPaths list, the row is **SKIPPED**; the API itself enforces path integrity and refusing invalid payloads.

### 6.5 Payload examples (CREATE)
**Single path**
```json
{
  "data": {
    "name": "Repo_system_expert",
    "hiddenrepopath": [
      { "path": "/opt/immune/storage/", "retention": 365 }
    ]
  }
}
```

**Multiple paths (mixed separators)**
```json
{
  "data": {
    "name": "Repo_network",
    "hiddenrepopath": [
      { "path": "/data/net1/", "retention": 180 },
      { "path": "/data/net2/", "retention": 30 }
    ]
  }
}
```

**With HA replication (optional)**
```json
{
  "data": {
    "name": "Repo_ha_example",
    "hiddenrepopath": [
      { "path": "/mnt/prim/", "retention": 365 }
    ],
    "repoha": [
      { "ha_li": "10.10.10.21:5504", "ha_day": 3 },
      { "ha_li": "10.10.10.22:5504", "ha_day": 3 }
    ]
  }
}
```

### 6.6 Error handling
- Missing sheet/columns → validation error with the missing names.
- Mismatched list lengths (`storage_paths` vs `retention_days`) → validation error, row skipped.
- Missing RepoPaths on node → SKIP.
- HTTP 4xx/5xx → surfaced with code + message snippet (first 200 chars) in logs and result rows.

---

## 7. Adding a New Importer (Pattern)
1) **Define a profile** for the resource (built-in defaults). Include:
   - Required sheet and columns (+ aliases), split rules, coercions
   - XLSX→API mapping (whitelist `post`/`put`, list builders)
   - Equality rules (fields to compare; unordered list-of-dicts by key)
   - Pre-flight verifications (e.g., dependent resources, valid IDs)
2) **Implement a thin adapter** subclassing `BaseImporter`:
   - `iter_desired(...)` → parse/normalize rows per profile
   - `fetch_existing(...)` → list API objects and canonicalize per profile
   - `build_payload_create(...)` / `build_payload_update(...)` → apply mapping and filter to whitelisted fields
   - `apply(...)` → call `DirectorClient.create_resource`/`update_resource`
3) **Tests** for NOOP/CREATE/UPDATE, validation failures, and API error propagation.

---

## 8. CLI Usage (unchanged from v1)
```
python -m lp_tenant_importer_v2.main \
  --tenant core \
  --tenants-file ./tenants.yml \
  --xlsx ./samples/core_config.xlsx \
  --dry-run \
  import-repos --format table
```

Options (global): `--tenant`, `--tenants-file` (kept for compatibility; actual path comes from `.env`), `--xlsx`, `--dry-run`, `--no-verify`, `--format {table,json}`.

---

## 9. Quality, Testing & Packaging
- **Testing**: unit tests per importer + parity tests (compare v1 vs v2 dry-run stdout for same input files).
- **Logging**: levels `DEBUG/INFO/WARNING/ERROR`; secrets masked; concise, traceable messages.
- **Packaging**: build a Windows `.exe` with **auto-py-exe** using `lp_tenant_importer_v2/main.py` as the entry point.

---

## 10. Security & Secrets
- Store only the API token in `.env`.
- Do not log tokens or sensitive payload bodies.
- Allow toggling TLS verification via `--no-verify` for lab/test only.

---

## 11. Migration Notes (v1 → v2)
- Same CLI and inputs for end users.
- Per-tenant targets are ignored (warning) — only global `defaults.target` is used.
- Importer code is thinner; behavior is driven by resource profiles.

---

## 12. Glossary
- **Repo**: A storage repository with one or more `{path, retention}` pairs.
- **NP/RP/PP**: Normalization, Routing, Processing Policies.
- **BE/SH/AIO**: Backend, Search Head, All-in-One nodes.
- **NOOP**: No change required (desired = existing per profile equality rules).
- **SKIP**: Intentionally not applied due to validation or pre-flight failures.

---

## Appendix A — Repos Profile (Override Example)
> Optional YAML to override a subset of defaults (e.g., different separators or sheet name). Unspecified keys inherit built-ins.

```yaml
# file: resources/repos.yml
resource: "Repos"

xlsx:
  sheet: "Repository"   # use a different sheet name in your workbook
  columns:
    storage_paths:
      split_on: ["|"]   # remove comma as a valid separator

compare:
  # Include repoha equality only if your deployment uses it
  eq_fields: ["hiddenrepopath"]
```

## Appendix B — Repos Canonicalization (GET → compare)
- Map GET field `repopath` → canonical `hiddenrepopath` for comparison.
- Normalize paths (trim, trailing slash) before comparing.
- Ensure values are strings at parse time; cast numeric fields during payload build only.

