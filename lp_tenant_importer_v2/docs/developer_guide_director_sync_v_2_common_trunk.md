# Developer Guide — DirectorSync (v2, Common Trunk)

> Status: **Updated – 29 Sep 2025**. This revision reflects the modules already migrated to the v2 common trunk and clarifies API payload contracts (notably **Normalization Policies CSV fields**).
> Audience: Developers building, extending, or operating the DirectorSync importer tool.

---

## 1. Overview

DirectorSync is a command-line tool that synchronizes configuration data ("resources") into Logpoint Director via its HTTP APIs. The v2 refactor preserves the **same end-user CLI and inputs** as v1 while moving shared plumbing into a **common trunk** for maintainability and faster feature work.

**Key goals**

- Eliminate redundancy across importers (Repos, Routing Policies, Normalization Policies, …).
- Keep the CLI and input files identical for users.
- Provide strong logging, validation, and a clear decision model (**NOOP / CREATE / UPDATE / SKIP**).
- Make importer behavior **declarative** via **resource profiles** (built-in defaults + optional YAML overrides).

---

## 2. Repository Structure (v2)

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
│  ├─ repos.py                 # migrated
│  ├─ routing_policies.py      # migrated
│  └─ normalization_policies.py# migrated (CSV payload semantics)
└─ utils/
   ├─ __init__.py
   ├─ diff_engine.py           # NOOP/CREATE/UPDATE/SKIP decision helper
   ├─ validators.py            # XLSX sheet/column validation
   ├─ resolvers.py             # simple in-memory caches for lookups
   └─ reporting.py             # uniform table/json output
```

> Other importers (Processing Policies, Devices, Device Groups, Syslog Collectors, Alerts) will follow the same profile-driven pattern.

---

## 3. Configuration & Inputs

### 3.1 Environment (.env)

Required variables:

- `LP_DIRECTOR_URL` — Director base URL.
- `LP_DIRECTOR_API_TOKEN` — API token (Bearer).
- `LP_TENANTS_FILE` — Path to `tenants.yml`.

### 3.2 Tenants file (tenants.yml)

- **Targets come from global defaults only**. Per-tenant overrides (`tenant.defaults.target`) are ignored (warning is logged).
- Roles: `backends`, `search_heads`, `all_in_one`.
- For each CLI command, DirectorSync resolves target nodes from `defaults.target.<element>`.

**Typical mapping**

```yaml
defaults:
  target:
    repos: ["backends"]
    routing_policies: ["backends"]
    normalization_policies: ["backends"]
    # others to be added as they are migrated
```

### 3.3 Excel (XLSX) conventions

- Sheets and columns depend on the resource **profile**.
- Multi-value cells are supported via separators **`|`** or **`,`**.
- **All parsed cell values are strings**. Numeric fields required by the API are cast (when needed) by builders at payload time.

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

- Loads `.env` and parses `tenants.yml`.
- Resolves target nodes from **global** `defaults.target.<element>` only.

### 4.3 `importers/base.py`

Standard pipeline:

1. Load Excel sheets
2. Validate required sheets/columns
3. Fetch existing objects from API
4. Diff desired vs existing → decision (`NOOP`, `CREATE`, `UPDATE`, `SKIP`)
5. Apply changes (unless dry-run)
6. Report (table/json), honoring monitor results where applicable

### 4.4 Utilities

- `diff_engine.py` — subset comparison and human-readable reasons.
- `validators.py` — sheet/column presence checks.
- `reporting.py` — compact CLI table and JSON output.
- `resolvers.py` — tiny per-node caches for lookups.

---

## 5. Migrated Modules — Quick Reference

| Resource                   | XLSX Sheet             | CLI Command                      | Targets (default) | Payload Contract (POST/PUT)                                                                  | Special Notes |
|---------------------------|------------------------|----------------------------------|-------------------|-----------------------------------------------------------------------------------------------|---------------|
| **Repos**                 | `Repo`                 | `import-repos`                   | `backends`        | `name`, `hiddenrepopath:[{path,retention}]`, optional `repoha:[{ha_li,ha_day}]`               | Pre-flight **RepoPaths** check; list-of-dicts compared **order-insensitively** by key. |
| **Routing Policies**      | `RoutingPolicy`        | `import-routing-policies`        | `backends`        | `policy_name`, `routing_criteria:[{type,key,value,repo,drop}]`, `catch_all`, `active`        | Repo **names→IDs** lookups (criteria & `catch_all`); group rows by policy. |
| **Normalization Policies**| `NormalizationPolicy`  | `import-normalization-policies`  | `backends`        | **CSV strings**: `norm_packages:"ID1,ID2"`, `compiled_normalizer:"C1,C2"`; `name` on POST | **CSV required** by API (not arrays). Packages are **name→ID**; compiled must exist on node. |

> Equality rules: defined per importer; generally, lists are compared without order using key fields, while scalar fields are direct-equality.

---

## 6. Module Details

### 6.1 Repos (canonical example)

- **Parsing**: `storage_paths` and `retention_days` are paired 1:1; optional HA pairs `repoha_li`/`repoha_day`.
- **Verification**: desired paths must be present in `Repos/RepoPaths` on the node.
- **Comparison**: `hiddenrepopath` and `repoha` lists are compared **order-insensitively**.
- **Payload**: list-of-dicts per API contract; numeric values cast appropriately by builders.

### 6.2 Routing Policies

- **Parsing**: group rows by `cleaned_policy_name` (or `policy_name` alias). Multi-value columns (`rule_type`,`key`,`value`,`repo`,`drop`) are zipped into `routing_criteria`.
- **Lookups**: repo names resolved to IDs (per-node cache) for both `catch_all` and each criterion.
- **Comparison**: `routing_criteria` compared without order; keys = `{type,key,value,repo}`; `drop` compared as value; also compare `active` and `catch_all`.
- **Payload**: only documented fields; monitor polled when present.

### 6.3 Normalization Policies

- **Parsing**: `policy_name`, `normalization_packages` (names), `compiled_normalizer` (names). Empty both → **SKIP**.
- **Dependencies**: preload `NormalizationPackage` (name↔id) and `CompiledNormalizers` sets per node; missing items → **SKIP** with reason.
- **Comparison**: compare **by names** (sorted) for both fields.
- **Payload**: **CSV strings** (not lists):
  - POST: `{ name, norm_packages:"ID1,ID2" | "", compiled_normalizer:"C1,C2" | "" }`
  - PUT: `{ norm_packages:"ID1,ID2" | "", compiled_normalizer:"C1,C2" | "" }`

---

## 7. CLI Usage (unchanged from v1)

```bash
# Repos
python -m lp_tenant_importer_v2.main   --tenant core   --tenants-file ./tenants.yml   --xlsx ./samples/core_config.xlsx   import-repos --format table
```

```bash
# Routing Policies
python -m lp_tenant_importer_v2.main   --tenant core   --tenants-file ./tenants.yml   --xlsx ./samples/core_config.xlsx   import-routing-policies --format table
```

```bash
# Normalization Policies
python -m lp_tenant_importer_v2.main   --tenant core   --tenants-file ./tenants.yml   --xlsx ./samples/core_config.xlsx   import-normalization-policies --format table
```

Global flags: `--dry-run`, `--no-verify`, `--format {table,json}`. The final `status` column honors monitor results when present.

---

## 8. Quality, Testing & Packaging

- **Idempotence**: re-running with identical inputs yields **NOOP** everywhere.
- **Unit tests**: per importer (diff logic, lookups, payload builders). Parity tests (v1 vs v2 dry-run) recommended.
- **Logging**: `DEBUG/INFO/WARNING/ERROR`; tokens masked; concise error surfacing.
- **Packaging**: Windows `.exe` using **auto-py-exe** (`lp_tenant_importer_v2/main.py` entry point).

---

## 9. Migration Notes (v1 → v2)

- Same CLI and inputs for end users.
- Only **global** `defaults.target` is honored for selecting nodes.
- Importers are thinner; behavior is profile-driven. **Normalization Policies** now explicitly use **CSV fields** per API requirement.

---

## 10. Glossary

- **Repo**: Storage repository with one or more `{path, retention}` pairs.
- **RP/NP/PP**: Routing, Normalization, Processing Policies.
- **BE/SH/AIO**: Backend, Search Head, All-in-One nodes.
- **NOOP**: No change required.
- **SKIP**: Not applied due to validation/pre-flight failures.
