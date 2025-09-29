# Developer Guide — DirectorSync (v2, Common Trunk) — updated

> Status: **Updated – 29 Sep 2025**. This revision reflects the modules migrated to the v2 common trunk and adds **Enrichment Policies** with their API/validation rules.
> Audience: Developers building, extending, or operating the DirectorSync importer tool.

---

## 1. Overview

DirectorSync is a command-line tool that synchronizes configuration data ("resources") into Logpoint Director via its HTTP APIs. The v2 refactor preserves the **same end-user CLI and inputs** as v1 while moving shared plumbing into a **common trunk** for maintainability and faster feature work.

**Key goals**

- Eliminate redundancy across importers (Repos, Routing Policies, Normalization Policies, **Enrichment Policies**).
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
│  ├─ normalization_policies.py# migrated (CSV payload semantics)
│  └─ enrichment_policies.py   # **migrated in this update**
└─ utils/
   ├─ __init__.py
   ├─ diff_engine.py           # NOOP/CREATE/UPDATE/SKIP decision helper
   ├─ validators.py            # XLSX sheet/column validation
   ├─ resolvers.py             # simple per-node caches for lookups
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
    enrichment_policies: ["backends"]
```

### 3.3 Excel (XLSX) conventions

- Sheets and columns depend on the resource **profile**.
- Multi-value cells are supported via separators **`|`** or **`,`**.
- **All parsed cell values are strings**. Numeric fields required by the API are cast by builders at payload time.

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

## 5. Migrated Modules — Quick Reference (updated)

| Resource                   | XLSX Sheets                                     | CLI Command                      | Targets (default) | Payload Contract (POST/PUT)                                                                                 | Special Notes |
|---------------------------|--------------------------------------------------|----------------------------------|-------------------|--------------------------------------------------------------------------------------------------------------|---------------|
| **Repos**                 | `Repo`                                          | `import-repos`                   | `backends`        | `name`, `hiddenrepopath:[{path,retention}]`, optional `repoha:[{ha_li,ha_day}]`                              | Pre-flight **RepoPaths** check; list-of-dicts compared **order-insensitively** by key. |
| **Routing Policies**      | `RoutingPolicy`                                 | `import-routing-policies`        | `backends`        | `policy_name`, `routing_criteria:[{type,key,value,repo,drop}]`, `catch_all`, `active`                       | Repo **names→IDs** lookups (criteria & `catch_all`); group rows by policy. |
| **Normalization Policies**| `NormalizationPolicy`                           | `import-normalization-policies`  | `backends`        | **CSV strings**: `norm_packages:"ID1,ID2"`, `compiled_normalizer:"C1,C2"`; `name` on POST                | **CSV required** by API (not arrays). Packages are **name→ID**; compiled must exist on node. |
| **Enrichment Policies**   | `EnrichmentPolicy`, `EnrichmentRules`, `EnrichmentCriteria` | `import-enrichment-policies`      | `backends`        | Envelope **`{"data": { name, specifications, [description] }}`**; PUT accepts same body shape as POST      | **Aggregate by `source`**; strict **SKIP** if **any spec has empty rules** or **any `source` missing on node**; inventory via **`GET …/EnrichmentSource`** and exact match on **`source_name`**. |

---

## 6. Enrichment Policies (details)

**Aggregation (V1‑compatible):** one specification per `source`. We union & deduplicate `rules` and `criteria` across all rows for a given `(policy_name, source)`.

**Pre-flight checks (hard SKIPs):**
- **Missing `source_name` on node**: Inventory comes **only** from `GET /configapi/{pool}/{node}/EnrichmentSource` and we match exactly on `source_name` (case‑sensitive). If any required source is absent → **SKIP** the policy.
- **Empty rules in any specification**: If after aggregation a specification ends up with `rules = []`, the **entire policy is SKIPPED**. Operators must fix the spreadsheet.

**Validation:**
- Each specification must have **≥ 1 criteria** (empty `value` allowed).
- Rule fields respected: `category` (`simple` or `type_based`); `operation` defaults to `Equals`; when `category=simple` → `event_key` required; when `type_based` → `type` required; boolean `prefix` coerced to bool.

**Diff & Apply:**
- Comparison limited to `specifications` (optionally include `description` if required by your process). Lists are order‑insensitive.
- `POST/PUT /EnrichmentPolicy` with **`{"data": payload}`**. If a job id or monitor URL is returned, we poll; otherwise we infer success from response `status/message` and surface any error text.

---

## 7. CLI Usage (unchanged)

```bash
# Enrichment Policies
python -m lp_tenant_importer_v2.main \
  --tenant core \
  --tenants-file ./tenants.yml \
  --xlsx ./samples/core_config.xlsx \
  import-enrichment-policies --format table
```

Global flags: `--dry-run`, `--no-verify`, `--format {table,json}`.

---

## 8. Quality, Testing & Packaging

- **Idempotence**: re-running with identical inputs yields **NOOP** everywhere.
- **Unit tests**: per importer (diff logic, lookups, payload builders). Parity tests (v1 vs v2 dry-run) recommended.
- **Logging**: `DEBUG/INFO/WARNING/ERROR`; tokens masked; concise error surfacing. Enrichment Policies log aggregated `sources` with counts per policy.
- **Packaging**: Windows `.exe` using **auto-py-exe** (`lp_tenant_importer_v2/main.py` entry point).

---

## 9. Migration Notes (v1 → v2)

- Same CLI and inputs for end users.
- Only **global** `defaults.target` is honored for selecting nodes.
- Importers are thinner; behavior is profile-driven. **Normalization Policies** use **CSV fields**; **Enrichment Policies** introduce strict SKIP rules and source inventory via the `EnrichmentSource` list endpoint.

---

## 10. Glossary

- **Repo**: Storage repository with one or more `{path, retention}` pairs.
- **EP/RP/NP/PP**: Enrichment, Routing, Normalization, Processing Policies.
- **BE/SH/AIO**: Backend, Search Head, All-in-One nodes.
- **NOOP**: No change required.
- **SKIP**: Not applied due to validation/pre-flight failures.

