# DirectorSync — lp_tenant_importer_v2

A simplified, maintainable, and extensible refactor of the Logpoint Director importer.
It preserves **exactly the same CLI** and **input files** as v1 for the end user,
but moves all shared logic into a **common trunk** to eliminate redundancy.

## Highlights
- Unified `DirectorClient` (JSON-first) with built-in **monitor** for `/monitorapi/*` jobs and token masking in logs.
- `BaseImporter` orchestrates: **load → validate → fetch existing → diff → plan → apply → report**.
- `DiffEngine` provides consistent `NOOP/CREATE/UPDATE/SKIP` decisions with reasons.
- Centralized **validation**, **resolvers** (name→id with caching), and **reporting** (table/json).
- **Strict compatibility**: same `.env`, same `tenants.yml` schema, same commands/flags.
- **Global targets only**: ignores `tenant.defaults.target[...]` (warns and proceeds).

## Quickstart (same as v1)
```bash
python -m lp_tenant_importer_v2.main   --tenant core   --tenants-file ./tenants.yml   --xlsx ./samples/core_config.xlsx   import-repos --format table
```

## Build `.exe` with auto-py-exe
- Script: `lp_tenant_importer_v2/main.py` (Console Based)
- Additional files: `.env` and your `tenants.yml`
- No hidden imports needed.
