# DirectorSync Migration Source — Handover Package

This archive contains the source code for the LogPoint migration tooling used during the customer engagement:

- `lp_tenant_exporter_v2/` — LogPoint configuration splitter / transformer.
- `lp_tenant_importer_v2/` — LogPoint Director API importer.

## What has been removed

All customer-specific data, credentials and runtime artifacts have been stripped:

- JSON dumps and Excel workbooks (`.json`, `.xlsx`, `.xls`, `.csv`).
- Environment files (`.env`, `.env.*`).
- Tenant topology files (`tenants.yml`, `pools.json`).
- Log files and `__pycache__` directories.
- Lock files and other temporary artifacts.

## What you must recreate

Before the tools can run in a new environment, create real configuration files from the provided `.example` / `.sample` templates:

| Template | Copy to | Purpose |
|---|---|---|
| `lp_tenant_exporter_v2/config/logpoint_config_splitter-config.json.example` | `lp_tenant_exporter_v2/config/logpoint_config_splitter-config.json` | Tenant list and collector → tenant mapping. |
| `lp_tenant_exporter_v2/config/splitter.json.example` | `lp_tenant_exporter_v2/config/splitter.json` | CLI template for `split_cli.py`. |
| `lp_tenant_importer_v2/tenants.example.yml` | `lp_tenant_importer_v2/tenants.yml` | Pool UUIDs and node topology per tenant. |
| `lp_tenant_importer_v2/.env.example` | `lp_tenant_importer_v2/.env` | Director URL and API token. |

See `CONCEPT_AND_USAGE_GUIDE.md` for the full workflow, prerequisites and command reference.

See `TOOLS_AND_IDE_RECOMMENDATIONS.md` for a recommended toolkit (IDE, API clients, data helpers, monitoring) to operate and maintain the Director/Fleet/SIEM estate.
