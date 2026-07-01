# DirectorSync v2 — Concept and Usage Guide

## 1. What is DirectorSync?

DirectorSync v2 is a two-stage migration toolkit for LogPoint SIEM environments managed by LogPoint Director.

- **Stage 1 — Export / Split** (`lp_tenant_exporter_v2`):  
  Reads a monolithic LogPoint configuration dump (JSON) and produces one Excel workbook per tenant. The workbooks are cleaned, normalized and ready for import.

- **Stage 2 — Import** (`lp_tenant_importer_v2`):  
  Reads a per-tenant Excel workbook and synchronizes the configuration into the target Director-managed SIEM nodes (backends, search heads) using the Config API.

## 2. High-level workflow

```
Source LogPoint
      │
      │  1. Obtain JSON configuration dump(s)
      ▼
lp_tenant_exporter_v2
      │
      ├── tools/getDistCollectorIDs.py  → derive collector → tenant mapping
      │
      └── splitter/logpoint_config_splitter.py  → one XLSX per tenant
              │
              ▼
      tenant_a_config.xlsx, tenant_b_config.xlsx, ...
              │
              ▼
lp_tenant_importer_v2
      │
      ├── .env (Director URL + API token)
      ├── tenants.yml (pool UUIDs, node IDs, target roles)
      └── python -m lp_tenant_importer_v2.main --tenant <name> --xlsx <file> import-<element>
              │
              ▼
      Director Config API
              │
              ▼
      target SIEM nodes
```

## 3. Prerequisites

- Python **>= 3.10** for the importer; the exporter also runs on 3.9+.
- Network access from the execution host to the LogPoint Director API.
- A LogPoint configuration dump from the source environment (obtained through LogPoint support or export procedures).
- Director API token with sufficient privileges for the target pools.

## 4. Installation

Create a virtual environment and install dependencies for each module:

```bash
# Exporter
python -m venv venv_exporter
source venv_exporter/bin/activate  # Windows: venv_exporter\Scripts\activate
pip install -r lp_tenant_exporter_v2/requirements.txt

# Importer
python -m venv venv_importer
source venv_importer/bin/activate
pip install -r lp_tenant_importer_v2/requirements.txt
```

## 5. Configuration

All environment-specific values must be recreated from the provided `.example` / `.sample` templates. Do **not** commit real tokens or IPs to version control.

### 5.1 Exporter configuration

Copy and edit the templates:

```bash
cp lp_tenant_exporter_v2/config/logpoint_config_splitter-config.json.example \
   lp_tenant_exporter_v2/config/logpoint_config_splitter-config.json

cp lp_tenant_exporter_v2/config/splitter.json.example \
   lp_tenant_exporter_v2/config/splitter.json
```

`logpoint_config_splitter-config.json` needs:

- `tenant_list`: list of tenant short names (e.g. `["tenant_a", "tenant_b"]`).
- `collector_to_tenant`: mapping of distributed-collector IDs to tenant names.
- `collector_field_column`, `collector_field_split_regex`, `collector_value_left_of_colon`: how to parse the collector column on devices.

Use `tools/getDistCollectorIDs.py` to derive an initial collector → tenant mapping from the source JSON.

### 5.2 Importer configuration

Copy and edit the templates:

```bash
cp lp_tenant_importer_v2/tenants.example.yml lp_tenant_importer_v2/tenants.yml
cp lp_tenant_importer_v2/.env.example lp_tenant_importer_v2/.env
```

`tenants.yml` defines, for each tenant:

- `pool_uuid`: the Director pool UUID where the tenant lives.
- `siems.search_heads[]`: search-head nodes (`id`, `name`, `ip`).
- `siems.backends[]`: backend nodes (`id`, `name`, `ip`, `ip_private`).
- `siems.all_in_one[]`: optional all-in-one nodes.
- `defaults.target.<element>`: which node roles each configuration element is pushed to (global only; tenant-level targets are ignored).

`.env` needs:

```env
LP_DIRECTOR_URL=https://director.example.com
LP_DIRECTOR_API_TOKEN=YOUR_API_TOKEN_HERE
LP_TENANTS_FILE=./lp_tenant_importer_v2/tenants.yml
```

## 6. Export / split usage

### 6.1 Derive collector mapping

```bash
python lp_tenant_exporter_v2/tools/getDistCollectorIDs.py \
  lp_tenant_exporter_v2/data/sync_config_ESA.json \
  --tenants tenant_a,tenant_b,tenant_c \
  --out lp_tenant_exporter_v2/config
```

Review the generated Markdown summaries and copy the mapping into `config/logpoint_config_splitter-config.json`.

### 6.2 Run the splitter

```bash
python lp_tenant_exporter_v2/splitter/logpoint_config_splitter.py \
  --input lp_tenant_exporter_v2/data/sync_config_ESA.json \
  --config-dir lp_tenant_exporter_v2/config \
  --output-dir lp_tenant_exporter_v2/split/tenants \
  --input-sh lp_tenant_exporter_v2/data/alerts_SH.json
```

Output: one Excel workbook per tenant in `--output-dir`.

Optional enrichment post-processing:

```bash
python lp_tenant_exporter_v2/tools/enrichment_postprocess.py \
  --dir lp_tenant_exporter_v2/split/tenants
```

## 7. Import usage

The importer exposes one subcommand per configuration element. Run from the repository root so the package is importable.

### 7.1 Dry-run a single element

```bash
python -m lp_tenant_importer_v2.main \
  --tenant tenant_a \
  --xlsx lp_tenant_importer_v2/samples/tenant_a_config.xlsx \
  --dry-run \
  import-repos
```

### 7.2 Apply a single element

```bash
python -m lp_tenant_importer_v2.main \
  --tenant tenant_a \
  --xlsx lp_tenant_importer_v2/samples/tenant_a_config.xlsx \
  import-repos
```

### 7.3 Available import subcommands

- `import-repos`
- `import-routing-policies`
- `import-normalization-policies`
- `import-enrichment-policies`
- `import-processing-policies`
- `import-device-groups`
- `import-devices`
- `import-syslog-collectors`
- `import-alert-rules`
- `import-user-lists`
- `list-alert-users` (report only)

Use `--help` on any subcommand for options (`--no-verify`, `--format table|json`, etc.).

### 7.4 Import order recommendation

Dependencies matter. A typical order is:

1. `import-repos`
2. `import-routing-policies`
3. `import-normalization-policies`
4. `import-enrichment-policies`
5. `import-processing-policies`
6. `import-device-groups`
7. `import-devices`
8. `import-syslog-collectors`
9. `import-user-lists`
10. `import-alert-rules`

## 9. Idempotency and diff engine

The importer is designed to be safe to re-run:

1. Load the Excel workbook and validate required sheets/columns.
2. Fetch existing resources from each target node.
3. Compare desired state (Excel) with existing state (API).
4. Decide: `CREATE`, `UPDATE`, `NOOP`, or `SKIP`.
5. Apply changes and poll the Director monitor API until completion.
6. Render a report.

Always start with `--dry-run` on a new tenant or element.

## 10. Security and operational notes

- Keep `.env`, `tenants.yml` and all exported `.xlsx` files confidential.
- Do not share source JSON dumps or split workbooks outside the target environment.
- Rotate the Director API token after the migration if it was shared with operators.
- Run first on a non-production tenant or pool to validate the end-to-end flow.

## 11. Getting help

Refer to the detailed design documents under:

- `lp_tenant_importer_v2/docs/`
- `lp_tenant_exporter_v2/docs/`
- `lp_tenant_exporter_v2/splitter/README_splitter.md`
