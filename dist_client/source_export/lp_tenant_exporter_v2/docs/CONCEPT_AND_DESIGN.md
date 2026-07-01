# LogPoint Configuration Exporter — Concept and Design

This document describes the concept, design and implementation of `lp_tenant_exporter_v2`, the first stage of DirectorSync. It reads a monolithic LogPoint configuration dump and produces one sanitized Excel workbook per tenant.

---

## 1. Purpose

In a multi-tenant LogPoint Director / Fleet deployment, the source environment is often exported as a single JSON file containing the configuration of all tenants. Before importing this configuration into the target Director, it must be:

- **split** into per-tenant views,
- **cleaned** of customer-specific suffixes and noise,
- **normalized** into a spreadsheet format that the importer can consume.

The exporter performs this transformation offline. It does not call the Director API; it only reads JSON dumps and writes Excel workbooks.

---

## 2. High-level workflow

```text
Source LogPoint
      │
      │  Obtain backend JSON dump (Sync.* entities)
      │  Optionally obtain Search-Head JSON dump (alerts, user lists)
      ▼
lp_tenant_exporter_v2
      │
      ├── tools/getDistCollectorIDs.py  → derive collector → tenant mapping
      │
      ├── config/logpoint_config_splitter-config.json  → tenant list + mapping
      │
      └── splitter/logpoint_config_splitter.py  → one XLSX per tenant
              │
              ▼
      tenant_a_config.xlsx, tenant_b_config.xlsx, ...
              │
              ▼
lp_tenant_importer_v2
```

---

## 3. Components

| Component | File | Role |
|---|---|---|
| **Core splitter** | `splitter/logpoint_config_splitter.py` | Reads the JSON dump, extracts entities, assigns rows to tenants and writes XLSX workbooks. |
| **CLI wrapper** | `splitter/split_cli.py` | Template-driven wrapper that invokes the core splitter using a JSON command template. |
| **Device resolver** | `splitter/device_tenant_resolver.py` | Assigns devices to tenants using collector mapping, with a name-based fallback. |
| **Alert export** | `splitter/alert_export.py` | Loads alerts and user-defined lists from a Search-Head JSON dump and routes them to tenants by repo. |
| **Collector mapper** | `tools/getDistCollectorIDs.py` | Derives a `collector_id → tenant` mapping from the backend JSON using majority rule on device names. |
| **Entity mapping** | `config/mapping.yaml` | Declares the sheets, columns and metadata used for each entity type. |

---

## 4. Configuration

The exporter is driven by two configuration files:

### 4.1 `config/logpoint_config_splitter-config.json`

Created from `logpoint_config_splitter-config.json.example`, it contains:

- `tenant_list`: list of tenant short names (e.g. `["tenant_a", "tenant_b"]`).
- `collector_to_tenant`: mapping of distributed-collector IDs to tenant names.
- `collector_field_column`: the column holding collector IDs on devices (default: `distributed_collector`).
- `collector_field_split_regex`: regex used to split multiple collector IDs in one cell (default: `[,;|\s]+`).
- `collector_value_left_of_colon`: if `true`, keeps only the left part of `uuid:label` values.

Use `tools/getDistCollectorIDs.py` to derive an initial `collector_to_tenant` mapping from the backend JSON.

### 4.2 `config/splitter.json`

Used by `split_cli.py`, it contains a `cmd` template with placeholders such as `{python}`, `{script}`, `{input}`, `{input_sh}`, `{config_dir}` and `{out_dir}`.

---

## 5. Entity extraction and tenant assignment

The core splitter parses the backend JSON dump and extracts entities into Pandas DataFrames. Supported entities include:

- `Repo`
- `RoutingPolicy`
- `ProcessingPolicy`
- `NormalizationPolicy`
- `EnrichmentPolicy`, `EnrichmentRules`, `EnrichmentCriteria`
- `Device`, `DeviceFetcher`
- `DeviceGroup`
- `UserDefinedList`

### 5.1 Tenant assignment rules

Each entity row is assigned to one or more tenants using the following logic:

1. **Devices** are assigned by `distributed_collector` first. If a device has no collector or the collector maps to multiple tenants, a name-based fallback is used. Unassigned devices are reported separately.
2. **Repos** are matched by tenant name appearing in the repo name.
3. **Policies** are matched by tenant name appearing in the policy name.
4. **DeviceGroups** are exported fully (multitenant) and filtered later by the importer if needed.

### 5.2 Cleaning and normalization

- Tenant suffixes are removed from names.
- Multi-valued cells are kept as CSV or JSON-encoded strings, depending on the target sheet.
- Column names are mapped to the importer contract declared in `config/mapping.yaml`.

---

## 6. Alerts and Search-Head data

Alerts and user-defined lists are usually exported from a dedicated Search-Head JSON dump. The exporter:

1. Loads the Search-Head dump via `splitter/alert_export.py`.
2. Flattens alert objects into dotted columns.
3. Routes each alert to tenants based on `settings.repos`:
   - Empty or missing repos → all tenants.
   - `host:port` without repo name → all tenants (shared backend).
   - `host:port/repo_name` → mapped to the tenant that owns the repo.

---

## 7. Output format

For each tenant, the exporter writes one Excel workbook named `{tenant}_config.xlsx` containing one sheet per entity, for example:

- `Repo`
- `RoutingPolicy`
- `ProcessingPolicy`
- `NormalizationPolicy`
- `EnrichmentPolicy`
- `Device`
- `DeviceGroup`
- `Alert`
- `UserDefinedList`

These workbooks are the direct input of `lp_tenant_importer_v2`.

---

## 8. Running the exporter

### Direct execution

```bash
python -m lp_tenant_exporter_v2.splitter.logpoint_config_splitter \
  --input lp_tenant_exporter_v2/data/sync_config_ESA.json \
  --config-dir lp_tenant_exporter_v2/config \
  --output-dir lp_tenant_exporter_v2/split/tenants \
  --input-sh lp_tenant_exporter_v2/data/alerts_SH.json
```

### Template-driven execution

```bash
python -m lp_tenant_exporter_v2.splitter.split_cli \
  --input lp_tenant_exporter_v2/data/sync_config_ESA.json \
  --out-dir lp_tenant_exporter_v2/split/tenants \
  --template lp_tenant_exporter_v2/config/splitter.json \
  --config-dir lp_tenant_exporter_v2/config \
  --input-sh lp_tenant_exporter_v2/data/alerts_SH.json
```

See `splitter/README_splitter.md` for more details.

---

## 9. Integration with the importer

The output workbooks are consumed by `lp_tenant_importer_v2`:

```bash
python -m lp_tenant_importer_v2.main \
  --tenant tenant_a \
  --tenants-file lp_tenant_importer_v2/tenants.yml \
  --xlsx lp_tenant_exporter_v2/split/tenants/tenant_a/tenant_a_config.xlsx \
  --dry-run \
  import-repos
```

See `lp_tenant_importer_v2/docs/running_the_importer.md` for the full importer workflow.

---

## 10. Design principles

- **Offline only:** the exporter never calls an API.
- **Deterministic:** the same input JSON and configuration always produce the same output workbooks.
- **Configurable:** tenant detection, collector parsing and entity mapping are driven by configuration files.
- **Safe:** the exporter preserves the raw input; it only creates new XLSX files in the output directory.
