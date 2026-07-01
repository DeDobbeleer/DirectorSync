# LogPoint Configuration Splitter

This directory contains the LogPoint configuration splitter used during migration.

## Files

- `logpoint_config_splitter.py` — core splitter. Reads a LogPoint JSON dump and writes one Excel workbook per tenant.
- `split_cli.py` — template-driven wrapper that reads `config/splitter.json` and invokes the core splitter.
- `device_tenant_resolver.py` — helper to assign devices to tenants based on collector mapping.
- `alert_export.py` — helpers to load alerts and user lists from a Search-Head JSON dump.

## Running the splitter directly

```bash
python lp_tenant_exporter_v2/splitter/logpoint_config_splitter.py \
  --input lp_tenant_exporter_v2/data/sync_config_ESA.json \
  --config-dir lp_tenant_exporter_v2/config \
  --output-dir lp_tenant_exporter_v2/split/tenants \
  --input-sh lp_tenant_exporter_v2/data/alerts_SH.json
```

Arguments:

- `--input` (required): path to the source LogPoint JSON dump.
- `--config-dir` (default: `.`): directory containing `logpoint_config_splitter-config.json`.
- `--output-dir` (default: `tenants_output`): directory where the per-tenant XLSX files are written.
- `--input-sh` (optional): path to a Search-Head JSON dump for alerts and user-defined lists.

## Running via the template wrapper

```bash
python lp_tenant_exporter_v2/splitter/split_cli.py \
  --input lp_tenant_exporter_v2/data/sync_config_ESA.json \
  --out-dir lp_tenant_exporter_v2/split/tenants \
  --template lp_tenant_exporter_v2/config/splitter.json \
  --config-dir lp_tenant_exporter_v2/config \
  --input-sh lp_tenant_exporter_v2/data/alerts_SH.json
```

Wrapper-specific arguments:

- `--input`: source JSON dump.
- `--out-dir`: output directory.
- `--template`: path to the JSON command template.
- `--config-dir`: configuration directory passed to the core splitter.
- `--input-sh`: Search-Head JSON dump passed to the core splitter.
- `--python`: Python interpreter to use (default: current interpreter).
- `--script`: core splitter script to invoke (default: `logpoint_config_splitter.py` in the same directory).

The template file (`config/splitter.json`) must contain a `cmd` string with optional placeholders such as `{python}`, `{script}`, `{input}`, `{input_sh}`, `{config_dir}`, and `{out_dir}`.

Example template:

```json
{
  "cmd": "\"{python}\" \"{script}\" --input \"{input}\" --input-sh \"{input_sh}\" --config-dir \"{config_dir}\" --output-dir \"{out_dir}\""
}
```

## Output

One Excel workbook per tenant, containing entity-specific sheets such as `Repo`, `RoutingPolicy`, `NormalizationPolicy`, `ProcessingPolicy`, `Device`, `DeviceFetcher`, `DeviceGroups`, `Alert`, `UserDefinedList`, etc.
