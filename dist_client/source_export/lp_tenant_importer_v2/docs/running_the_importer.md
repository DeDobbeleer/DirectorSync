# Running the Importer

This guide explains how to run the `lp_tenant_importer_v2` importer from source.

## Running from the project root (recommended)

The simplest way is to run from the repository root so Python can find the `lp_tenant_importer_v2` package:

```bash
cd ~/dev/DirectorSync
source venv_importer/bin/activate
python -m lp_tenant_importer_v2.main \
  --tenant core \
  --tenants-file ./lp_tenant_importer_v2/tenants.yml \
  --xlsx ./lp_tenant_importer_v2/samples/core_config.xlsx \
  --dry-run \
  import-repos
```

## Running from inside `lp_tenant_importer_v2/`

If you prefer to work inside the importer directory, add the parent directory to `PYTHONPATH`:

```bash
cd ~/dev/DirectorSync/lp_tenant_importer_v2
export PYTHONPATH=..
source ../venv_importer/bin/activate
python -m lp_tenant_importer_v2.main \
  --tenant core \
  --tenants-file ../tenants.yml \
  --xlsx samples/core_config.xlsx \
  --dry-run \
  import-repos
```

Quick sanity check:

```bash
export PYTHONPATH=..
python -c "import lp_tenant_importer_v2; print('OK:', lp_tenant_importer_v2.__file__)"
```

## Available subcommands

- `import-repos`
- `import-routing-policies`
- `import-normalization-policies`
- `import-enrichment-policies`
- `import-processing-policies`
- `import-device-groups`
- `import-devices`
- `import-syslog-collectors`
- `import-alert-rules`
- `import-user-defined-lists`
- `list-alert-users`

## Building and running the Windows executable

The repository includes a PyInstaller spec file that builds `dist/LPImporter.exe`:

```bash
pyinstaller lp_tenant_importer_v2/build.spec --clean
```

Run the executable from the distribution folder:

```powershell
.\dist\LPImporter.exe --tenant core --xlsx .\lp_tenant_importer_v2\samples\core_config.xlsx import-repos
```

> Note: older documentation referred to the executable as `directorSync.exe` and used `--additional-hooks-dir hooks-importer`. The current canonical build is `LPImporter` via `build.spec` with hooks in `hooks/`.

## Running the exporter splitter

The splitter is run directly from Python (no build required):

```bash
python -m lp_tenant_exporter_v2.splitter.split_cli \
  --input data/sync_config_ESA.json \
  --input-sh data/alerts_with_ESA_original_repos.json \
  --output-dir split \
  --config-dir config
```

## Tips

- Always start with `--dry-run` on a new tenant or resource type.
- Use absolute paths in `.env` for `LP_TENANTS_FILE` and `LP_PROFILE_FILE` to avoid working-directory issues.
- On Windows, use `venv_importer\Scripts\activate` instead of `source venv_importer/bin/activate`.
