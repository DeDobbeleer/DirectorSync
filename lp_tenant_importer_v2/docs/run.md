Tu as ce message parce que tu exécutes depuis **`lp_tenant_importer_v2/`** et, dans ce cas, Python **ne voit pas** le package `lp_tenant_importer_v2` (le parent n’est pas sur `sys.path`). Deux façons pro de régler ça :

## Option A — Lancer depuis la racine du repo (le plus simple)

```bash
cd ~/dev/DirectorSync
source lp_tenant_importer_v2/.venv/bin/activate
git pull origin main
python -m lp_tenant_importer_v2.main \
  --tenant core \
  --tenants-file ./tenants.yml \
  --xlsx ./lp_tenant_importer_v2/samples/core_config.xlsx \
  --dry-run \
  --no-verify \
  import-repos
```

## Option B — Rester dans `lp_tenant_importer_v2/` mais ajouter le parent au PYTHONPATH

- import-repos
- import-routing-policies
- import-normalization-policies
- import-enrichment-policies
- import-processing-policies
- import-device-groups
- import-devices
- import-syslog-collectors
- import-alert-rules
- list-alert-users
- import-user-lists
  
```bash
cd ~/dev/DirectorSync/lp_tenant_importer_v2
export PYTHONPATH=..
cd ~/dev/DirectorSync
source lp_tenant_importer_v2/.venv/bin/activate
git pull origin main
cd lp_tenant_importer_v2
python -m lp_tenant_importer_v2.main \
  --tenant core \
  --tenants-file ../tenants.yml \
  --xlsx samples/core_config.xlsx \
  --dry-run \
  --no-verify \
  import-alert-rules
```

```bash
cd ~/dev/DirectorSync/lp_tenant_importer_v2
export PYTHONPATH=..
cd ~/dev/DirectorSync
source lp_tenant_importer_v2/.venv/bin/activate
git pull origin main
cd lp_tenant_importer_v2
python -m lp_tenant_importer_v2.main \
  --tenant core \
  --tenants-file ../tenants.yml \
  --xlsx samples/core_config.xlsx \
  import-alert-rules
```

## Compilation for `.exe` and run from `dist/`

The repository ships a PyInstaller spec file that produces `dist/LPImporter.exe`:

```bash
pyinstaller build.spec --clean
```

Run the generated executable from the distribution folder:

```powershell
.\dist\LPImporter.exe --tenant core --xlsx .\lp_tenant_importer_v2\samples\core_config.xlsx import-alert-rules
```

> Note: older documentation referred to the executable as `directorSync.exe` and used `--additional-hooks-dir hooks-importer`. The current canonical build is `LPImporter` via `build.spec` with hooks in `hooks/`.

For the exporter splitter, run the Python script directly (no build is required):

```bash
python lp_tenant_exporter_v2\splitter\logpoint_config_splitter.py --input data\sync_config_ESA.json --input-sh data\alerts_with_ESA_original_repos.json --output-dir split --config-dir config
```

### Vérif rapide

```bash
# Toujours depuis lp_tenant_importer_v2/
export PYTHONPATH=..
python -c "import lp_tenant_importer_v2, sys; print('OK:', lp_tenant_importer_v2.__file__)"
```

> Astuce pro : utilise des **chemins absolus** dans `.env` (`LP_TENANTS_FILE`, `LP_PROFILE_FILE`) pour être insensible au répertoire courant.
