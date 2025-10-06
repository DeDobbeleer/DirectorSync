Tu as ce message parce que tu exécutes depuis **`lp_tenant_importer_v2/`** et, dans ce cas, Python **ne voit pas** le package `lp_tenant_importer_v2` (le parent n’est pas sur `sys.path`). Deux façons pro de régler ça :

## Option A — Lancer depuis la racine du repo (le plus simple)

```bash
cd ~/dev/DirectorSync
source lp_tenant_importer_v2/.venv/bin/activate
git pull origin main
python -m lp_tenant_importer_v2.main \
  --tenant core \
  --tenants-file ./tenants.yml \
  --xlsx ./lp_tenant_importer/samples/core_config.xlsx \
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
  import-devices
```

### Vérif rapide

```bash
# Toujours depuis lp_tenant_importer_v2/
export PYTHONPATH=..
python -c "import lp_tenant_importer_v2, sys; print('OK:', lp_tenant_importer_v2.__file__)"
```

> Astuce pro : utilise des **chemins absolus** dans `.env` (`LP_TENANTS_FILE`, `LP_PROFILE_FILE`) pour être insensible au répertoire courant.



convert to exe

pyinstaller --onefile --name DirectorSync app.py --collect-submodules lp_tenant_importer_v2 --collect-all pandas --collect-all openpyxl --collect-all requests --collect-all PyYAML 

pyinstaller --onefile --name DirectorSync "app.py" --additional-hooks-dir=hooks --collect-all pandas --collect-all openpyxl
  requests
pandas
openpyxl
python-dotenv
PyYAML

	Wu5T2HeE76