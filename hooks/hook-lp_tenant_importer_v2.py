# hooks/hook-lp_tenant_importer_v2.py
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# Embarque tout le package, y compris lp_tenant_importer_v2.importers.*
hiddenimports = collect_submodules('lp_tenant_importer_v2')
# datas = collect_data_files('lp_tenant_importer_v2')  # ex: resources/profiles.yml
