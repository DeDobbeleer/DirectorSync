# PyInstaller hook for lp_tenant_importer_v2
# Ensures all data files are included

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Collect all data files from the package
datas = collect_data_files('lp_tenant_importer_v2', include_py_files=True)

# Collect all submodules (for dynamic imports)
hiddenimports = collect_submodules('lp_tenant_importer_v2')

# Additional hidden imports for external dependencies
hiddenimports += [
    'pandas._libs.tslibs.np_datetime',
    'pandas._libs.tslibs.timestamps',
    'pandas._libs.tslibs.timezones',
    'pandas._libs.tslibs.nattype',
    'pandas._libs.tslibs.tzconversion',
    'pandas._libs.missing',
    'pandas._libs.hashtable',
    'pandas._libs.algos',
    'pandas._libs.index',
    'pandas._libs.indexing',
    'pandas._libs.internals',
    'pandas._libs.interval',
    'pandas._libs.join',
    'pandas._libs.lib',
    'pandas._libs.ops',
    'pandas._libs.ops_dispatch',
    'pandas._libs.parsers',
    'pandas._libs.properties',
    'pandas._libs.reduction',
    'pandas._libs.reshape',
    'pandas._libs.sparse',
    'pandas._libs.testing',
    'pandas._libs.writers',
    'pandas.io.excel',
    'pandas.io.formats.excel',
    'openpyxl.cell._writer',
    'yaml.loader',
    'yaml.dumper',
    'yaml.scanner',
    'yaml.parser',
    'yaml.composer',
    'yaml.resolver',
    'yaml.emitter',
    'yaml.serializer',
    'yaml.representer',
    'yaml.constructor',
]
