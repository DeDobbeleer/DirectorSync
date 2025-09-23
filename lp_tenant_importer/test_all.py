import os
import subprocess
import logging
from pathlib import Path
from logging_utils import setup_logging
from core.nodes import collect_nodes
from config_loader import load_tenants_file, get_tenant
import pandas as pd

logging.getLogger().handlers = []
setup_logging()
logger = logging.getLogger(__name__)

xlsx_path = "core_config.xlsx"
logger.info("Checking for XLSX file: %s", xlsx_path)
if not Path(xlsx_path).exists():
    logger.error("%s not found. Please place your real core_config.xlsx in the directory.", xlsx_path)
    print(f"ERROR: {xlsx_path} not found. Please place your real core_config.xlsx in the directory.")
    exit(1)

logger.debug("Verifying XLSX content for %s", xlsx_path)
sheet_names = pd.ExcelFile(xlsx_path).sheet_names
logger.info("Available sheets: %s", sheet_names)
print(f"Available sheets: {sheet_names}")

for sheet in ["Repo", "RoutingPolicy", "Alert", "NormalizationPolicy", "ProcessingPolicy", "EnrichmentPolicy"]:
    if sheet in sheet_names:
        logger.debug("Reading sheet: %s", sheet)
        df = pd.read_excel(xlsx_path, sheet_name=sheet, skiprows=0)
        if 'row1' in df.iloc[0].astype(str).str.lower().values:
            df = df.iloc[1:].reset_index(drop=True)
        logger.info("Sheet '%s': %d rows, columns: %s", sheet, len(df), list(df.columns))
        print(f"Sheet '{sheet}': {len(df)} rows, columns: {list(df.columns)}")
        if not df.empty:
            logger.debug("First row of %s: %s", sheet, df.iloc[0].to_dict())
            print(f"First row: {df.iloc[0].to_dict()}")
    else:
        logger.warning("Sheet '%s' not found in XLSX", sheet)
        print(f"Sheet '{sheet}' not found in XLSX")

logger.info("Loading tenants.yml and collecting nodes for tenant 'core'")
config = load_tenants_file("./tenants.yml")
tenant = get_tenant(config, "core")
nodes = collect_nodes(tenant)
logger.info("Nodes: %s", nodes)
print(f"Nodes: {nodes}")

commands = [
    ["python", "main.py", "--help"],
    [
        "python",
        "main.py",
        "import-repos",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-routing-policies",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-alerts",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-normalization-policies",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-processing-policies",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
    [
        "python",
        "main.py",
        "import-enrichment-policies",
        "--tenant",
        "core",
        "--xlsx",
        "core_config.xlsx",
        "--dry-run",
        "--format",
        "table",
    ],
]

for cmd in commands:
    logger.info("Running command: %s", " ".join(cmd))
    print(f"\nRunning: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        logger.error("Command failed with exit code %d: %s", result.returncode, result.stderr)
        print(f"Error (exit code {result.returncode}): {result.stderr}")
    else:
        logger.debug("Command succeeded: %s", result.stdout)