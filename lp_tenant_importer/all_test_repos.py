import os
import subprocess
import logging
from pathlib import Path
from logging_utils import setup_logging
from core.nodes import collect_nodes
from config_loader import load_tenants_file, get_tenant
import pandas as pd

# Configure logging
logging.getLogger().handlers = []
setup_logging()
logger = logging.getLogger(__name__)

# Verify XLSX content for Repo sheet
xlsx_path = "core_config.xlsx"
logger.info("Checking for XLSX file: %s", xlsx_path)
if not Path(xlsx_path).exists():
    logger.error("%s not found. Please place your real core_config.xlsx in the directory.", xlsx_path)
    print(f"ERROR: {xlsx_path} not found. Please place your real core_config.xlsx in the directory.")
    exit(1)

logger.debug("Verifying Repo sheet content for %s", xlsx_path)
df = pd.read_excel(xlsx_path, sheet_name="Repo", skiprows=0)
if 'row1' in df.iloc[0].astype(str).str.lower().values:
    df = df.iloc[1:].reset_index(drop=True)
logger.info("Sheet 'Repo': %d rows, columns: %s", len(df), list(df.columns))
print(f"Sheet 'Repo': {len(df)} rows, columns: {list(df.columns)}")
if not df.empty:
    logger.debug("First row of Repo: %s", df.iloc[0].to_dict())
    print(f"First row: {df.iloc[0].to_dict()}")

# Test nodes
logger.info("Loading tenants.yml and collecting nodes for tenant 'core'")
config = load_tenants_file(os.getenv("LP_TENANTS_FILE", "~/.config/lp_importer/tenants.yml"))
tenant = get_tenant(config, "core")
nodes = collect_nodes(tenant)
logger.info("Nodes: %s", nodes)
print(f"Nodes: {nodes}")

# Test CLI command for repos
command = [
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
]
logger.info("Running command: %s", " ".join(command))
print(f"\nRunning: {' '.join(command)}")
result = subprocess.run(command, capture_output=True, text=True)
print(result.stdout)
if result.returncode != 0:
    logger.error("Command failed with exit code %d: %s", result.returncode, result.stderr)
    print(f"Error (exit code {result.returncode}): {result.stderr}")
else:
    logger.debug("Command succeeded: %s", result.stdout)