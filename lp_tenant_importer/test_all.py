import pandas as pd
from importers.repos import import_repos_for_nodes
from core.nodes import collect_nodes
from core.http import DirectorClient
from config_loader import load_tenants_file, get_tenant
from logging_utils import logger
import os
from dotenv import load_dotenv

def test_all():
    load_dotenv()
    base_url = os.getenv("LP_DIRECTOR_URL", "https://10.160.144.185")
    api_token = os.getenv("LP_DIRECTOR_API_TOKEN")
    if not api_token:
        logger.error("API_TOKEN not found in .env")
        exit(1)
    
    client = DirectorClient(base_url, api_token, verify=False)
    config_file = "core_config.xlsx"
    tenant_config = load_tenants_file(os.path.expanduser("~/.config/lp_importer/tenants.yml"))
    tenant = get_tenant(tenant_config, "core")
    pool_uuid = tenant["pool_uuid"]
    nodes = collect_nodes(tenant)
    targets = tenant["defaults"]["target"]["repos"]
    
    df = pd.read_excel(config_file, sheet_name=None)
    assert "Repo" in df, "Missing Repo sheet"
    assert len(df["Repo"]) == 6, f"Expected 6 repos, got {len(df['Repo'])}"
    
    results, any_error = import_repos_for_nodes(client, pool_uuid, nodes, config_file, dry_run=True, targets=targets)
    logger.info(f"Repos import dry-run results: {results}")
    assert len(results) >= len(df["Repo"]) * len(nodes.get("backends", [])), f"Expected at least {len(df['Repo']) * len(nodes.get('backends', []))} results, got {len(results)}"
    
    actions = [r["action"] for r in results]
    assert any(a in ["CREATED", "UPDATED", "NONE", "MISSING_STORAGE_PATHS", "DRY_RUN"] for a in actions), f"Unexpected actions: {actions}"
    
    # Test sans dry-run (commenter en prod)
    results, any_error = import_repos_for_nodes(client, pool_uuid, nodes, config_file, dry_run=False, targets=targets)
    logger.info(f"Repos import results: {results}")
    assert any(r["action"] == "CREATED" and r["result"] == "SUCCESS" for r in results), "No successful CREATED action"

if __name__ == "__main__":
    test_all()