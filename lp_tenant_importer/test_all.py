import pandas as pd
from repos import import_repos
from core.nodes import get_nodes_by_role
from core.http import DirectorClient
from logging_utils import logger
import os
from dotenv import load_dotenv

def test_all():
    load_dotenv()
    base_url = os.getenv("BASE_URL", "https://10.160.144.185")
    api_token = os.getenv("API_TOKEN")
    if not api_token:
        logger.error("API_TOKEN not found in .env")
        exit(1)
    
    client = DirectorClient(base_url, api_token, verify_ssl=False)
    config_file = "core_config.xlsx"
    df = pd.read_excel(config_file, sheet_name=None)
    assert "repos" in df, "Missing repos sheet"
    assert len(df["repos"]) == 6, f"Expected 6 repos, got {len(df['repos'])}"
    
    nodes = get_nodes_by_role()
    backends = nodes.get("backends", [])
    
    # Test dry-run
    results = import_repos(client, config_file, dry_run=True, nonzero_on_skip=False)
    logger.info(f"Repos import dry-run results: {results}")
    assert len(results) >= len(df["repos"]) * len(backends), f"Expected at least {len(df['repos']) * len(backends)} results, got {len(results)}"
    
    # Vérifier actions
    actions = [r["action"] for r in results]
    assert any(a in ["CREATE", "UPDATE", "NOOP", "MISSING_STORAGE_PATHS"] for a in actions), f"Unexpected actions: {actions}"
    
    # Test sans dry-run (commenter en prod)
    results = import_repos(client, config_file, dry_run=False, nonzero_on_skip=False)
    logger.info(f"Repos import results: {results}")
    assert any(r["action"] == "CREATE" and r["result"] == "SUCCESS" for r in results), "No successful CREATE action"

if __name__ == "__main__":
    test_all()