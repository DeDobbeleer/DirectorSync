# /lp_tenant_import/test_http.py
import logging
logging.basicConfig(level="DEBUG")
from core.http import DirectorClient
from config_loader import load_env
import os
import json

# Charger .env
load_env()

# Simuler client
client = DirectorClient(
    base_url=os.getenv("LP_DIRECTOR_URL"),
    token=os.getenv("LP_TOKEN"),
    verify=os.getenv("LP_VERIFY", "true").lower() == "true",
    timeout=int(os.getenv("LP_HTTP_TIMEOUT", 30)),
    proxies={
        "http": os.getenv("LP_HTTP_PROXY", ""),
        "https": os.getenv("LP_HTTPS_PROXY", ""),
    },
    artifacts_dir="./artifacts_test"
)

# Simuler endpoint (pas d’appel réel)
endpoint = client.build_endpoint(
    pool_uuid="a9fa7661c4f84b278b136e94a86b4ea2",
    siem_id="506caf32de83054497d07c3c632a98cb",
    resource="repos"
)
print(f"Endpoint: {endpoint}")

# Simuler payload pour POST (exemple repo)
payload = {
    "name": "Repo_system",
    "storage_paths": ["/data_hot"],
    "retention_days": 90,
    "active": True
}
print(f"Payload: {json.dumps(payload, indent=2)}")

# Pas d’appel réel (dry-run simulé), juste vérifier headers
print(f"Headers: {dict(client.session.headers)}")