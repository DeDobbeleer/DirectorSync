# /lp_tenant_import/test_config.py
import logging
logging.basicConfig(level="DEBUG")
from lp_tenant_importer.config_loader import load_env, load_tenants_file, get_tenant, get_targets

# Simuler .env
with open(".env", "w") as f:
    f.write("""LP_DIRECTOR_URL=https://10.160.144.185
LP_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
LP_TENANTS_FILE=./tenants.yml
LP_LOG_LEVEL=DEBUG
LP_LOG_JSON=false""")

# Simuler tenants.yml
with open("tenants.yml", "w") as f:
    f.write("""tenants:
  core:
    pool_uuid: "a9fa7661c4f84b278b136e94a86b4ea2"
    siems:
      search_heads: []
      backends:
        - { id: "506caf32de83054497d07c3c632a98cb", name: "lb-backend01" }
        - { id: "01925abf82fe0db0a75c190c4316b8a6", name: "lb-backend02" }
      all_in_one: []
    defaults:
      target:
        repos: [ backends, all_in_one ]
        alerts: [ search_heads ]
defaults:
  target:
    repos: [ backends, all_in_one ]
    alerts: [ search_heads ]
""")

# Test
load_env()
config = load_tenants_file("./tenants.yml")
tenant = get_tenant(config, "core")
print("Tenant:", tenant)
print("Repos targets:", get_targets(tenant, "repos"))
print("Alerts targets:", get_targets(tenant, "alerts"))