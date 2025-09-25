
import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import yaml
from dotenv import load_dotenv

from logging_utils import setup_logging

logger = logging.getLogger(__name__)

def load_env() -> None:
    """Load .env file and validate required variables.

    Raises:
        ValueError: If required environment variables are missing.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(script_dir, '.env')
    
    load_dotenv(env_path)
    required_vars = ["LP_DIRECTOR_URL", "LP_DIRECTOR_API_TOKEN", "LP_TENANTS_FILE"]
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        logger.error("Missing required environment variables: %s", ", ".join(missing))
        raise ValueError(f"Missing environment variables: {', '.join(missing)}")


def load_tenants_file(tenants_file: str) -> Dict[str, Any]:
    """Load and validate tenants YAML configuration file.

    Args:
        tenants_file: Path to the tenants YAML file.

    Returns:
        Dictionary containing the parsed YAML configuration.

    Raises:
        FileNotFoundError: If the tenants file does not exist.
        ValueError: If the YAML structure is invalid or missing required keys.
    """
    tenants_file = os.path.expanduser(tenants_file)
    if not os.path.exists(tenants_file):
        logger.error("Tenants file not found: %s", tenants_file)
        raise FileNotFoundError(f"Tenants file not found: {tenants_file}")

    with open(tenants_file, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file) or {}

    if not isinstance(config, dict) or "tenants" not in config:
        logger.error("Invalid tenants.yml: missing 'tenants' key")
        raise ValueError("Invalid tenants.yml: missing 'tenants' key")

    for tenant_name, tenant_data in config.get("tenants", {}).items():
        if "pool_uuid" not in tenant_data:
            logger.error("Tenant %s missing pool_uuid", tenant_name)
            raise ValueError(f"Tenant {tenant_name} missing pool_uuid")
        if "siems" not in tenant_data:
            logger.error("Tenant %s missing siems", tenant_name)
            raise ValueError(f"Tenant {tenant_name} missing siems")
    logger.debug(f"tenant config : {config}")
    return config


def get_tenant(config: Dict[str, Any], tenant_name: str) -> Dict[str, Any]:
    """Retrieve tenant configuration by name.

    Args:
        config: Parsed tenants YAML configuration.
        tenant_name: Name of the tenant to retrieve.

    Returns:
        Tenant configuration dictionary with siems (backends, search_heads, all_in_one).

    Raises:
        ValueError: If the tenant is not found.
    """
    tenant = config.get("tenants", {}).get(tenant_name)
    if not tenant:
        logger.error("Tenant %s not found in configuration file", tenant_name)
        raise ValueError(f"Tenant {tenant_name} not found")
    
    logger.debug(f"config dump: {config.get("tenants", {})}")
    defaults = config.get("tenants", {}).get("defaults", {})

    if not defaults :
        logger.error("defaults not found in configuration file")
        raise ValueError(f"defaults not found in configuration file")
    
    tenant["efaults"] = defaults

    # Use explicit all_in_one from YAML, no automatic computation
    siems = tenant.get("siems", {})
    for role in ["backends", "search_heads", "all_in_one"]:
        if role not in siems:
            siems[role] = []
        for node in siems[role]:
            if not isinstance(node, dict) or "id" not in node or "name" not in node:
                logger.error("Invalid node in %s: %s", role, node)
                raise ValueError(f"Invalid node in {role}: must have 'id' and 'name'")

    logger.debug("Tenant %s: %d backends, %d search_heads, %d all_in_one",
                 tenant_name, len(siems["backends"]), len(siems["search_heads"]), len(siems["all_in_one"]))
    return tenant


def get_targets(tenant: Dict[str, Any], element: str) -> List[str]:
    """Get target SIEM roles for a configuration element from tenant YAML.

    Args:
        tenant: Tenant configuration dictionary.
        element: Configuration element (e.g., 'repos', 'alerts').

    Returns:
        List of target roles (e.g., ['backends', 'all_in_one']).

    Raises:
        ValueError: If tenants file cannot be loaded.
    """
    default_targets = tenant.get("defaults", {}).get("target", {}).get(element, [])
    if not default_targets:
        # Fallback to global defaults
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        env_path = os.path.join(script_dir, '.env')
    
        load_dotenv(env_path)
        
        
        tenants_file = os.getenv("LP_TENANTS_FILE", "tenants.yaml")
        logging.info(f"Tenant file path: {tenants_file}")
        config = load_tenants_file(tenants_file)
        default_targets = config.get("defaults", {}).get("target", {}).get(element, [])
    logger.debug("Targets for %s: %s", element, default_targets)
    return default_targets


if __name__ == "__main__":
    load_env()
    setup_logging()
    config = load_tenants_file(os.getenv("LP_TENANTS_FILE"))
    tenant = get_tenant(config, "core")
    logger.debug("Tenant config: %s", tenant)
    logger.debug("Repos targets: %s", get_targets(tenant, "repos"))