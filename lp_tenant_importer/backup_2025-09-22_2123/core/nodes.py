import logging
from typing import Dict, List, Any

from logging_utils import setup_logging

logger = logging.getLogger(__name__)

def collect_nodes(tenant: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """Collect SIEM nodes by role from tenant configuration.

    Args:
        tenant: Tenant configuration dictionary from YAML.

    Returns:
        Dictionary mapping roles (backends, search_heads, all_in_one) to lists of SIEM nodes.

    Raises:
        ValueError: If tenant configuration is invalid or missing siems.
    """
    siems = tenant.get("siems", {})
    if not siems:
        logger.error("Tenant configuration missing 'siems' key")
        raise ValueError("Tenant configuration missing 'siems' key")

    # Extract nodes by role
    backends = siems.get("backends", [])
    search_heads = siems.get("search_heads", [])
    all_in_one = siems.get("all_in_one", [])

    # Validate node structure
    for role, nodes in [("backends", backends), ("search_heads", search_heads), ("all_in_one", all_in_one)]:
        for node in nodes:
            if not isinstance(node, dict) or "id" not in node or "name" not in node:
                logger.error("Invalid node in %s: %s", role, node)
                raise ValueError(f"Invalid node in {role}: must have 'id' and 'name'")

    logger.debug(
        "Collected nodes: %d backends, %d search_heads, %d all_in_one",
        len(backends), len(search_heads), len(all_in_one)
    )

    return {
        "backends": backends,
        "search_heads": search_heads,
        "all_in_one": all_in_one,
    }

if __name__ == "__main__":
    setup_logging()
    # Example tenant for testing
    sample_tenant = {
        "pool_uuid": "a9fa7661c4f84b278b136e94a86b4ea2",
        "siems": {
            "backends": [
                {"id": "506caf32de83054497d07c3c632a98cb", "name": "lb-backend01"},
                {"id": "01925abf82fe0db0a75c190c4316b8a6", "name": "lb-backend02"},
            ],
            "search_heads": [
                {"id": "1234567890abcdef1234567890abcdef", "name": "lb-search01"},
            ],
            "all_in_one": [],
        },
    }
    nodes = collect_nodes(sample_tenant)
    logger.debug("Nodes: %s", nodes)