from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class Node:
    """Represents a SIEM node with an ID and name."""
    def __init__(self, id: str, name: str):
        self.id = id
        self.name = name

def collect_nodes(tenant_config: Dict) -> Dict[str, List[Node]]:
    """Collect nodes from tenant configuration.

    Args:
        tenant_config: Dictionary containing tenant configuration.

    Returns:
        Dictionary of node types and their instances.
    """
    nodes = {"backends": [], "search_heads": [], "all_in_one": []}
    
    siems = tenant_config.get("siems", {})
    for node_type in ["backends", "search_heads", "all_in_one"]:
        node_list = siems.get(node_type, [])
        for node in node_list:
            nodes[node_type].append(Node(node.get("id", ""), node.get("name", "")))
        logger.debug("Collected nodes: %d %s", len(nodes[node_type]), node_type)
    
    return nodes