import json
import argparse
import logging
import os
import sys
from typing import Tuple, Dict, List
from dotenv import load_dotenv

from config_loader import load_tenants_file, get_tenant
from core.http import DirectorClient
from core.nodes import Node, collect_nodes
from importers.repos import import_repos_for_nodes
from importers.routing_policies import import_routing_policies_for_nodes
from importers.normalization_policies import import_normalization_policies_for_nodes
from importers.processing_policies import import_processing_policies_for_nodes
from importers.enrichment_policies import import_enrichment_policies_for_nodes
from importers.alerts import import_alerts_for_nodes

logging_utils = __import__("logging_utils")
logging_utils.setup_logging()

logger = logging.getLogger(__name__)

# Charger les variables d'environnement depuis .env
# env_path = os.path.join()
#logger.debug("Loading .env from: %s", env_path)

script_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(script_dir, '.env')
logger.debug(f"opening env file: {env_path}")
load_dotenv(env_path)


def _prepare_context(args) -> Tuple[DirectorClient, str, str, str, Dict[str, List[Node]], str]:
    """Prepare the context for the command execution.

    Args:
        args: Parsed command line arguments.

    Returns:
        Tuple containing client, tenant file, tenant name, pool UUID, nodes, and XLSX path.
    """
    api_token = os.environ.get("LP_DIRECTOR_API_TOKEN", "")
    logger.debug("Loaded API token: %s (length=%d)", "*" * min(len(api_token), 8) if api_token else "None", len(api_token))  # Log token masked with length
    if not api_token:
        logger.error("API token is empty or not loaded from .env")
    base_url = os.environ.get("LP_DIRECTOR_URL", "https://localhost")
    tenants_file = os.path.expanduser(args.tenants_file or "tenants.yml")
    tenant_name = args.tenant
    xlsx_path = os.path.expanduser(args.xlsx)

    client = DirectorClient(base_url, api_token, verify=not args.no_verify)
    
    tenant_config = load_tenants_file(tenants_file)
    tenant = get_tenant(tenant_config, tenant_name)
    pool_uuid = tenant["pool_uuid"]
    nodes = collect_nodes(tenant)

    # De-duplicate nodes based on ID
    seen_ids = set()
    deduplicated_nodes = {"backends": [], "search_heads": [], "all_in_one": []}
    for node_type, node_list in nodes.items():
        for node in node_list:
            if node.id not in seen_ids:
                deduplicated_nodes[node_type].append(node)
                seen_ids.add(node.id)
    logger.debug("De-duplicated nodes: %s", deduplicated_nodes)

    logger.debug("Loaded API token: %s", json.dumps({"length": len(api_token)}, separators=(',', ':')))

    return client, tenants_file, tenant_name, pool_uuid, deduplicated_nodes, xlsx_path

def cmd_import_repos(args):
    """Import repositories command handler."""
    client, tenants_file, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_tenant(load_tenants_file(tenants_file), tenant_name)["defaults"]["target"]["repos"]
    rows, any_error = import_repos_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets, args.force_create)
    logger.debug("Finished import_repos_for_nodes, rows=%d, any_error=%s", len(rows), any_error)
    print_table(rows, args.format)
    if any_error:
        sys.exit(1)

def cmd_import_routing_policies(args):
    """Import routing policies command handler."""
    client, tenants_file, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_tenant(load_tenants_file(tenants_file), tenant_name)["defaults"]["target"]["routing_policies"]
    rows, any_error = import_routing_policies_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if any_error:
        sys.exit(1)
    print_table(rows, args.format)

def cmd_import_normalization_policies(args):
    """Import normalization policies command handler."""
    client, tenants_file, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_tenant(load_tenants_file(tenants_file), tenant_name)["defaults"]["target"]["normalization_policies"]
    rows, any_error = import_normalization_policies_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if any_error:
        sys.exit(1)
    print_table(rows, args.format)

def cmd_import_processing_policies(args):
    """Import processing policies command handler."""
    client, tenants_file, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_tenant(load_tenants_file(tenants_file), tenant_name)["defaults"]["target"]["processing_policies"]
    rows, any_error = import_processing_policies_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if any_error:
        sys.exit(1)
    print_table(rows, args.format)

def cmd_import_enrichment_policies(args):
    """Import enrichment policies command handler."""
    client, tenants_file, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_tenant(load_tenants_file(tenants_file), tenant_name)["defaults"]["target"]["enrichment-policies"]
    rows, any_error = import_enrichment_policies_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if any_error:
        sys.exit(1)
    print_table(rows, args.format)

def cmd_import_alerts(args):
    """Import alerts command handler."""
    client, tenants_file, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_tenant(load_tenants_file(tenants_file), tenant_name)["defaults"]["target"]["alerts"]
    rows, any_error = import_alerts_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if any_error:
        sys.exit(1)
    print_table(rows, args.format)

# def print_table(rows, format):
#     """Print the result table in the specified format."""
#     if format == "table":
#         headers = ["siem", "node", "name", "result", "action", "error"]
#         print(f"| {' | '.join(headers)} |")
#         print(f"| {' | '.join(['-' * len(h) for h in headers])} |")
#         for row in rows:
#             print(f"| {' | '.join(str(row.get(h, '')) for h in headers)} |")
#     elif format == "json":
#         import json
#         print(json.dumps(rows, indent=2))
        
def print_table(rows: list, format ) -> None:
    """Pretty markdown-like table commune (Repos / Routing / Normalization / Processing)."""
    def _present(v) -> bool:
        return not (v is None or v == "" or v == [])

    candidates = [
       "siem","node","name","policy","path",
       "packages_count","compiled_count","criteria_count","catch_all",
       "result","action","status","monitor_ok","verified","error","NP_Name","RP_Name","EP_Name",
    ]
    mandatory = {"siem","node","result"}
    
    if format == "table": 
        cols = []
        for c in candidates:
            if (c in mandatory) or any(_present(r.get(c)) for r in rows):
                cols.append(c)

        def _fmt(v, col):
            if col == "node":
                s = str(v or "")
                if len(s) > 16:
                    s = f"{s[:8]}…{s[-4:]}"
                return s or "—"
            if isinstance(v, bool):
                return "✓" if v else "✗"
            if v is None or v == "":
                return "—"
            return str(v)

        widths = {c: len(c) for c in cols}
        for r in rows:
            for c in cols:
                w = len(_fmt(r.get(c), c))
                if w > widths[c]:
                    widths[c] = w

        header = "| " + " | ".join(c.ljust(widths[c]) for c in cols) + " |"
        sep    = "| " + " | ".join("-" * widths[c] for c in cols) + " |"
        print(header)
        print(sep)
        for r in rows:
            print("| " + " | ".join(_fmt(r.get(c), c).ljust(widths[c]) for c in cols) + " |")
            
    elif format == "json":
        import json
        print(json.dumps(rows, indent=2))    
        
def main():
    """Main function to parse arguments and dispatch commands."""
    parser = argparse.ArgumentParser(description="Logpoint Director Importer")
    parser.add_argument("--tenant", required=True, help="Tenant name")
    parser.add_argument("--tenants-file", help="Path to tenants configuration file")
    parser.add_argument("--xlsx", required=True, help="Path to Excel configuration file")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode, no changes made")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--force-create", action="store_true", help="Force creation even if storage paths missing")

    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_import_repos = subparsers.add_parser("import-repos", help="Import repositories")
    parser_import_repos.set_defaults(func=cmd_import_repos)

    parser_import_routing_policies = subparsers.add_parser("import-routing-policies", help="Import routing policies")
    parser_import_routing_policies.set_defaults(func=cmd_import_routing_policies)

    parser_import_normalization_policies = subparsers.add_parser("import-normalization-policies", help="Import normalization policies")
    parser_import_normalization_policies.set_defaults(func=cmd_import_normalization_policies)

    parser_import_processing_policies = subparsers.add_parser("import-processing-policies", help="Import processing policies")
    parser_import_processing_policies.set_defaults(func=cmd_import_processing_policies)

    parser_import_enrichment_policies = subparsers.add_parser("import-enrichment-policies", help="Import enrichment policies")
    parser_import_enrichment_policies.set_defaults(func=cmd_import_enrichment_policies)

    parser_import_alerts = subparsers.add_parser("import-alerts", help="Import alerts")
    parser_import_alerts.set_defaults(func=cmd_import_alerts)

    args = parser.parse_args()
    logger.debug("Parsed arguments: %s", vars(args))
      
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    return args.func(args)

if __name__ == "__main__":
    main()