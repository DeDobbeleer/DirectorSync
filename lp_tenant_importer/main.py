import argparse
import os
from dotenv import load_dotenv
from core.http import DirectorClient
from importers.repos import import_repos
from logging_utils import logger
# Autres imports pour routing_policies, etc.

def cmd_import_repos(args, client):
    results = import_repos(
        client,
        args.xlsx,
        dry_run=args.dry_run,
        nonzero_on_skip=args.nonzero_on_skip,
        force_create=args.force_create
    )
    # Formatage table (basé sur tes logs)
    print("| siem | node | name | result | action | error |")
    print("| ---- | ---- | ---- | ------ | ------ | ----- |")
    for r in results:
        print(f"| {r['siem']} | {r['node']} | {r['name']} | {r['result']} | {r['action']} | {r['error']} |")
    logger.debug(f"Finished import_repos_for_nodes, rows={len(results)}, any_error={any(r['result'] == 'FAILED' for r in results)}")

def main():
    # Charger .env
    load_dotenv()
    logger.debug(f"Loading .env from: {os.path.abspath('.env')}")
    base_url = os.getenv("BASE_URL", "https://10.160.144.185")
    api_token = os.getenv("API_TOKEN")
    if not api_token:
        logger.error("API_TOKEN not found in .env")
        exit(1)
    logger.debug(f"Loaded API token: **** (length={len(api_token)})")

    parser = argparse.ArgumentParser(description="Logpoint Director Tenant Importer")
    parser.add_argument("--tenant", required=True, help="Tenant name")
    parser.add_argument("--xlsx", required=True, help="Path to config XLSX file")
    parser.add_argument("--dry-run", action="store_true", help="Simulate import without API calls")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--nonzero-on-skip", action="store_true", help="Exit with non-zero code on skip")
    parser.add_argument("--force-create", action="store_true", help="Force creation even if storage paths missing")
    
    subparsers = parser.add_subparsers(dest="command")
    parser_repos = subparsers.add_parser("import-repos")
    parser_repos.set_defaults(func=cmd_import_repos)
    # Autres subcommands (routing_policies, etc.)
    
    args = parser.parse_args()
    logger.debug(f"Parsed arguments: {vars(args)}")
    
    if not args.command:
        parser.print_help()
        exit(1)
    
    # Initialiser client
    client = DirectorClient(base_url, api_token, verify_ssl=not args.no_verify)
    args.func(args, client)

if __name__ == "__main__":
    main()