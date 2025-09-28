"""
CLI — Strictly identical commands/flags to v1 for end-users (no force-create).
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, List, Tuple
import requests

from .core.config import Config, NodeRef
from .core.director_client import DirectorClient
from .core.logging_utils import setup_logging, get_logger
from .importers.repos import ReposImporter
from .utils.reporting import print_rows
from .utils.validators import ValidationError
from .core.config import ConfigError
setup_logging()
log = get_logger(__name__)

EXIT_OK = 0
EXIT_GENERIC_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_VALIDATION_ERROR = 3
EXIT_NETWORK_ERROR = 4

def _prepare_context(args) -> Tuple[DirectorClient, str, str, Dict[str, List[NodeRef]], str, Config]:
    # Friendly fallback: honor --tenants-file if env is missing
    if args.tenants_file and not os.getenv("LP_TENANTS_FILE"):
        os.environ["LP_TENANTS_FILE"] = args.tenants_file
    try:
        cfg = Config.from_env()
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        raise
    
    client = DirectorClient(cfg.director_url, os.getenv("LP_DIRECTOR_API_TOKEN", ""), verify=not args.no_verify)
    tenant = cfg.get_tenant(args.tenant)
    pool_uuid = tenant.pool_uuid

    nodes = {
        "backends": tenant.siems["backends"],
        "search_heads": tenant.siems["search_heads"],
        "all_in_one": tenant.siems["all_in_one"],
    }
    return client, pool_uuid, args.tenant, nodes, args.xlsx, cfg


def cmd_import_repos(args):
    try:
        # Early check: XLSX path exists
        if not os.path.isfile(args.xlsx):
            raise FileNotFoundError(
                f"XLSX file not found: {args.xlsx}. "
                "Hint: try ./lp_tenant_importer/samples/core_config.xlsx "
                "or provide an absolute path."
            )
        client, pool_uuid, tenant_name, _nodes_map, xlsx_path, cfg = _prepare_context(args)
        nodes = cfg.get_targets(cfg.get_tenant(tenant_name), "repos")
        importer = ReposImporter()
        result = importer.run_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run)
        print_rows(result.rows, args.format)
        if result.any_error:
            raise RuntimeError("One or more operations failed; see rows above.")
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        sys.exit(EXIT_CONFIG_ERROR)
    except FileNotFoundError as exc:
        log.error("File not found: %s", exc)
        sys.exit(EXIT_VALIDATION_ERROR)
    except ValidationError as exc:
        log.error("Validation error: %s", exc)
    except RuntimeError as exc:
        # Catch loader errors (e.g., pandas/openpyxl issues) and surface as validation failures
        log.error("Validation error: %s", exc)
        sys.exit(EXIT_VALIDATION_ERROR)
        sys.exit(EXIT_VALIDATION_ERROR)
    except requests.RequestException as exc:
        log.error("Network/HTTP error: %s", exc)
        sys.exit(EXIT_NETWORK_ERROR)
    except Exception as exc:
        log.error("Unexpected error: %s", exc, exc_info=True)
        sys.exit(EXIT_GENERIC_ERROR)


# Stubs for other commands — wired to preserve CLI; will be migrated progressively.
def _not_implemented(name: str):
    log.error("%s importer not implemented in v2 yet. This is a placeholder wired to the new trunk.", name)
    print_rows([{"siem": "-", "node": "-", "result": "skip", "action": f"{name} importer not implemented in v2 yet"}], "table")


def cmd_import_routing_policies(args): _not_implemented("routing_policies")
def cmd_import_normalization_policies(args): _not_implemented("normalization_policies")
def cmd_import_processing_policies(args): _not_implemented("processing_policies")
def cmd_import_enrichment_policies(args): _not_implemented("enrichment_policies")
def cmd_import_device_groups(args): _not_implemented("device_groups")
def cmd_import_devices(args): _not_implemented("devices")
def cmd_import_syslog_collectors(args): _not_implemented("syslog_collectors")
def cmd_import_alerts(args): _not_implemented("alerts")


def main():
    parser = argparse.ArgumentParser(description="Logpoint Director Importer (v2)")
    parser.add_argument("--tenant", required=True, help="Tenant name")
    parser.add_argument("--tenants-file", help="(Ignored) for compatibility; path comes from LP_TENANTS_FILE in .env")
    parser.add_argument("--xlsx", required=True, help="Path to Excel configuration file")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode, no changes made")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sp = subparsers.add_parser("import-repos", help="Import repositories")
    sp.set_defaults(func=cmd_import_repos)

    sp = subparsers.add_parser("import-routing-policies", help="Import routing policies")
    sp.set_defaults(func=cmd_import_routing_policies)

    sp = subparsers.add_parser("import-normalization-policies", help="Import normalization policies")
    sp.set_defaults(func=cmd_import_normalization_policies)

    sp = subparsers.add_parser("import-processing-policies", help="Import processing policies")
    sp.set_defaults(func=cmd_import_processing_policies)

    sp = subparsers.add_parser("import-enrichment-policies", help="Import enrichment policies")
    sp.set_defaults(func=cmd_import_enrichment_policies)

    sp = subparsers.add_parser("import-device-groups", help="Import device groups")
    sp.set_defaults(func=cmd_import_device_groups)

    sp = subparsers.add_parser("import-devices", help="Import devices")
    sp.set_defaults(func=cmd_import_devices)

    sp = subparsers.add_parser("import-syslog-collectors", help="Import Syslog Collectors")
    sp.set_defaults(func=cmd_import_syslog_collectors)

    sp = subparsers.add_parser("import-alerts", help="Import alerts")
    sp.set_defaults(func=cmd_import_alerts)

    args = parser.parse_args()
    
    try:
        args.func(args)
        return EXIT_OK
    except SystemExit as e:
        # Propagate explicit exits (we set them above)
        return int(e.code) if isinstance(e.code, int) else EXIT_GENERIC_ERROR
    except Exception as exc:
        log.error("Fatal error: %s", exc, exc_info=True)
        return EXIT_GENERIC_ERROR

if __name__ == "__main__":
    main()
