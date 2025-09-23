import os
import sys
import json
import argparse
import logging
from typing import List, Dict, Any
from pathlib import Path

from config_loader import load_env, load_tenants_file, get_tenant, get_targets
from core.http import DirectorClient
from core.nodes import collect_nodes
from importers.repos import import_repos_for_nodes
from importers.routing_policies import import_routing_policies_for_nodes
from importers.alerts import import_alerts_for_nodes
from importers.normalization_policies import import_normalization_policies_for_nodes
from importers.processing_policies import import_processing_policies_for_nodes
from logging_utils import setup_logging

logger = logging.getLogger(__name__)

def _env_bool(name: str, default: bool = False) -> bool:
    """Convert environment variable to boolean.

    Args:
        name: Environment variable name.
        default: Default value if variable is unset or invalid.

    Returns:
        Boolean value of the variable.
    """
    value = os.getenv(name, "").strip().lower()
    return value in ("1", "true", "yes", "on", "y") or default


def _disable_insecure_warning() -> None:
    """Disable insecure request warnings if LP_VERIFY is False."""
    if not _env_bool("LP_VERIFY", True):
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            logger.warning("Failed to disable insecure warnings")


def _prepare_context(
    args: argparse.Namespace,
) -> tuple[DirectorClient, Dict[str, Any], str, str, Dict[str, List], str]:
    """Prepare context for import commands.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Tuple of (client, tenants_config, tenant_name, pool_uuid, nodes, xlsx_path).

    Raises:
        SystemExit: If required environment variables are missing.
    """
    load_env()
    base_url = os.getenv("LP_DIRECTOR_URL")
    api_token = os.getenv("LP_TOKEN")
    if not base_url or not api_token:
        logger.error("LP_DIRECTOR_URL and/or LP_TOKEN not set in .env")
        sys.exit(2)

    tenants_file = args.tenants_file or os.getenv("LP_TENANTS_FILE", "~/.config/lp_importer/tenants.yml")
    tenant_name = args.tenant
    xlsx_path = args.xlsx

    verify = not args.no_verify and _env_bool("LP_VERIFY", True)
    _disable_insecure_warning()
    timeout = int(os.getenv("LP_HTTP_TIMEOUT", 30))
    proxies = {"http": os.getenv("LP_HTTP_PROXY", ""), "https": os.getenv("LP_HTTPS_PROXY", "")}

    tenants_config = load_tenants_file(tenants_file)
    tenant_obj = get_tenant(tenants_config, tenant_name)
    pool_uuid = tenant_obj["pool_uuid"]
    nodes = collect_nodes(tenant_obj)

    # De-duplicate nodes considering all_in_one as both backend and search_head
    unique_nodes = {"backends": [], "search_heads": [], "all_in_one": []}
    seen_ids = set()
    for role in ["all_in_one", "backends", "search_heads"]:  # Process all_in_one first
        for node in nodes[role]:
            if node["id"] not in seen_ids:
                unique_nodes[role].append(node)
                seen_ids.add(node["id"])
    logger.debug("De-duplicated nodes: %s", unique_nodes)
    nodes = unique_nodes

    client = DirectorClient(
        base_url, api_token, verify=verify, timeout=timeout, proxies=proxies
    )

    return client, tenants_config, tenant_name, pool_uuid, nodes, xlsx_path


def _print_table(rows: List[Dict[str, Any]]) -> None:
    """Print results as a markdown-like table.

    Args:
        rows: List of result dictionaries.
    """
    if not rows:
        logger.warning("No results to display in table")
        print("| siem | node | name | result | action |")
        print("| ---- | ---- | ---- | ------ | ------ |")
        print("| none | none | N/A  | SKIPPED | NO_DATA |")
        return

    candidates = [
        "siem",
        "node",
        "name",
        "policy",
        "path",
        "packages_count",
        "compiled_count",
        "criteria_count",
        "catch_all",
        "result",
        "action",
        "status",
        "error",
    ]
    mandatory = {"siem", "node", "result"}
    cols = [c for c in candidates if c in mandatory or any(r.get(c) for r in rows)]

    def _fmt(value, col):
        if col == "node" and value:
            str_val = str(value)
            return str_val[:16] + "…" + str_val[-4:] if len(str_val) > 20 else str_val
        if isinstance(value, bool):
            return "✓" if value else "✗"
        return str(value or "—")

    widths = {
        c: max(len(c), max((len(_fmt(r.get(c), c)) for r in rows), default=0)) for c in cols
    }
    header = "| " + " | ".join(c.ljust(widths[c]) for c in cols) + " |"
    sep = "| " + " | ".join("-" * widths[c] for c in cols) + " |"
    
    print(header)
    print(sep)
    for row in rows:
        print("| " + " | ".join(_fmt(row.get(c), c).ljust(widths[c]) for c in cols) + " |")


def cmd_import_repos(args: argparse.Namespace) -> int:
    """Import repositories from XLSX file.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 2 for errors).
    """
    client, _, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_targets(
        get_tenant(load_tenants_file(args.tenants_file or os.getenv("LP_TENANTS_FILE")), tenant_name),
        "repos",
    )
    logger.debug("Importing repos with targets: %s", targets)
    rows, any_error = import_repos_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if args.format == "table":
        _print_table(rows)
    else:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 2 if any_error else 0


def cmd_import_routing_policies(args: argparse.Namespace) -> int:
    """Import routing policies from XLSX file.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 2 for errors).
    """
    client, _, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_targets(
        get_tenant(load_tenants_file(args.tenants_file or os.getenv("LP_TENANTS_FILE")), tenant_name),
        "routing_policies",
    )
    logger.debug("Importing routing policies with targets: %s", targets)
    rows, any_error = import_routing_policies_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if args.format == "table":
        _print_table(rows)
    else:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 2 if any_error else 0


def cmd_import_alerts(args: argparse.Namespace) -> int:
    """Import alerts from XLSX file.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 2 for errors).
    """
    client, _, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_targets(
        get_tenant(load_tenants_file(args.tenants_file or os.getenv("LP_TENANTS_FILE")), tenant_name),
        "alerts",
    )
    logger.debug("Importing alerts with targets: %s", targets)
    rows, any_error = import_alerts_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if args.format == "table":
        _print_table(rows)
    else:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 2 if any_error else 0


def cmd_import_normalization_policies(args: argparse.Namespace) -> int:
    """Import normalization policies from XLSX file.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 2 for errors).
    """
    client, _, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_targets(
        get_tenant(load_tenants_file(args.tenants_file or os.getenv("LP_TENANTS_FILE")), tenant_name),
        "normalization_policies",
    )
    logger.debug("Importing normalization policies with targets: %s", targets)
    rows, any_error = import_normalization_policies_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if args.format == "table":
        _print_table(rows)
    else:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 2 if any_error else 0


def cmd_import_processing_policies(args: argparse.Namespace) -> int:
    """Import processing policies from XLSX file.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 2 for errors).
    """
    client, _, tenant_name, pool_uuid, nodes, xlsx_path = _prepare_context(args)
    targets = get_targets(
        get_tenant(load_tenants_file(args.tenants_file or os.getenv("LP_TENANTS_FILE")), tenant_name),
        "processing_policies",
    )
    logger.debug("Importing processing policies with targets: %s", targets)
    rows, any_error = import_processing_policies_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run, targets)
    if args.format == "table":
        _print_table(rows)
    else:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 2 if any_error else 0


def build_parser() -> argparse.ArgumentParser:
    """Build command-line argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="lp_importer", description="Import configurations tenant by tenant, element by element"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Simulate without making API calls"
    )
    parser.add_argument(
        "--format", choices=["json", "table"], default="json", help="Output format"
    )
    parser.add_argument(
        "--no-verify", action="store_true", help="Disable TLS verification"
    )
    parser.add_argument(
        "--nonzero-on-skip", action="store_true", help="Return exit code 2 if any actions are skipped"
    )
    parser.add_argument(
        "--emit-checklist", action="store_true", help="Emit dest_lookup_checklist.csv"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # import-repos
    pr = subparsers.add_parser("import-repos", help="Import repositories from XLSX")
    pr.add_argument("--tenant", required=True, help="Tenant key from tenants.yml")
    pr.add_argument("--xlsx", required=True, help="Path to XLSX file")
    pr.add_argument("--tenants-file", help="Path to tenants.yml")
    pr.add_argument("--dry-run", action="store_true", help="Simulate without making API calls")
    pr.add_argument("--format", choices=["json", "table"], default="json", help="Output format")
    pr.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
    pr.add_argument("--nonzero-on-skip", action="store_true", help="Return exit code 2 if any actions are skipped")
    pr.add_argument("--emit-checklist", action="store_true", help="Emit dest_lookup_checklist.csv")
    pr.set_defaults(func=cmd_import_repos)

    # import-routing-policies
    rp = subparsers.add_parser("import-routing-policies", help="Import routing policies from XLSX")
    rp.add_argument("--tenant", required=True, help="Tenant key from tenants.yml")
    rp.add_argument("--xlsx", required=True, help="Path to XLSX file")
    rp.add_argument("--tenants-file", help="Path to tenants.yml")
    rp.add_argument("--dry-run", action="store_true", help="Simulate without making API calls")
    rp.add_argument("--format", choices=["json", "table"], default="json", help="Output format")
    rp.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
    rp.add_argument("--nonzero-on-skip", action="store_true", help="Return exit code 2 if any actions are skipped")
    rp.add_argument("--emit-checklist", action="store_true", help="Emit dest_lookup_checklist.csv")
    rp.set_defaults(func=cmd_import_routing_policies)

    # import-alerts
    pa = subparsers.add_parser("import-alerts", help="Import alerts from XLSX (Search Heads)")
    pa.add_argument("--tenant", required=True, help="Tenant key from tenants.yml")
    pa.add_argument("--xlsx", required=True, help="Path to XLSX file")
    pa.add_argument("--tenants-file", help="Path to tenants.yml")
    pa.add_argument("--dry-run", action="store_true", help="Simulate without making API calls")
    pa.add_argument("--format", choices=["json", "table"], default="json", help="Output format")
    pa.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
    pa.add_argument("--nonzero-on-skip", action="store_true", help="Return exit code 2 if any actions are skipped")
    pa.add_argument("--emit-checklist", action="store_true", help="Emit dest_lookup_checklist.csv")
    pa.set_defaults(func=cmd_import_alerts)

    # import-normalization-policies
    np = subparsers.add_parser("import-normalization-policies", help="Import normalization policies from XLSX")
    np.add_argument("--tenant", required=True, help="Tenant key from tenants.yml")
    np.add_argument("--xlsx", required=True, help="Path to XLSX file")
    np.add_argument("--tenants-file", help="Path to tenants.yml")
    np.add_argument("--dry-run", action="store_true", help="Simulate without making API calls")
    np.add_argument("--format", choices=["json", "table"], default="json", help="Output format")
    np.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
    np.add_argument("--nonzero-on-skip", action="store_true", help="Return exit code 2 if any actions are skipped")
    np.add_argument("--emit-checklist", action="store_true", help="Emit dest_lookup_checklist.csv")
    np.set_defaults(func=cmd_import_normalization_policies)

    # import-processing-policies
    pp = subparsers.add_parser("import-processing-policies", help="Import processing policies from XLSX")
    pp.add_argument("--tenant", required=True, help="Tenant key from tenants.yml")
    pp.add_argument("--xlsx", required=True, help="Path to XLSX file")
    pp.add_argument("--tenants-file", help="Path to tenants.yml")
    pp.add_argument("--dry-run", action="store_true", help="Simulate without making API calls")
    pp.add_argument("--format", choices=["json", "table"], default="json", help="Output format")
    pp.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
    pp.add_argument("--nonzero-on-skip", action="store_true", help="Return exit code 2 if any actions are skipped")
    pp.add_argument("--emit-checklist", action="store_true", help="Emit dest_lookup_checklist.csv")
    pp.set_defaults(func=cmd_import_processing_policies)

    return parser


def main() -> int:
    """Main entry point for the CLI.

    Returns:
        Exit code (0 for success, 2 for errors or skips if --nonzero-on-skip).
    """
    setup_logging()
    parser = build_parser()
    args = parser.parse_args()
    return_code = args.func(args)

    if args.nonzero_on_skip and os.path.exists("plan.json"):
        try:
            with open("plan.json", "r", encoding="utf-8") as file:
                plan = json.load(file)
            if any(isinstance(row, dict) and row.get("action", "").lower() == "skip" for row in plan):
                return 2
        except Exception as e:
            logger.warning("Failed to check plan.json: %s", e)

    return return_code


if __name__ == "__main__":
    sys.exit(main())