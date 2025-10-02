# lp_tenant_importer_v2/main.py
"""CLI — generic wiring for all importers via a central registry.

End-user UX remains identical. Each importer declares itself in
`lp_tenant_importer_v2/importers/registry.py`, and `main.py` generates
subcommands automatically and routes to a single handler.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Tuple, List, Dict, Any

import requests

from .core.config import Config, ConfigError
from .core.director_client import DirectorClient
from .core.logging_utils import setup_logging, get_logger
from .utils.reporting import print_rows
from .utils.validators import ValidationError  # keep if present in your tree
from .importers.registry import get_spec_by_key, iter_specs

# Initialize logging ASAP
setup_logging()
log = get_logger(__name__)

# Exit codes
EXIT_OK = 0
EXIT_GENERIC_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_VALIDATION_ERROR = 3
EXIT_NETWORK_ERROR = 4


def _prepare_context(args) -> Tuple[DirectorClient, str, str, str, Config]:
    """Resolve environment/config and return runtime artifacts.

    Returns:
        client: DirectorClient
        pool_uuid: Pool UUID
        tenant_name: Tenant name string
        xlsx_path: Resolved XLSX path
        cfg: Config object
    """
    # Fallback to --tenants-file if env is missing
    if args.tenants_file and not os.getenv("LP_TENANTS_FILE"):
        os.environ["LP_TENANTS_FILE"] = args.tenants_file

    cfg = Config.from_env()

    token = os.getenv("LP_DIRECTOR_API_TOKEN", "")
    client = DirectorClient(
        cfg.director_url,
        token,
        verify=not args.no_verify,
    )

    tenant = cfg.get_tenant(args.tenant)
    pool_uuid = tenant.pool_uuid

    # Normalize XLSX path for nicer error messages
    xlsx_path = os.path.abspath(os.path.expanduser(args.xlsx))
    return client, pool_uuid, tenant.name, xlsx_path, cfg


def _enrich_rows_for_output(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize a few fields for nicer table output."""
    out: List[Dict[str, Any]] = []
    for r in rows:
        rr = dict(r)  # shallow copy

        # Normalize 'error'
        err = rr.get("error")
        if isinstance(err, list):
            rr["error"] = f"missing repos: {', '.join(err)}" if err else "—"
        elif err in (None, ""):
            res = rr.get("result_detail") or rr.get("details") or {}
            if isinstance(res, dict) and "missing_repos" in res:
                m = res.get("missing_repos") or []
                rr["error"] = f"missing repos: {', '.join(m)}" if m else "—"

        # Monitor fields
        rr["monitor_ok"] = "—" if not rr.get("monitor_ok") else str(rr["monitor_ok"])
        rr["monitor_branch"] = rr.get("monitor_branch") or "—"

        out.append(rr)
    return out


# ----------------------- Generic command handler ----------------------------

def cmd_import_generic(args):
    """Generic handler for all importers declared in the registry."""
    try:
        # Early check: XLSX path exists
        if not os.path.isfile(args.xlsx):
            raise FileNotFoundError(
                (
                    f"XLSX file not found: {args.xlsx}. "
                    "Hint: try ./lp_tenant_importer_v2/samples/core_config.xlsx "
                    "or provide an absolute path."
                )
            )

        spec_key = getattr(args, "importer_key", None)
        if not spec_key:
            raise RuntimeError("Internal error: importer_key not set on subcommand")
        spec = get_spec_by_key(spec_key)

        client, pool_uuid, tenant_name, xlsx_path, cfg = _prepare_context(args)

        # Resolve target nodes from global defaults.target for this element
        nodes = cfg.get_targets(cfg.get_tenant(tenant_name), spec.element_key)

        # Lazy-load the importer class and run
        importer_cls = spec.load_class()
        importer = importer_cls()
        result = importer.run_for_nodes(client, pool_uuid, nodes, xlsx_path, args.dry_run)

        # Enrich and print
        rows = _enrich_rows_for_output(result.rows)
        print_rows(rows, args.format)

        if result.any_error:
            raise RuntimeError("One or more operations failed; see rows above.")

    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        sys.exit(EXIT_CONFIG_ERROR)
    except FileNotFoundError as exc:
        log.error("File not found: %s", exc)
        sys.exit(EXIT_VALIDATION_ERROR)
    except ValidationError as exc:  # noqa: F401 (keep aligned with project layout)
        log.error("Validation error: %s", exc)
        sys.exit(EXIT_VALIDATION_ERROR)
    except requests.RequestException as exc:
        log.error("Network/HTTP error: %s", exc)
        sys.exit(EXIT_NETWORK_ERROR)
    except RuntimeError as exc:
        log.error("Validation error: %s", exc)
        sys.exit(EXIT_VALIDATION_ERROR)
    except Exception as exc:  # pragma: no cover — safety net
        log.error("Unexpected error: %s", exc, exc_info=True)
        sys.exit(EXIT_GENERIC_ERROR)


# ---------------------------- Argument parser -------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Logpoint Director Importer (v2)")
    parser.add_argument("--tenant", required=True, help="Tenant name")
    parser.add_argument(
        "--tenants-file",
        help="(Optional) Fallback if LP_TENANTS_FILE is not set in the environment",
    )
    parser.add_argument("--xlsx", required=True, help="Path to Excel configuration file")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode, no changes made")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Generate subcommands from the registry
    for spec in iter_specs():
        sp = subparsers.add_parser(spec.cli, help=spec.help)
        sp.set_defaults(func=cmd_import_generic, importer_key=spec.key)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
        return EXIT_OK
    except SystemExit as e:  # explicit exits above
        return int(e.code) if isinstance(e.code, int) else EXIT_GENERIC_ERROR
    except Exception as exc:  # pragma: no cover — safety net
        log.error("Fatal error: %s", exc, exc_info=True)
        return EXIT_GENERIC_ERROR


if __name__ == "__main__":  # pragma: no cover
    main()
