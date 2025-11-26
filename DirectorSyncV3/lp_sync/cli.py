"""Command-line entry point for the lp_sync V3 project.

The CLI is intentionally minimal at this stage and will be extended as the
synchronization engine matures.
"""

from __future__ import annotations

import argparse
import logging
from typing import NoReturn

from . import __version__


LOGGER = logging.getLogger(__name__)


def configure_logging(verbosity: int) -> None:
    """Configure basic logging for the CLI.

    Args:
        verbosity: Verbosity level, typically 0 or 1.
    """
    level = logging.DEBUG if verbosity > 0 else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    LOGGER.debug("Logging configured with level %s", logging.getLevelName(level))


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="lp-sync",
        description="DirectorSync V3 generic synchronization tool.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"lp-sync {__version__}",
        help="Show program version and exit.",
    )
    # Subcommands will be added in later iterations.
    return parser


def main() -> NoReturn:
    """Main entry point for the lp-sync CLI."""
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)
    LOGGER.info("lp-sync CLI started (skeleton).")
    LOGGER.info("No subcommands are implemented yet.")
    parser.print_help()
    raise SystemExit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
