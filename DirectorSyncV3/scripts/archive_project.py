#!/usr/bin/env python
"""
Utility script to create a ZIP archive of the project.

This tool can be used to bundle the current working tree into a single ZIP
file for sharing or backup purposes.

It is intentionally self-contained and does not depend on the lp_sync
package, so it can be executed directly:

    python scripts/archive_project.py

The default root directory is the parent of this script, which is expected
to be the project root (e.g. DirectorSyncV3).
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import zipfile
from pathlib import Path
from typing import NoReturn


LOGGER = logging.getLogger("archive_project")


def configure_logging(verbosity: int) -> None:
    """Configure logging for the script.

    Args:
        verbosity: Verbosity level, where 0 is INFO and >=1 is DEBUG.
    """
    level = logging.DEBUG if verbosity > 0 else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    LOGGER.debug("Logging configured with level %s", logging.getLevelName(level))


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the archive tool.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="Create a ZIP archive of the DirectorSyncV3 project.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help=(
            "Project root directory to archive "
            "(default: parent of this script)."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output ZIP file path. "
            "If not provided, a timestamped name will be generated "
            "in the parent directory of the root."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times).",
    )
    return parser


def create_archive(root: Path, output: Path | None = None) -> Path:
    """Create a ZIP archive of the given root directory.

    Args:
        root: Project root directory to archive.
        output: Optional destination file path.

    Returns:
        The path to the created ZIP archive.

    Raises:
        FileNotFoundError: If the root directory does not exist.
    """
    if not root.exists():
        raise FileNotFoundError(f"Root directory does not exist: {root}")

    if output is None:
        timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        output = root.parent / f"{root.name}-{timestamp}.zip"

    LOGGER.info("Creating archive from %s to %s", root, output)

    # Store paths relative to the parent of the root directory so that
    # the archive contains the root directory name at the top level.
    base = root.parent

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in root.rglob("*"):
            if path.is_file():
                arcname = path.relative_to(base)
                LOGGER.debug("Adding %s as %s", path, arcname)
                zf.write(path, arcname)

    LOGGER.info("Archive created: %s", output)
    return output


def main() -> NoReturn:
    """Entry point for the archive tool."""
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)

    archive_path = create_archive(args.root, args.output)
    print(f"Archive created at: {archive_path}")
    raise SystemExit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
