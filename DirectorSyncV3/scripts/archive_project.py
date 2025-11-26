"""Utility script to create a ZIP archive of the project.

This tool can be used to bundle the current working tree into a single ZIP
file for sharing or backup purposes.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import zipfile
from pathlib import Path
from typing import NoReturn

from lp_sync.utils.logging import get_logger


LOGGER = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the archive tool."""
    parser = argparse.ArgumentParser(
        description="Create a ZIP archive of the lp_sync_v3 project."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Project root directory (default: parent of this script).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output ZIP path (default: auto-named in the root directory).",
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
        timestamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        output = root.parent / f"{root.name}-{timestamp}.zip"

    LOGGER.info("Creating archive from %s to %s", root, output)

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in root.rglob("*"):
            if path.is_file():
                arcname = path.relative_to(root.parent)
                LOGGER.debug("Adding %s as %s", path, arcname)
                zf.write(path, arcname)

    LOGGER.info("Archive created: %s", output)
    return output


def main() -> NoReturn:
    """Entry point for the archive tool."""
    parser = build_parser()
    args = parser.parse_args()
    archive_path = create_archive(args.root, args.output)
    print(f"Archive created at: {archive_path}")
    raise SystemExit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
