"""Logging utilities for DirectorSync v2.

Centralized, dual-channel logging:
- Console handler: INFO/WARNING/ERROR to stderr (human-friendly).
- File handler: level driven by environment (.env), written under ./logs by default,
  with filename pattern: <Tenant>-<Action>-YYYY-MM-HH.log.

This module is idempotent: calling `setup_logging(...)` multiple times reconfigures
the root logger cleanly without duplicating handlers.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional
from datetime import datetime

# Optional .env loader; silently continue if not available
try:
    from dotenv import find_dotenv, load_dotenv  # type: ignore
except Exception:  # pragma: no cover - defensive import
    find_dotenv = None  # type: ignore
    load_dotenv = None  # type: ignore

# Default formats
DEF_CONSOLE_FORMAT = "%(asctime)s %(levelname)s %(name)s - %(message)s"
DEF_FILE_FORMAT = (
    "%(asctime)s %(levelname)s %(name)s "
    "[%(filename)s:%(lineno)d %(funcName)s] - %(message)s"
)


def _load_env() -> None:
    """Load environment variables from a .env file at repo root if present."""
    try:
        if find_dotenv and load_dotenv:
            env_path = find_dotenv(usecwd=True) or ""
            load_dotenv(env_path, override=True)
    except Exception:
        # Never fail logging initialization because .env loading had an issue.
        pass


def _resolve_file_level() -> int:
    """Resolve the numeric level for the *file* handler from environment.

    Precedence:
        1) LP_LOG_FILE_LEVEL
        2) LP_LOG_LEVEL (fallback for backward-compat)
        3) DEBUG (sane default for troubleshooting)
    """
    lvl_name = (
        os.getenv("LP_LOG_FILE_LEVEL")
        or os.getenv("LP_LOG_LEVEL")
        or "DEBUG"
    ).upper()
    return getattr(logging, lvl_name, logging.DEBUG)


def _ensure_logs_dir() -> Path:
    """Return the logs directory path, creating it if necessary."""
    base = os.getenv("LP_LOG_DIR") or "./logs"
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _build_log_filename(tenant: str, action: str) -> str:
    """Build log file name: <Tenant>-<Action>-YYYY-MM-HH.log

    Note: per requirement, the *day* component is intentionally omitted.
    """
    # Example: 2025-10-05 -> hour 05 => 2025-10-05 -> we keep YYYY-MM-HH
    ts = datetime.now().strftime("%Y-%m-%H")
    # Keep the given spelling and punctuation as-is
    return f"{tenant}-{action}-{ts}.log"


def setup_logging(
    level: Optional[str] = None,
    *,
    tenant: Optional[str] = None,
    action: Optional[str] = None,
) -> None:
    """Configure the root logger with console + optional file handlers.

    Args:
        level: (Optional) legacy/global level. Only used as a fallback for
               determining the *root* threshold; handler levels are managed
               independently (console/file).
        tenant: Tenant name for the log filename.
        action: CLI subcommand (e.g., 'import-repos') for the log filename.

    Behavior:
        - Console: fixed at INFO (thus includes WARNING/ERROR/CRITICAL).
        - File: level comes from `.env` (LP_LOG_FILE_LEVEL -> LP_LOG_LEVEL -> DEBUG).
        - Root level is set to the *minimum* of the two handler levels to avoid
          filtering out DEBUG logs needed by the file handler.
    """
    _load_env()
    logging.captureWarnings(True)

    # Resolve handler levels
    console_level = logging.INFO
    file_level = _resolve_file_level()

    # Root level must be the minimum so that no handler is starved by root filter
    root_level_name = (level or os.getenv("LP_LOG_LEVEL") or "DEBUG").upper()
    root_level_from_level = getattr(logging, root_level_name, logging.DEBUG)
    root_level = min(console_level, file_level, root_level_from_level)

    root = logging.getLogger()
    # Idempotent reconfiguration: purge existing handlers
    for h in list(root.handlers):
        root.removeHandler(h)

    # Console handler (stderr)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(logging.Formatter(DEF_CONSOLE_FORMAT))
    root.addHandler(console_handler)

    # File handler (if tenant & action provided)
    if tenant and action:
        logs_dir = _ensure_logs_dir()
        logfile = logs_dir / _build_log_filename(tenant, action)
        file_handler = logging.FileHandler(logfile, encoding="utf-8")
        file_handler.setLevel(file_level)
        file_handler.setFormatter(logging.Formatter(DEF_FILE_FORMAT))
        root.addHandler(file_handler)

    root.setLevel(root_level)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a child logger with the given name."""
    return logging.getLogger(name or "lp_v2")
