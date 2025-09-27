"""
Logging utilities for DirectorSync v2.
"""
import logging
import os
from typing import Optional


def setup_logging(level: str | None = None) -> None:
    """
    Configure root logger with concise format.
    Level can be overridden via LP_LOG_LEVEL env.
    """
    level_name = (level or os.getenv("LP_LOG_LEVEL") or "INFO").upper()
    numeric_level = getattr(logging, level_name, logging.INFO)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )


def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name or "lp_v2")
