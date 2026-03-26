"""Logging helpers for DirectorSync V3."""

from __future__ import annotations

import logging


def get_logger(name: str) -> logging.Logger:
    """Return a logger configured with a default format.

    Args:
        name: Name of the logger.

    Returns:
        A Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
