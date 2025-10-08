"""
Central logging for DirectorSync v3.

- Console handler: INFO..CRITICAL (no DEBUG)
- Timed rotated file handler: DEBUG (logs/app.log, daily rotation)
- Action-based file handler: DEBUG (logs/YYYY-MM-DD/<action>_<run_id>.log)
- Secret redaction: masks tokens/passwords in both msg and % args
- UTC timestamps in ISO-8601
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class MaskSecretsFilter(logging.Filter):
    """
    Redact common secrets (bearer tokens, API keys, passwords) from log records.
    """

    _patterns = [
        re.compile(r"(Authorization:\s*Bearer\s+)([A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"(api[_-]?key\s*[=:]\s*)([A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r"(password\s*[=:]\s*)([^,\s]+)", re.IGNORECASE),
        re.compile(r"(\btoken\s*[=:]\s*)([A-Za-z0-9._-]+)", re.IGNORECASE),
    ]

    @staticmethod
    def _mask(text: str) -> str:
        masked = text
        for pat in MaskSecretsFilter._patterns:
            masked = pat.sub(r"\1***REDACTED***", masked)
        return masked

    def filter(self, record: logging.LogRecord) -> bool:
        # Mask %-style dict args
        if record.args and isinstance(record.args, dict):
            record.args = {k: self._mask(str(v)) for k, v in record.args.items()}
        # Mask message string
        if isinstance(record.msg, str):
            record.msg = self._mask(record.msg)
        return True


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _utc_formatter(fmt: str) -> logging.Formatter:
    f = logging.Formatter(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%SZ")
    # Force UTC
    f.converter = time.gmtime  # type: ignore[attr-defined]
    return f


def build_logger(
    *,
    name: str = "ds",
    run_id: str,
    action: str,
    base_dir: str = "logs",
    console_level: str = "INFO",
    file_level: str = "DEBUG",
    extra: Optional[Dict[str, Any]] = None,
) -> logging.LoggerAdapter:
    """
    Configure and return a LoggerAdapter.

    Design:
      - A base logger `<name>` holds console + rotating file handlers (configured once).
      - A child logger `<name>.<action>.<run_id>` holds a per-run file handler.
      - Records propagate to base logger so they appear in all sinks.
    """
    mask = MaskSecretsFilter()

    # --- Base logger with console + rotating file (configured once) ---
    base = logging.getLogger(name)
    base.setLevel(logging.DEBUG)

    if not getattr(base, "_ds_configured", False):
        _ensure_dir(base_dir)
        fmt = (
            "%(asctime)s | %(levelname)-8s | %(name)s | "
            "run=%(run_id)s action=%(action)s tenant=%(tenant)s pool=%(pool)s profile=%(profile)s | "
            "%(message)s"
        )
        formatter = _utc_formatter(fmt)

        # Console
        sh = logging.StreamHandler()
        sh.setLevel(getattr(logging, console_level.upper(), logging.INFO))
        sh.setFormatter(formatter)
        sh.addFilter(mask)

        # Timed rotating file (daily)
        rh = logging.handlers.TimedRotatingFileHandler(
            os.path.join(base_dir, "app.log"),
            when="midnight",
            backupCount=14,
            encoding="utf-8",
        )
        rh.setLevel(getattr(logging, file_level.upper(), logging.DEBUG))
        rh.setFormatter(formatter)
        rh.addFilter(mask)

        base.addHandler(sh)
        base.addHandler(rh)
        base._ds_configured = True  # type: ignore[attr-defined]

    # --- Child logger with per-run action file (configured once per action+run) ---
    child_name = f"{name}.{action}.{run_id}"
    child = logging.getLogger(child_name)
    child.setLevel(logging.DEBUG)
    child.propagate = True

    if not getattr(child, "_ds_action_configured", False):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        dated_dir = os.path.join(base_dir, today)
        _ensure_dir(dated_dir)

        fmt = (
            "%(asctime)s | %(levelname)-8s | %(name)s | "
            "run=%(run_id)s action=%(action)s tenant=%(tenant)s pool=%(pool)s profile=%(profile)s | "
            "%(message)s"
        )
        formatter = _utc_formatter(fmt)

        fh = logging.FileHandler(
            os.path.join(dated_dir, f"{action}_{run_id}.log"),
            encoding="utf-8",
        )
        fh.setLevel(getattr(logging, file_level.upper(), logging.DEBUG))
        fh.setFormatter(formatter)
        fh.addFilter(mask)

        child.addHandler(fh)
        child._ds_action_configured = True  # type: ignore[attr-defined]

    # Adapter with contextual extras
    adapter = logging.LoggerAdapter(
        child,
        {
            "run_id": run_id,
            "action": action,
            "tenant": (extra or {}).get("tenant"),
            "pool": (extra or {}).get("pool"),
            "profile": (extra or {}).get("profile"),
        },
    )
    adapter.debug("Logger initialised")
    return adapter
