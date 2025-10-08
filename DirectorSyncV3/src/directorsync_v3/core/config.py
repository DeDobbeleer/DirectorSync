"""
Minimal configuration loader for DirectorSync v3 (Step 1).

Scope (Step 1):
- Provide typed defaults.
- Merge *CLI overrides only* (no YAML files or ENV yet).
- Generate a stable run_id on first access.
- English-only docstrings; PEP-8 compliant; error-safe.

Next steps (Step 2):
- Add YAML file loading and DSYNC_* environment overrides.
- Add type coercion and strict/permissive validation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


# ---------- Typed sections ----------

@dataclass
class AppSection:
    run_id: Optional[str] = None
    dry_run: bool = False
    concurrency: int = 4


@dataclass
class DirectorSection:
    base_url: str = ""
    token: str = ""          # secret – never log in clear text
    verify_tls: bool = True
    timeout_sec: int = 30
    retries: int = 3


@dataclass
class ProfilesSection:
    search_paths: list[str] = field(default_factory=lambda: ["resources/profiles"])
    defaults: str = "_defaults"


@dataclass
class LoggingSection:
    base_dir: str = "logs"
    console_level: str = "INFO"   # INFO..CRITICAL
    file_level: str = "DEBUG"     # DEBUG..CRITICAL


@dataclass
class InputsSection:
    xlsx_path: str = "./data/import.xlsx"
    sheet_overrides: Dict[str, str] = field(default_factory=dict)


@dataclass
class ContextSection:
    tenant: str = ""
    pool_uuid: str = ""


@dataclass
class AppConfig:
    """Typed configuration object built by `load_config`."""
    app: AppSection
    director: DirectorSection
    profiles: ProfilesSection
    logging: LoggingSection
    inputs: InputsSection
    context: ContextSection

    @property
    def run_id(self) -> str:
        """
        Return a stable run identifier for this process.
        Generated lazily when first accessed if not provided.
        """
        if not self.app.run_id:
            self.app.run_id = uuid.uuid4().hex[:12]
        return self.app.run_id


# ---------- Defaults (Step 1) ----------

_DEFAULTS: Dict[str, Any] = {
    "app": {"run_id": None, "dry_run": False, "concurrency": 4},
    "director": {
        "base_url": "",
        "token": "",
        "verify_tls": True,
        "timeout_sec": 30,
        "retries": 3,
    },
    "profiles": {"search_paths": ["resources/profiles"], "defaults": "_defaults"},
    "logging": {"base_dir": "logs", "console_level": "INFO", "file_level": "DEBUG"},
    "inputs": {"xlsx_path": "./data/import.xlsx", "sheet_overrides": {}},
    "context": {"tenant": "", "pool_uuid": ""},
}


def _deep_merge(base: Dict[str, Any], ext: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Shallow-friendly deep merge for dicts: maps merge recursively, lists/scalars override.
    `ext` wins over `base`. Returns a new dict.
    """
    if not ext:
        return dict(base)
    out: Dict[str, Any] = dict(base)
    for k, v in ext.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(cli_overrides: Optional[Dict[str, Any]] = None) -> AppConfig:
    """
    Build an AppConfig from defaults + CLI overrides (Step 1 only).

    Precedence (current step):
      CLI overrides > built-in defaults

    Args:
        cli_overrides: A nested dict mirroring the config schema to override values
                       (e.g., {"context": {"tenant": "acme"}, "app": {"dry_run": True}}).

    Returns:
        AppConfig with typed sections and a lazily-generated run_id.
    """
    merged = _deep_merge(_DEFAULTS, cli_overrides or {})

    return AppConfig(
        app=AppSection(**merged.get("app", {})),
        director=DirectorSection(**merged.get("director", {})),
        profiles=ProfilesSection(**merged.get("profiles", {})),
        logging=LoggingSection(**merged.get("logging", {})),
        inputs=InputsSection(**merged.get("inputs", {})),
        context=ContextSection(**merged.get("context", {})),
    )
