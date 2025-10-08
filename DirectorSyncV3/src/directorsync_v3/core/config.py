from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

import yaml


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


# ---------- Defaults ----------

_DEFAULT_FILES: Tuple[str, ...] = (
    "./directorsync.yml",
    os.path.expanduser("~/.config/directorsync/config.yml"),
    "/etc/directorsync/config.yml",
)

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


# ---------- Utilities ----------

def _deep_merge(base: Dict[str, Any], ext: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Deep-merge for dicts: maps merge recursively, lists/scalars override.
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


def _read_yaml_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Top-level YAML must be a mapping: {path}")
    return data


def _load_first_existing(files: Tuple[str, ...]) -> Dict[str, Any]:
    for p in files:
        if os.path.exists(p):
            return _read_yaml_file(p)
    return {}


def _env_to_dict(prefix: str = "DSYNC_") -> Dict[str, Any]:
    """
    Convert DSYNC_FOO__BAR=val to {"foo": {"bar": "val"}} (lowercased keys).
    """
    out: Dict[str, Any] = {}
    plen = len(prefix)
    for key, val in os.environ.items():
        if not key.startswith(prefix):
            continue
        path = key[plen:].lower().split("__")
        cursor = out
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[path[-1]] = val
    return out


def _interpolate_env(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Replace values like "${VAR}" with os.environ["VAR"] when present.
    """
    def repl(v: Any) -> Any:
        if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
            return os.environ.get(v[2:-1], "")
        return v

    def walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: walk(repl(v)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [walk(x) for x in obj]
        return repl(obj)

    return walk(cfg)


def _coerce_types(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal type coercion for booleans and integers in known keys.
    """
    def to_bool(x: Any) -> bool:
        return str(x).strip().lower() in {"1", "true", "yes", "y", "on"}

    def walk(obj: Any, key_path: Tuple[str, ...] = ()) -> Any:
        if isinstance(obj, dict):
            return {k: walk(v, key_path + (k,)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [walk(v, key_path) for v in obj]
        # heuristics by key
        if key_path[-1:] in [("verify_tls",), ("dry_run",)]:
            return to_bool(obj)
        if key_path[-1:] in [("timeout_sec",), ("retries",), ("concurrency",)]:
            try:
                return int(obj)
            except Exception:
                return obj
        return obj

    return walk(cfg)


def _validate(cfg: Dict[str, Any]) -> None:
    """
    Validate required fields when not in dry_run.
    """
    dry = bool(cfg.get("app", {}).get("dry_run", False))
    if dry:
        return
    missing = []
    if not cfg.get("director", {}).get("base_url"):
        missing.append("director.base_url")
    if not cfg.get("context", {}).get("tenant"):
        missing.append("context.tenant")
    if not cfg.get("context", {}).get("pool_uuid"):
        missing.append("context.pool_uuid")
    if missing:
        raise ValueError(
            "Missing required configuration for non-dry run: " + ", ".join(missing)
        )


# ---------- Public API ----------

def load_config(
    cli_overrides: Optional[Dict[str, Any]] = None,
    files: Tuple[str, ...] = _DEFAULT_FILES,
    env_prefix: str = "DSYNC_",
) -> AppConfig:
    """
    Build an AppConfig from (in precedence order):
      1) CLI overrides
      2) Environment variables (prefix DSYNC_, nested via __)
      3) YAML file (first existing)
      4) Built-in defaults

    Also performs:
      - ${ENV_VAR} interpolation
      - basic type coercion (bool/int)
      - validation of required fields when not in dry_run
    """
    # Load file first (low precedence)
    file_cfg = _load_first_existing(files)

    # Env overlay
    env_cfg = _env_to_dict(env_prefix)

    # Combine: defaults <- file <- env <- cli
    merged = _deep_merge(_DEFAULTS, file_cfg)
    merged = _deep_merge(merged, env_cfg)
    merged = _deep_merge(merged, cli_overrides or {})

    # Interpolate and coerce
    merged = _interpolate_env(merged)
    merged = _coerce_types(merged)

    # Validate
    _validate(merged)

    # Build typed object
    return AppConfig(
        app=AppSection(**merged.get("app", {})),
        director=DirectorSection(**merged.get("director", {})),
        profiles=ProfilesSection(**merged.get("profiles", {})),
        logging=LoggingSection(**merged.get("logging", {})),
        inputs=InputsSection(**merged.get("inputs", {})),
        context=ContextSection(**merged.get("context", {})),
    )
