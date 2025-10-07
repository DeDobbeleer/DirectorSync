#!/usr/bin/env python3
"""Dump MITRE ATT&CK taxonomy from Logpoint Director API.

Enhancements:
- Supports loading configuration from a .env file (auto-detected or via --env-file).
- CLI args override .env; .env overrides process env.

This mini-script calls the Director endpoint `MitreAttacks/fetch` and exports
results to JSON (default), CSV, or XLSX.

Usage examples
--------------
1) JSON to stdout (auto-load .env if present):
    python mitre_attacks_dump.py --debug

   Example .env:
       BASE_URL=https://director.example.com
       POOL_UUID=a9fa7661c4f84b278b136e94a86b4ea2
       LOGPOINT_ID=506caf82de83054597d07c3c632a98ce
       LP_DIRECTOR_API_TOKEN=eyJhbGciOi... (redacted)
       NO_VERIFY=1  # optional

2) XLSX to file with explicit env file:
    python mitre_attacks_dump.py --env-file .env.local \
        --format xlsx --out mitre_attacks.xlsx

3) CSV to directory (arguments override .env):
    python mitre_attacks_dump.py --format csv --out ./mitre_csv \
        --base-url https://10.160.144.185 --no-verify \
        --pool-uuid a9fa7661c4f84b278b136e94a86b4ea2 \
        --logpoint-id 506caf82de83054597d07c3c632a98ce \
        --token-file token.txt

Notes
-----
- If --token / --token-file is omitted, the script reads LP_DIRECTOR_API_TOKEN
  (from .env or environment).
- Output tables are created from any top-level list of objects found in the
  API response payload (e.g., `attack_tags`, `attack_categories`).
- Logging is verbose with DEBUG for troubleshooting.
"""

from __future__ import annotations
import re

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

import requests

try:
    import pandas as pd  # type: ignore
except Exception:  # pragma: no cover - optional dependency until xlsx/csv requested
    pd = None  # Will validate at runtime if user selects csv/xlsx


LOG = logging.getLogger("mitre_dump")


# ------------------------- Utilities ------------------------- #

def _parse_bool(val: Optional[str], default: bool = False) -> bool:
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}


def load_env_file(path: Optional[Path]) -> Dict[str, str]:
    """Load KEY=VALUE lines from a .env file (simple parser, no external deps).

    - Ignores blank lines and lines starting with '#'.
    - Accepts values with optional quotes (single/double) and unescapes basic cases.
    - Returns a dict of loaded keys (without touching os.environ).
    """
    cfg: Dict[str, str] = {}
    if path is None:
        # Auto-detect: prefer .env in cwd if present
        auto = Path(".env")
        if not auto.exists():
            return cfg
        path = auto

    if not path.exists():
        LOG.debug(".env file not found: %s", path)
        return cfg

    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        LOG.warning("Failed to read .env file %s: %s", path, exc)
        return cfg

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        # Strip optional surrounding quotes
        if (value.startswith("\"") and value.endswith("\"")) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        cfg[key] = value

    # Don't log secrets; just counts and known keys presence
    masked = {k: ("***" if "TOKEN" in k or "PASSWORD" in k else v) for k, v in cfg.items()}
    LOG.info("Loaded .env from %s with keys: %s", path, ", ".join(sorted(masked.keys())))
    return cfg


# ------------------------- HTTP / API Layer ------------------------- #

def _build_url(base_url: str, pool_uuid: str, logpoint_id: str) -> str:
    base = base_url.rstrip("/")
    return f"{base}/configapi/{pool_uuid}/{logpoint_id}/MitreAttacks/fetch"


def fetch_mitre_attacks(
    base_url: str,
    pool_uuid: str,
    logpoint_id: str,
    token: str,
    verify: bool = True,
    timeout: float = 30.0,
) -> Mapping[str, Any]:
    """Call the Director API and return parsed JSON.

    Parameters
    ----------
    base_url : str
        Director base URL, e.g., https://director.example.com
    pool_uuid : str
        Pool UUID
    logpoint_id : str
        Logpoint identifier (UUID or search-head ID required by your API)
    token : str
        Bearer token (valid for ~8h, depending on configuration)
    verify : bool
        TLS verification (False to allow self-signed)
    timeout : float
        Total request timeout in seconds

    Returns
    -------
    Mapping[str, Any]
        Parsed JSON body from the API.
    """
    url = _build_url(base_url, pool_uuid, logpoint_id)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {"data": {}}

    LOG.info("FETCH MitreAttacks: POST %s", url)
    try:
        resp = requests.post(url, headers=headers, json=payload, verify=verify, timeout=timeout)
    except requests.RequestException as exc:  # network/SSL errors
        LOG.error("HTTP request failed: %s", exc)
        raise SystemExit(2) from exc

    LOG.debug("HTTP %s %s -> %s", resp.request.method, resp.url, resp.status_code)

    if resp.status_code >= 400:
        # Best-effort parse error body
        try:
            err = resp.json()
        except Exception:
            err = {"text": resp.text[:500]}
        LOG.error("API error: status=%s body=%s", resp.status_code, err)
        raise SystemExit(1)

    try:
        data = resp.json()
    except json.JSONDecodeError as exc:
        LOG.error("Invalid JSON in response: %s", exc)
        raise SystemExit(3) from exc

    LOG.debug("Response keys: %s", list(data.keys()))
    return data


# ------------------------- Extraction / Tabling ------------------------- #

def _is_list_of_dicts(value: Any) -> bool:
    return isinstance(value, list) and (not value or isinstance(value[0], dict))


def extract_tables(payload: Mapping[str, Any]) -> Dict[str, List[Mapping[str, Any]]]:
    """Extract top-level tables from an API payload.

    Strategy: look for any top-level key whose value is a list of objects.
    If the payload nests under a `data` key (common pattern), we prefer that level.

    Returns a mapping of table_name -> list of rows (dicts).
    """
    root = payload.get("data") if isinstance(payload.get("data"), Mapping) else payload

    tables: Dict[str, List[Mapping[str, Any]]] = {}
    if isinstance(root, Mapping):
        for key, val in root.items():  # type: ignore[assignment]
            if _is_list_of_dicts(val):
                name = str(key).strip()
                tables[name] = val  # type: ignore[assignment]

    # Heuristics: if no obvious list-of-dicts found, but a single list exists
    # (e.g., data: [ {...}, {...} ]), treat it as a generic table.
    if not tables and _is_list_of_dicts(root):  # type: ignore[arg-type]
        tables["items"] = root  # type: ignore[assignment]

    return tables


def _json_serializeable(val: Any) -> Any:
    """Ensure nested structures remain JSON-serializable for CSV/XLSX.

    - dict/list -> JSON string (stable sort of keys).
    - other primitives -> unchanged.
    """
    if isinstance(val, (list, dict)):
        try:
            return json.dumps(val, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(val)
    return val


def normalize_rows(rows: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize rows so every value is flat and JSON-serializable."""
    out: List[Dict[str, Any]] = []
    for row in rows:
        flat: Dict[str, Any] = {}
        for k, v in row.items():
            flat[str(k)] = _json_serializeable(v)
        out.append(flat)
    return out


# ------------------------- Writers ------------------------- #

def write_json(payload: Mapping[str, Any], out_path: Optional[Path]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if out_path:
        out_path.write_text(text, encoding="utf-8")
        LOG.info("Wrote JSON: %s", out_path)
    else:
        print(text)


def write_csv_tables(tables: Mapping[str, List[Mapping[str, Any]]], out: Path) -> None:
    if pd is None:
        raise SystemExit(
            "pandas is required for CSV/XLSX export. Install with: pip install pandas openpyxl"
        )

    # If `out` ends with .csv and there is exactly one table, write single CSV.
    # Otherwise, treat `out` as a directory and write one file per table.
    if out.suffix.lower() == ".csv" and len(tables) == 1:
        (table_name, rows), = tables.items()
        df = pd.DataFrame(normalize_rows(rows))
        df.to_csv(out, index=False)
        LOG.info("Wrote CSV: %s (%d rows)", out, len(df))
        return

    # Directory mode
    out_dir = out if out.is_dir() or not out.suffix else out.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    prefix = out.stem if out.suffix else out.name

    for name, rows in tables.items():
        safe = name.replace("/", "_").replace("\\", "_")
        csv_path = out_dir / f"{prefix}_{safe}.csv"
        df = pd.DataFrame(normalize_rows(rows))
        df.to_csv(csv_path, index=False)
        LOG.info("Wrote CSV: %s (%d rows)", csv_path, len(df))


def write_xlsx_tables(tables: Mapping[str, List[Mapping[str, Any]]], out_path: Path) -> None:
    if pd is None:
        raise SystemExit(
            "pandas is required for CSV/XLSX export. Install with: pip install pandas openpyxl"
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(out_path, engine="openpyxl") as xw:
        for name, rows in tables.items():
            sheet = name[:31] or "Sheet1"  # Excel sheet name limit
            df = pd.DataFrame(normalize_rows(rows))
            df.to_excel(xw, sheet_name=sheet, index=False)
    LOG.info("Wrote XLSX: %s (sheets=%s)", out_path, ", ".join(tables.keys()))


# ------------------------- CLI ------------------------- #

def _read_token(cli_token: Optional[str], token_file: Optional[Path], env: Mapping[str, str]) -> str:
    if cli_token:
        return cli_token
    if token_file and token_file.exists():
        return token_file.read_text(encoding="utf-8").strip()
    # Prefer .env-loaded env mapping first, then process env
    tok = env.get("LP_DIRECTOR_API_TOKEN") or env.get("TOKEN") or os.getenv("DIRECTOR_TOKEN") or os.getenv("TOKEN")
    if tok:
        return tok.strip()
    raise SystemExit("Missing token. Provide --token, --token-file, or set DIRECTOR_TOKEN in .env or environment.")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Dump MITRE ATT&CK taxonomy from Logpoint Director API",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # These are optional now; they can come from .env
    p.add_argument("--base-url", help="Director base URL (e.g., https://director.example.com)")
    p.add_argument("--pool-uuid", help="Director Pool UUID")
    p.add_argument("--logpoint-id", help="Logpoint identifier (UUID or instance id)")

    envgrp = p.add_argument_group("env")
    envgrp.add_argument("--env-file", type=Path, help="Path to a .env file (auto-detect .env if omitted)")

    auth = p.add_argument_group("auth")
    auth.add_argument("--token", help="Bearer token (overrides env LP_DIRECTOR_API_TOKEN)")
    auth.add_argument("--token-file", type=Path, help="Path to a file containing only the token")

    out = p.add_argument_group("output")
    out.add_argument("--format", choices=["json", "csv", "xlsx"], default="json", help="Output format")
    out.add_argument("--out", type=Path, help="Output file path (or directory for CSV multi-table). If omitted with JSON, prints to stdout.")

    net = p.add_argument_group("network")
    net.add_argument("--no-verify", action="store_true", help="Disable TLS verification (for self-signed)")
    net.add_argument("--timeout", type=float, default=30.0, help="Request timeout in seconds")

    p.add_argument("--debug", action="store_true", help="Enable DEBUG logging")
    return p


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s [%(filename)s:%(lineno)d %(funcName)s] - %(message)s",
    )


def _resolve_config(args: argparse.Namespace, envfile_vars: Mapping[str, str]) -> Tuple[str, str, str, bool]:
    """Resolve base_url, pool_uuid, logpoint_id, verify flag from CLI/ENV/.env.

    Precedence: CLI > envfile_vars > process env.
    Also supports aliases: BASE_URL/DIRECTOR_BASE_URL, POOL_UUID/DIRECTOR_POOL_UUID,
    LOGPOINT_ID/DIRECTOR_LOGPOINT_ID. TLS verify can be controlled by NO_VERIFY/VERIFY.
    """
    # Base URL
    base_url = (
        args.base_url
        or envfile_vars.get("BASE_URL")
        or envfile_vars.get("DIRECTOR_BASE_URL")
        or os.getenv("BASE_URL")
        or os.getenv("DIRECTOR_BASE_URL")
    )

    pool_uuid = (
        args.pool_uuid
        or envfile_vars.get("POOL_UUID")
        or envfile_vars.get("DIRECTOR_POOL_UUID")
        or os.getenv("POOL_UUID")
        or os.getenv("DIRECTOR_POOL_UUID")
    )

    logpoint_id = (
        args.logpoint_id
        or envfile_vars.get("LOGPOINT_ID")
        or envfile_vars.get("DIRECTOR_LOGPOINT_ID")
        or os.getenv("LOGPOINT_ID")
        or os.getenv("DIRECTOR_LOGPOINT_ID")
    )

    # TLS verify handling
    no_verify_env = envfile_vars.get("NO_VERIFY") or os.getenv("NO_VERIFY")
    verify_env = envfile_vars.get("VERIFY") or os.getenv("VERIFY")
    # CLI --no-verify has highest precedence; otherwise derive from env
    verify = not args.no_verify if hasattr(args, "no_verify") else True
    if not hasattr(args, "no_verify") or not args.no_verify:
        # Only consider env when CLI didn't force no-verify
        if verify_env is not None:
            verify = _parse_bool(verify_env, default=True)
        if no_verify_env is not None and _parse_bool(no_verify_env, default=False):
            verify = False

    missing = [name for name, val in {
        "BASE_URL": base_url,
        "POOL_UUID": pool_uuid,
        "LOGPOINT_ID": logpoint_id,
    }.items() if not val]

    if missing:
        raise SystemExit(
            "Missing required settings: " + ", ".join(missing) +
            ". Provide via CLI, .env, or environment."
        )

    return str(base_url), str(pool_uuid), str(logpoint_id), bool(verify)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    configure_logging(args.debug)

    # Load .env values (auto-detect if --env-file not provided)
    envfile_vars = load_env_file(args.env_file)

    # Resolve config values with proper precedence
    base_url, pool_uuid, logpoint_id, verify = _resolve_config(args, envfile_vars)

    token = _read_token(args.token, args.token_file, envfile_vars)

    payload = fetch_mitre_attacks(
        base_url=base_url,
        pool_uuid=pool_uuid,
        logpoint_id=logpoint_id,
        token=token,
        verify=verify,
        timeout=args.timeout,
    )

    if args.format == "json":
        write_json(payload, args.out)
        return 0

    tables = extract_tables(payload)
    if not tables:
        LOG.warning("No tabular data found in response; writing raw JSON instead.")
        # Fallback: write JSON
        if args.out is None:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0

    if args.format == "csv":
        if args.out is None:
            # default to cwd directory name
            args.out = Path("mitre_attacks_csv")
        write_csv_tables(tables, args.out)
        return 0

    if args.format == "xlsx":
        if args.out is None:
            args.out = Path("mitre_attacks.xlsx")
        write_xlsx_tables(tables, args.out)
        return 0

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
