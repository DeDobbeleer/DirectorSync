"""
Resolver cache primitives.

Importers can store API results by (pool_uuid, node_id, resource) to avoid
re-fetching data repeatedly within a single run.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple


class ResolverCache:
    """A tiny in-memory cache keyed by (pool_uuid, node_id, resource)."""
    def __init__(self) -> None:
        self._cache: Dict[Tuple[str, str, str], Any] = {}

    def get(self, pool_uuid: str, node_id: str, resource: str):
        """Return a cached value or None."""
        return self._cache.get((pool_uuid, node_id, resource))

    def set(self, pool_uuid: str, node_id: str, resource: str, value: Any) -> None:
        """Store a value under the composite cache key."""
        self._cache[(pool_uuid, node_id, resource)] = value


# lp_tenant_importer_v2/utils/resolvers.py
from __future__ import annotations

"""
Resolution helpers and lightweight caches for DirectorSync v2.

This module centralizes normalization/resolution utilities reused across
importers (Alert Rules, Normalization/Processing Policies, etc.).

Key exported helpers:
- normalize_repo_list_for_tenant(): normalize a list of repo names into the
  fully qualified "<ip>:<port>/<repo>" form expected by the Director API.

Design notes:
- Pandas is optional at runtime. When available, it is used to read an
  optional "Repo" mapping sheet from the XLSX to translate raw names.
- The function is intentionally tolerant and logs warnings instead of raising
  hard errors for non-blocking issues (unknown repo names, pre-qualified
  inputs, empty cells).
"""

import logging
import re
from collections import OrderedDict
from typing import Iterable, List, Optional, Sequence, Tuple, Union

try:
    import pandas as pd  # type: ignore
except Exception:  # pragma: no cover - optional import
    pd = None

logger = logging.getLogger(__name__)

# Matches "A.B.C.D:PORT/" at the beginning (simple/safe check).
_QUALIFIED_REPO_RE = re.compile(r"^\s*\d{1,3}(?:\.\d{1,3}){3}:\d+/", re.ASCII)


# --------------------------------------------------------------------------- #
# Generic small helpers
# --------------------------------------------------------------------------- #
def _as_list(values: Union[str, Sequence[str], None]) -> List[str]:
    """Coerce a cell or a sequence into a clean list of strings.

    Examples
    --------
    None -> []
    "a,b , c" -> ["a", "b", "c"]
    ["a", "b"] -> ["a", "b"]
    """
    if values is None:
        return []
    if isinstance(values, str):
        parts = re.split(r"[;,]", values)
        return [p.strip() for p in parts if p and p.strip()]
    return [str(v).strip() for v in values if str(v).strip()]


def _unique_preserve_order(items: Iterable[str]) -> List[str]:
    """Return a deduplicated list while preserving first-seen order."""
    return list(OrderedDict.fromkeys(items).keys())


def _get_attr(obj, *names: str, default=None):
    """Best-effort getter supporting dict-like and attribute-like access."""
    for name in names:
        # dict-like
        try:
            if isinstance(obj, dict) and name in obj:
                return obj[name]
        except Exception:
            pass
        # attribute-like
        try:
            if hasattr(obj, name):
                return getattr(obj, name)
        except Exception:
            pass
    return default


def _derive_tenant_endpoint(tenant_ctx) -> Optional[str]:
    """Derive '<ip>:<port>' from various possible tenant context shapes.

    Supported conventions (any of these may exist):
    - dict-like: {"ip": "...", "port": 1234} or {"ingest_host": "...", "ingest_port": 1234}
    - object-like attributes: .ip/.port or .ingest_host/.ingest_port
    - method hook: .get_endpoint() -> "ip:port"
    """
    # Callable hook (highest priority if present)
    try:
        if hasattr(tenant_ctx, "get_endpoint") and callable(tenant_ctx.get_endpoint):
            ep = tenant_ctx.get_endpoint()
            if isinstance(ep, str) and ":" in ep:
                return ep.strip()
    except Exception:  # pragma: no cover - defensive
        logger.debug("tenant_ctx.get_endpoint() failed", exc_info=True)

    # Attribute/dict fallbacks
    host = _get_attr(tenant_ctx, "ingest_host", "ip", default=None)
    port = _get_attr(tenant_ctx, "ingest_port", "port", default=None)

    if host and port:
        try:
            return f"{str(host).strip()}:{int(port)}"
        except Exception:  # pragma: no cover - defensive
            logger.debug("Failed to build endpoint from host/port", exc_info=True)

    return None


def _load_repo_mapping_from_xlsx(xlsx_reader, repo_map_df) -> Optional[pd.DataFrame]:
    """Obtain a mapping DataFrame with columns ['name', 'cleaned_repo_name'].

    Priority:
    1) repo_map_df if already provided and valid
    2) xlsx_reader if it can read a sheet named 'Repo'

    Returns
    -------
    DataFrame or None
    """
    if pd is None:
        return None

    # Pre-provided mapping
    if repo_map_df is not None:
        try:
            cols = {c.lower(): c for c in repo_map_df.columns}
            name_col = cols.get("name")
            cleaned_col = cols.get("cleaned_repo_name") or cols.get("cleaned")
            if name_col and cleaned_col:
                df = repo_map_df[[name_col, cleaned_col]].copy()
                df.columns = ["name", "cleaned_repo_name"]
                return df
        except Exception:  # pragma: no cover
            logger.debug("Provided repo_map_df invalid", exc_info=True)

    # Load from XLSX reader
    if xlsx_reader is not None:
        try:
            # The reader is expected to offer a pandas-like interface
            df = xlsx_reader.read_sheet("Repo")  # user-facing sheet name
            if df is None:
                return None
            cols = {c.lower(): c for c in df.columns}
            name_col = cols.get("name")
            cleaned_col = cols.get("cleaned_repo_name") or cols.get("cleaned")
            if not (name_col and cleaned_col):
                logger.warning(
                    "Repo sheet present but missing required columns 'name' and "
                    "'cleaned_repo_name' (or 'cleaned'); mapping will be skipped."
                )
                return None
            df = df[[name_col, cleaned_col]].copy()
            df.columns = ["name", "cleaned_repo_name"]
            return df
        except Exception:  # pragma: no cover
            logger.debug("Failed reading 'Repo' sheet from xlsx_reader", exc_info=True)

    return None


def _apply_repo_mapping(raw_names: List[str], repo_df: pd.DataFrame) -> Tuple[List[str], List[str]]:
    """Map raw repo names via DataFrame. Returns (mapped, unknown).

    Unknown names are returned for logging at WARNING level.
    """
    if pd is None or repo_df is None:
        return raw_names, []

    # Build a simple dict for fast lookups
    mapping = {}
    try:
        for _, row in repo_df.iterrows():
            src = str(row["name"]).strip()
            dst = str(row["cleaned_repo_name"]).strip()
            if src and dst:
                mapping[src] = dst
    except Exception:  # pragma: no cover
        logger.debug("Iterating repo_df failed", exc_info=True)
        return raw_names, []

    mapped, unknown = [], []
    for name in raw_names:
        if name in mapping:
            mapped.append(mapping[name])
        else:
            unknown.append(name)
            mapped.append(name)  # keep original if unknown (tolerant)
    return mapped, unknown


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def normalize_repo_list_for_tenant(
    repos: Union[str, Sequence[str], None],
    *,
    tenant_ctx,
    use_tenant_ip: bool = True,
    enable_repo_sheet_mapping: bool = True,
    xlsx_reader=None,
    repo_map_df=None,
) -> List[str]:
    """Normalize repository names for AlertRules (and others) to API form.

    Parameters
    ----------
    repos
        Raw repos coming from XLSX (string with separators, or list).
    tenant_ctx
        Context object/dict holding tenant endpoint info. See `_derive_tenant_endpoint`.
    use_tenant_ip
        If True, prefix each repo with '<ip>:<port>/' using tenant_ctx.
        If False, leave names as-is unless already qualified.
    enable_repo_sheet_mapping
        If True, attempt to map raw names using the "Repo" sheet or provided
        `repo_map_df` (columns: name, cleaned_repo_name).
    xlsx_reader
        Optional XLSX reader exposing read_sheet("Repo") -> pandas.DataFrame.
    repo_map_df
        Optional DataFrame with columns [name, cleaned_repo_name].

    Returns
    -------
    List[str]
        Fully normalized repo strings in the shape expected by the Director API.
        Examples:
            ["127.0.0.1:5504/_LogPointAlerts", "127.0.0.1:5504/_logpoint"]
    """
    raw_list = _unique_preserve_order(_as_list(repos))
    if not raw_list:
        logger.debug("normalize_repo_list_for_tenant: empty repo list from XLSX")
        return []

    logger.debug("normalize_repo_list_for_tenant: raw repos (xlsx) = %s", raw_list)

    # Optional mapping through "Repo" sheet
    if enable_repo_sheet_mapping:
        repo_df = _load_repo_mapping_from_xlsx(xlsx_reader, repo_map_df)
        if repo_df is not None:
            mapped, unknown = _apply_repo_mapping(raw_list, repo_df)
            if unknown:
                logger.warning(
                    "Some repo names not found in mapping sheet; keeping as-is: %s",
                    unknown,
                )
            raw_list = mapped
            logger.debug("normalize_repo_list_for_tenant: mapped repos = %s", raw_list)
        else:
            logger.debug("Repo mapping disabled or sheet not available; skipping.")

    # If a name is already fully qualified '<ip>:<port>/', keep it
    qualified = [r for r in raw_list if _QUALIFIED_REPO_RE.match(r)]
    if qualified:
        # If some are qualified and some are not, we still prefix only the unqualified
        logger.debug("Found pre-qualified repos (kept as-is): %s", qualified)

    if use_tenant_ip:
        endpoint = _derive_tenant_endpoint(tenant_ctx)
        if not endpoint:
            logger.warning(
                "Tenant endpoint could not be derived from tenant_ctx; "
                "repos will not be prefixed. (This is acceptable if repos "
                "are already qualified)."
            )
            endpoint = None
    else:
        endpoint = None

    normalized: List[str] = []
    for name in raw_list:
        name = name.strip()
        if not name:
            continue
        if _QUALIFIED_REPO_RE.match(name):
            normalized.append(name)
            continue
        if endpoint:
            normalized.append(f"{endpoint}/{name}")
        else:
            normalized.append(name)

    normalized = _unique_preserve_order(normalized)
    logger.debug("normalize_repo_list_for_tenant: final repos = %s", normalized)
    return normalized
