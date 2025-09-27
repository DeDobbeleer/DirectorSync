"""
Resource Profiles for DirectorSync v2 (declarative importer behavior).

This module ships a built-in profile for the Repos resource and helper
functions to:
  - parse XLSX rows (multi-value friendly, all strings)
  - build API payloads (POST/PUT) using only documented fields
  - canonicalize GET objects for order-insensitive equality
  - run pre-flight verifications (e.g., RepoPaths)

Rules:
- All parsed XLSX values are normalized to *strings*.
- Multi-value cells can use '|' or ',' separators.
- For Repos, API payload fields follow the Director 2.7 docs (whitelisted).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd


# ---------------------------- helpers (generic) ----------------------------

def _to_str(value: Any) -> str:
    """Normalize any scalar value to a clean string.

    - Empty/NaN -> ""
    - Numeric floats like 365.0 -> "365"
    - Other -> str(value)
    """
    if value is None:
        return ""
    # Pandas NA/NaN awareness
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    # Numeric-ish -> normalize integers to no decimal part
    if isinstance(value, (int,)):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return str(value)
    # Everything else
    return str(value)


def _split_multi(cell: Any, seps: Iterable[str]) -> List[str]:
    """Split a cell into multiple string values using any of the separators."""
    raw = _to_str(cell)
    if raw == "":
        return []
    # Replace all separators by the first one, then split once
    seps = list(seps) or ["|"]
    canon = raw
    for s in seps[1:]:
        canon = canon.replace(s, seps[0])
    items = [part.strip() for part in canon.split(seps[0])]
    return [itm for itm in items if itm != ""]


def _ensure_trailing_slash(path: str) -> str:
    s = _to_str(path).strip()
    return s if s.endswith("/") else s + "/"


def _canon_list_of_dict_unordered(items: List[Dict[str, Any]], key_fields: List[str], value_fields: List[str]) -> List[Tuple]:
    """Return a stable, order-insensitive canonical representation.

    Example: [{"path": "/a/", "retention": "365"}] with key_fields=["path"]
             becomes [("/a/", ("retention","365"))]
    """
    out: List[Tuple] = []
    for it in items or []:
        key = tuple(_to_str(it.get(k)) for k in key_fields)
        val = tuple((vf, _to_str(it.get(vf))) for vf in value_fields)
        out.append((key, val))
    out.sort(key=lambda x: x[0])
    return out


# ---------------------------- Repos profile ----------------------------

@dataclass(frozen=True)
class ReposProfile:
    """Declarative behavior for the Repos importer."""

    # XLSX parsing config
    sheet: str = "Repo"
    col_name: str = "name"
    col_name_aliases: Tuple[str, ...] = ("cleaned_repo_name",)
    col_storage_paths: str = "storage_paths"
    col_retention_days: str = "retention_days"
    col_repoha_li: str = "repoha_li"     # optional
    col_repoha_day: str = "repoha_day"   # optional
    split_on: Tuple[str, ...] = ("|", ",")

    # API whitelist (Director 2.7) for payloads
    api_resource: str = "Repos"
    api_post_fields: Tuple[str, ...] = ("name", "hiddenrepopath", "repoha")
    api_put_fields: Tuple[str, ...] = ("id", "hiddenrepopath", "repoha")

    # Subresource for verification
    sub_repo_paths: str = "RepoPaths"
    repo_paths_candidates: Tuple[str, ...] = ("0.paths", "paths")  # tolerate list-of-dict or dict

    # Comparison fields (NOOP vs UPDATE)
    compare_fields: Tuple[str, ...] = ("hiddenrepopath", "repoha")

    # ----------------- parsing & canonicalization -----------------

    def resolve_name(self, row: pd.Series) -> str:
        """Pick name from main column or aliases; return stripped string."""
        candidates = (self.col_name,) + self.col_name_aliases
        for c in candidates:
            if c in row and _to_str(row.get(c)).strip():
                return _to_str(row.get(c)).strip()
        return ""

    def parse_row(self, row: pd.Series) -> Dict[str, Any]:
        """Parse and normalize a single XLSX row to desired canonical fields.

        Output keys:
          - name: str
          - hiddenrepopath: List[Dict[str,str]] with {"path": "/...", "retention": "<days>"}
          - repoha: Optional[List[Dict[str,str]]] with {"ha_li": "...", "ha_day": "<days>"}
        """
        name = self.resolve_name(row)
        paths = [_ensure_trailing_slash(p) for p in _split_multi(row.get(self.col_storage_paths), self.split_on)]
        rets = [_to_str(r) for r in _split_multi(row.get(self.col_retention_days), self.split_on)]

        if len(paths) != len(rets):
            raise ValueError(f"Row '{name}': storage_paths and retention_days length mismatch ({len(paths)} vs {len(rets)})")

        hiddenrepopath = [{"path": p, "retention": _to_str(r)} for p, r in zip(paths, rets)]

        repoha: List[Dict[str, str]] = []
        if self.col_repoha_li in row or self.col_repoha_day in row:
            li = [_to_str(x) for x in _split_multi(row.get(self.col_repoha_li), self.split_on)]
            dy = [_to_str(x) for x in _split_multi(row.get(self.col_repoha_day), self.split_on)]
            if li or dy:
                # zip len must match if either provided
                if len(li) != len(dy):
                    raise ValueError(f"Row '{name}': repoha_li and repoha_day length mismatch ({len(li)} vs {len(dy)})")
                repoha = [{"ha_li": _to_str(a), "ha_day": _to_str(b)} for a, b in zip(li, dy)]

        return {
            "name": name,
            "hiddenrepopath": hiddenrepopath,
            "repoha": repoha or None,
        }

    def canon_for_compare(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Return a stable comparable subset for NOOP vs UPDATE decisions.

        - Convert list-of-dicts to order-insensitive tuples keyed by their stable key.
        - Keep everything as strings.
        """
        # Normalize hiddenrepopath (tolerate 'repopath' from GET)
        hrp = obj.get("hiddenrepopath")
        if not hrp and obj.get("repopath"):
            # map GET 'repopath' -> 'hiddenrepopath'
            hrp = [{"path": _ensure_trailing_slash(x.get("path")), "retention": _to_str(x.get("retention"))}
                   for x in (obj.get("repopath") or [])]

        if hrp:
            # Ensure canonical path formatting + string retention
            hrp = [{"path": _ensure_trailing_slash(x.get("path")), "retention": _to_str(x.get("retention"))} for x in hrp]

        rha = obj.get("repoha")
        if rha:
            rha = [{"ha_li": _to_str(x.get("ha_li")), "ha_day": _to_str(x.get("ha_day"))} for x in rha]

        return {
            "hiddenrepopath": _canon_list_of_dict_unordered(hrp or [], ["path"], ["retention"]),
            "repoha": _canon_list_of_dict_unordered(rha or [], ["ha_li"], ["ha_day"]),
        }

    # ----------------- payload builders -----------------

    def build_post_payload(self, desired: Dict[str, Any]) -> Dict[str, Any]:
        """Construct payload (POST) using only documented fields."""
        data: Dict[str, Any] = {
            "name": _to_str(desired.get("name")),
            "hiddenrepopath": [
                {"path": _to_str(x.get("path")), "retention": _to_str(x.get("retention"))}
                for x in (desired.get("hiddenrepopath") or [])
            ],
        }
        # Optional HA
        if desired.get("repoha"):
            data["repoha"] = [
                {"ha_li": _to_str(x.get("ha_li")), "ha_day": _to_str(x.get("ha_day"))}
                for x in (desired.get("repoha") or [])
            ]
        # Filter by whitelist fields
        return {k: v for k, v in data.items() if k in self.api_post_fields}

    def build_put_payload(self, existing_id: str, desired: Dict[str, Any]) -> Dict[str, Any]:
        """Construct payload (PUT) using only documented fields."""
        data: Dict[str, Any] = {
            "id": _to_str(existing_id),
            "hiddenrepopath": [
                {"path": _to_str(x.get("path")), "retention": _to_str(x.get("retention"))}
                for x in (desired.get("hiddenrepopath") or [])
            ],
        }
        if desired.get("repoha"):
            data["repoha"] = [
                {"ha_li": _to_str(x.get("ha_li")), "ha_day": _to_str(x.get("ha_day"))}
                for x in (desired.get("repoha") or [])
            ]
        return {k: v for k, v in data.items() if k in self.api_put_fields}

    # ----------------- verification -----------------

    def extract_repo_paths(self, raw: Any) -> List[str]:
        """Extract the list of valid RepoPaths from API response.

        Tolerates:
          - [{"paths": [...]}]
          - {"paths": [...]}
        """
        # candidate "0.paths"
        if isinstance(raw, list) and raw:
            first = raw[0]
            if isinstance(first, dict) and "paths" in first and isinstance(first["paths"], list):
                return [_ensure_trailing_slash(_to_str(p)) for p in first["paths"]]

        # candidate "paths"
        if isinstance(raw, dict) and "paths" in raw and isinstance(raw["paths"], list):
            return [_ensure_trailing_slash(_to_str(p)) for p in raw["paths"]]

        # fallback: empty
        return []

# Single instance for Repos
REPOS_PROFILE = ReposProfile()
