from __future__ import annotations

import json
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

def _cfg_get(cfg: dict[str, Any], key: str, default: Any) -> Any:
    v = cfg.get(key, default)
    return v if v is not None else default

def _parse_collectors(value: Any, split_regex: str, left_of_colon: bool) -> list[str]:
    """
    Transform the 'distributed_collector' field value into a list of normalized IDs.
    - Accepts: None, Python list, JSON list as string, or plain string.
    - Splits using 'split_regex' (default comma/space/semicolon/pipe).
    - If 'left_of_colon' is True, keeps the left part of 'uuid:label'.
    - Deduplicates while preserving order.
    """
    if value is None:
        return []

    parts: list[str]
    if isinstance(value, list):
        parts = [str(x).strip() for x in value if str(x).strip()]
    elif isinstance(value, str):
        s = value.strip()
        if s.startswith("[") and s.endswith("]"):
            # E.g. '["id1", "id2"]'
            try:
                arr = json.loads(s)
                parts = [str(x).strip() for x in arr if str(x).strip()]
            except Exception:
                parts = re.split(split_regex, s)
        else:
            parts = re.split(split_regex, s)
        parts = [p for p in (str(x).strip() for x in parts) if p]
    else:
        parts = [str(value).strip()] if str(value).strip() else []

    if left_of_colon:
        out = []
        for p in parts:
            out.append(p.split(":", 1)[0].strip() if ":" in p else p)
        parts = out

    seen = set()
    uniq = []
    for p in parts:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq

def resolve_device_tenant_by_collectors(
    device_row: dict[str, Any],
    tenants: list[str],
    cfg: dict[str, Any]
) -> tuple[str | None, str]:
    """
    Returns (tenant_or_None, method):
      - method = "collector" if a unique collector mapping is found
      - method = "name" if no collector mapping → fallback by name
      - method = "none" if no info (caller decides)
    """
    collector_map: dict[str, str] = _cfg_get(cfg, "collector_to_tenant", {})
    if not collector_map:
        return None, "none"

    col_field = _cfg_get(cfg, "collector_field_column", "distributed_collector")
    split_rgx = _cfg_get(cfg, "collector_field_split_regex", r"[,;|\s]+")
    left_of_colon = bool(_cfg_get(cfg, "collector_value_left_of_colon", True))

    raw = device_row.get(col_field)
    collectors = _parse_collectors(raw, split_rgx, left_of_colon)
    if not collectors:
        return None, "none"

    mapped = [collector_map[c] for c in collectors if c in collector_map]
    mapped = [m for m in mapped if m in tenants]
    mapped_set = set(mapped)

    if len(mapped_set) == 1:
        return next(iter(mapped_set)), "collector"

    if len(mapped_set) > 1:
        log.warning(
            "Device '%s' collectors map to several tenants %s → fallback by name.",
            device_row.get("name") or device_row.get("device_id"),
            sorted(mapped_set),
        )
        return None, "name"

    return None, "name"

def determine_device_tenant(
    device_row: dict[str, Any],
    tenants: list[str],
    cfg: dict[str, Any],
    name_matcher,  # callback: (name: str, tenants: List[str]) -> str | None
    default_unassigned: str = "Unassigned",
) -> str:
    """
    Orchestration: first collector → tenant; otherwise fallback by name; otherwise 'Unassigned'.
    Sets device_row['_tenant_match_method'] = 'collector' / 'name' / 'none'.
    """
    t_collect, method = resolve_device_tenant_by_collectors(device_row, tenants, cfg)
    if t_collect:
        device_row["_tenant_match_method"] = "collector"
        return t_collect

    if method == "name":
        name = (device_row.get("name") or "").strip()
        if name:
            t_name = name_matcher(name, tenants)
            if t_name:
                device_row["_tenant_match_method"] = "name"
                return t_name

    device_row["_tenant_match_method"] = "none"
    return default_unassigned
