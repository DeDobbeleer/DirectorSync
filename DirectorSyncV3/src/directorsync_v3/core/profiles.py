"""
Profile loader and runtime helpers for DirectorSync v3 (Step 4).

Features (MVP):
- Load YAML profiles with optional inheritance via `extends`.
- Transform whitelist for mapping fields (deterministic, side-effect free).
- Payload templating with ${placeholders}.
- Diff normalization (lists-as-sets, ignore fields).
- Simple prechecks (non_empty, must_exist_many, unique_in_sheet advisory).

Out of scope (later steps):
- Dependency resolution (`resolve` inventories).
- Hooks execution.
- HTTP/Director client interactions.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass
from string import Template
from typing import Any, Dict, Iterable, List, Optional, Tuple
import importlib

import yaml


# =========================
# Exceptions
# =========================

class ProfileError(Exception):
    """Base error for profile-related issues."""


class ProfileValidationError(ProfileError):
    """Raised when a profile is structurally invalid."""


class TransformError(ProfileError):
    """Raised when a transform fails or is unknown."""


# =========================
# Transform registry (allow-list)
# =========================

def t_norm_str(value: Any, **_: Any) -> str:
    """Trim and collapse whitespace; preserve case."""
    return re.sub(r"\s+", " ", str(value or "")).strip()


def t_split(value: Any, sep: str = ";", **_: Any) -> List[str]:
    """Split a scalar string into a list by separator; trims pieces; drops empties."""
    s = str(value or "")
    return [p.strip() for p in s.split(sep) if p.strip()]


def t_uniq(value: Any, **_: Any) -> List[Any]:
    """Remove duplicates while keeping the first occurrence."""
    if value is None:
        return []
    items = list(value) if isinstance(value, (list, tuple)) else [value]
    return list(dict.fromkeys(items))


def t_sort(value: Any, **_: Any) -> List[Any]:
    """Lexically sort a sequence; returns [] for None."""
    if value is None:
        return []
    try:
        return sorted(list(value))
    except Exception as exc:
        raise TransformError(f"Cannot sort value: {value!r}") from exc


def t_csv(value: Any, sep: str = ",", **_: Any) -> str:
    """Join a list into a string with a separator; coerce scalars to str."""
    if isinstance(value, (list, tuple)):
        return sep.join(map(str, value))
    return str(value or "")


def t_to_bool(value: Any, **_: Any) -> bool:
    """Coerce common truthy strings to boolean."""
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def t_to_int(value: Any, **_: Any) -> int:
    """Strict integer conversion (raises on invalid)."""
    s = str(value).strip()
    if not s or not s.lstrip("-").isdigit():
        raise TransformError(f"Cannot convert to int: {value!r}")
    return int(s)


TRANSFORM_REGISTRY = {
    "norm_str": t_norm_str,
    "split": t_split,
    "uniq": t_uniq,
    "sort": t_sort,
    "csv": t_csv,
    "to_bool": t_to_bool,
    "to_int": t_to_int,
}

# =========================
# Resolve & hook types
# =========================

InventoryProvider = Any  # callable: (name: str) -> list[dict]
HookFunc = Any           # callable signature varies per hook (documented below)

# =========================
# Profile Runtime
# =========================

@dataclass
class ResourceProfile:
    """Typed wrapper around a validated profile configuration."""

    name: str
    cfg: Dict[str, Any]

    # ----- Identity -----
    @property
    def id_field(self) -> str:
        return self.cfg.get("identity", {}).get("id_field", "id")

    @property
    def name_field(self) -> str:
        return self.cfg.get("identity", {}).get("name_field", "name")

    @property
    def natural_key(self) -> List[str]:
        return list(self.cfg.get("identity", {}).get("natural_key", [self.name_field]))

    # ----- Mapping -----
    def map_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map a raw input row (header->value) into logical fields based on xlsx.mapping.
        Supports either `col` or `expr`, plus an optional `transform` list.
        """
        xlsx = self.cfg.get("xlsx", {})
        mapping = xlsx.get("mapping")
        if not isinstance(mapping, dict) or not mapping:
            raise ProfileValidationError(f"Profile '{self.name}' missing xlsx.mapping")

        out: Dict[str, Any] = {}
        for logical, spec in mapping.items():
            if not isinstance(spec, dict):
                raise ProfileValidationError(
                    f"Profile '{self.name}' mapping for '{logical}' must be a map"
                )
            has_col = "col" in spec
            has_expr = "expr" in spec
            if has_col == has_expr:
                # either both or neither present
                raise ProfileValidationError(
                    f"Profile '{self.name}' mapping for '{logical}' must specify exactly one of 'col' or 'expr'"
                )
            if has_col:
                val = row.get(spec["col"])
            else:
                val = Template(str(spec["expr"])).safe_substitute(row)

            transforms = spec.get("transform", []) or []
            for t in transforms:
                if isinstance(t, str):
                    fn = TRANSFORM_REGISTRY.get(t)
                    params = {}
                elif isinstance(t, dict):
                    fn = TRANSFORM_REGISTRY.get(t.get("fn"))
                    params = {k: v for k, v in t.items() if k != "fn"}
                else:
                    fn = None
                    params = {}

                if not fn:
                    raise TransformError(f"Unknown transform for '{logical}': {t!r}")
                val = fn(val, **params)

            out[logical] = val
        return out

    # ----- Resolve -----
    def resolve(self, mapped: Dict[str, Any], provider: InventoryProvider) -> Dict[str, Any]:
        """
        Apply profile 'resolve' rules to enrich mapped fields by looking up IDs in inventories.

        Supported forms:
          resolve:
            fieldX:
              from: "inventory_name"
              lookup:      { by: "name", using: "${source_field}" }
            fieldY:
              from: "inventory_name"
              lookup_many: { by: "name", using: "${source_list}" }

        - Default returned field is 'id'. No network calls here; provider supplies in-memory inventories.
        - Failures do not raise; they yield None (lookup) or [] (lookup_many). Prechecks decide SKIP/ERROR.
        """
        rules = self.cfg.get("resolve") or {}
        if not rules:
            return mapped

        out = dict(mapped)
        for target, spec in rules.items():
            if not isinstance(spec, dict) or "from" not in spec or not any(
                k in spec for k in ("lookup", "lookup_many")
            ):
                raise ProfileValidationError(f"Invalid resolve spec for '{target}'")

            inv_name = spec["from"]
            inventory = provider(inv_name)  # must return list[dict]
            if not isinstance(inventory, list):
                raise ProfileValidationError(f"Inventory '{inv_name}' must be a list of objects")

            # Helper: single value substitute from mapped
            def _subst(expr: str) -> Any:
                # If expression is exactly "${field}", return the native value (list/int/bool/etc.)
                m = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", str(expr))
                if m:
                    return mapped.get(m.group(1))
                # Otherwise, regular string templating
                return Template(str(expr)).safe_substitute(mapped)

            # Helper: find by field, return 'id' by default
            def _find_one(by: str, value: Any, ret: str = "id") -> Any:
                for it in inventory:
                    if it.get(by) == value:
                        return it.get(ret)
                return None

            if "lookup" in spec:
                by = spec["lookup"].get("by")
                using = spec["lookup"].get("using")
                if by is None or using is None:
                    raise ProfileValidationError(f"Resolve.lookup must include 'by' and 'using' for '{target}'")
                needle = _subst(using)
                out[target] = _find_one(by, needle, "id")

            elif "lookup_many" in spec:
                by = spec["lookup_many"].get("by")
                using = spec["lookup_many"].get("using")
                if by is None or using is None:
                    raise ProfileValidationError(f"Resolve.lookup_many must include 'by' and 'using' for '{target}'")
                values = _subst(using)
                if isinstance(values, (list, tuple)):
                    needles = list(values)
                else:
                    needles = [values] if values not in (None, "", []) else []
                ids: List[Any] = []
                for v in needles:
                    fid = _find_one(by, v, "id")
                    if fid is not None:
                        ids.append(fid)
                out[target] = ids

        return out

    # ----- Prechecks -----
    def precheck(self, mapped: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Run simple declarative prechecks:
          - non_empty(field)
          - must_exist_many(field, min=1)
          - unique_in_sheet(field) [advisory; no-op here]
        Returns (ok, reason_if_not_ok).
        """
        checks = self.cfg.get("prechecks", []) or []
        for chk in checks:
            ctype = chk.get("type")
            field = chk.get("field")
            if ctype == "non_empty":
                if not mapped.get(field):
                    return False, f"Field '{field}' is empty"
            elif ctype == "must_exist_many":
                items = mapped.get(field) or []
                if not isinstance(items, (list, tuple)) or not items:
                    return False, f"Field '{field}' has no items"
                # optional threshold: require at least N items
                min_required = chk.get("min", 1)
                try:
                    min_required = int(min_required)
                except Exception:
                    min_required = 1
                if len(items) < max(1, min_required):
                    return False, f"Field '{field}' requires at least {max(1, min_required)} item(s)"
                if any(v in (None, "", []) for v in items):
                    return False, f"Field '{field}' contains empty item(s)"
            elif ctype == "unique_in_sheet":
                # advisory; typically enforced by input adapter
                continue
            else:
                raise ProfileValidationError(f"Unknown precheck type: {ctype}")
        return True, ""

    # ----- Payload templating -----
    def build_payload(self, mapped: Dict[str, Any]) -> Dict[str, Any]:
        """
        Render the 'payload' template with ${field} placeholders using mapped values.
        Works recursively on dicts and lists; leaves non-strings as-is.
        """
        payload_spec = self.cfg.get("payload")
        if payload_spec is None:
            raise ProfileValidationError(f"Profile '{self.name}' missing payload")

        def render(obj: Any) -> Any:

            if isinstance(obj, str):
                # If the whole string is exactly a single ${field}, preserve native type
                # (avoids turning lists/ints/bools into strings).
                m = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", obj)
                if m:
                    return mapped.get(m.group(1))
                return Template(obj).safe_substitute(mapped)

            if isinstance(obj, list):
                return [render(x) for x in obj]
            if isinstance(obj, dict):
                return {k: render(v) for k, v in obj.items()}
            return obj

        return render(payload_spec)

    # ----- Diff normalization -----
    def make_comparable(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a dict payload for comparison:
          - Convert configured list fields to sorted lists (set-like compare).
          - Drop ignored fields entirely.
        """
        obj = copy.deepcopy(obj)
        diff_cfg = self.cfg.get("diff", {}) or {}
        list_as_sets = set(diff_cfg.get("list_as_sets", []) or [])
        ignore_fields = set(diff_cfg.get("ignore_fields", []) or [])

        def normalize(value: Any, path: Tuple[str, ...]) -> Any:
            key = path[-1] if path else ""
            if key in ignore_fields:
                return None  # caller drops keys with None
            if isinstance(value, list) and key in list_as_sets:
                return sorted(value)
            if isinstance(value, dict):
                return {k: normalize(v, path + (k,)) for k, v in value.items()}
            return value

        normalized = {k: normalize(v, (k,)) for k, v in obj.items()}
        for k in list(normalized.keys()):
            if normalized[k] is None:
                normalized.pop(k, None)
        return normalized

    # ----- Natural key -----
    def key_tuple(self, mapped: Dict[str, Any]) -> Tuple[Any, ...]:
        """Return the tuple key based on `identity.natural_key`."""
        return tuple(mapped.get(k) for k in self.natural_key)


# =========================
# Loader with inheritance
# =========================

def _deep_merge(base: Dict[str, Any], ext: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-merge: dicts merge recursively; lists/scalars override."""
    result = copy.deepcopy(base)
    for k, v in ext.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)  # type: ignore[index]
        else:
            result[k] = copy.deepcopy(v)
    return result


class ProfileLoader:
    """
    Load profiles from disk, supporting `extends: "<parent>"` inheritance.

    Search order: the provided `search_paths`, checked in order for `<name>.yml`.
    """

    def __init__(self, search_paths: Optional[List[str]] = None) -> None:
        self.search_paths = search_paths or ["resources/profiles"]

    def _find_path(self, name: str) -> str:
        """Return the first existing '<search_path>/<name>.yml' or raise."""
        filename = f"{name}.yml"
        for base in self.search_paths:
            candidate = os.path.join(base, filename)
            if os.path.exists(candidate):
                return candidate
        raise ProfileError(f"Profile '{name}' not found in {self.search_paths}")

    def _read_yaml(self, path: str) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ProfileValidationError(f"Top-level YAML must be a mapping: {path}")
        return data

    def _load_recursive(self, name: str, stack: Optional[List[str]] = None) -> Dict[str, Any]:
        stack = stack or []
        if name in stack:
            cycle = " -> ".join(stack + [name])
            raise ProfileValidationError(f"Inheritance cycle detected: {cycle}")
        path = self._find_path(name)
        data = self._read_yaml(path)
        parent = data.get("extends")
        if parent:
            merged_parent = self._load_recursive(parent, stack + [name])
            data = _deep_merge(merged_parent, data)
        return data

    def load(self, name: str) -> ResourceProfile:
        """Load and validate a profile by name (without extension)."""
        data = self._load_recursive(name)

        # Minimal validation for this step
        for section in ("endpoint", "identity", "xlsx", "payload"):
            if section not in data:
                raise ProfileValidationError(f"Profile '{name}' missing required section: {section}")
        if "mapping" not in data.get("xlsx", {}):
            raise ProfileValidationError(f"Profile '{name}' missing xlsx.mapping")

        return ResourceProfile(name=name, cfg=data)
