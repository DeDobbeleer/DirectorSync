from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping

import logging

from .profiles import ResourceProfile

logger = logging.getLogger(__name__)


def validate_required_fields(
    profile: ResourceProfile,
    items: Iterable[Mapping[str, Any]],
) -> List[Mapping[str, Any]]:
    """
    Generic required field validation based on
    profile.constraints.required_fields.

    Raises ValueError if any required field is missing or empty.
    """
    required = list(profile.constraints.get("required_fields", []))
    if not required:
        return list(items)

    result: List[Mapping[str, Any]] = []
    for item in items:
        missing = [field for field in required if not _has_value(item, field)]
        if missing:
            tenant = item.get("tenant")
            raise ValueError(
                f"Resource '{profile.name}' item for tenant='{tenant}' is "
                f"missing required fields: {', '.join(missing)}"
            )
        result.append(item)

    return result


def _has_value(item: Mapping[str, Any], field: str) -> bool:
    """
    Support simple fields only (no nested arrays). This is sufficient
    for our current required_fields use cases.
    """
    return field in item and item[field] not in (None, "")


def validate_references(
    profile: ResourceProfile,
    items: Iterable[Mapping[str, Any]],
    cache_by_resource: Mapping[str, Iterable[Mapping[str, Any]]],
) -> List[Mapping[str, Any]]:
    """
    Generic reference validation based on profile.constraints.references.

    Each reference entry must have:

      - source_field: "catch_all" or "rules[].repo"
      - target_resource: "repos"
      - target_field: "name"

    The function uses cache_by_resource[target_resource] to build
    the set of allowed values for target_field.
    """
    refs = profile.constraints.get("references", [])
    if not refs:
        return list(items)

    result: List[Mapping[str, Any]] = []
    for item in items:
        for ref in refs:
            src = str(ref["source_field"])
            target_res = str(ref["target_resource"])
            target_field = str(ref["target_field"])

            allowed_values = _build_allowed_values(
                target_res, target_field, cache_by_resource
            )

            # Simple field: "catch_all"
            if "[]" not in src:
                value = item.get(src)
                _check_single_reference(
                    profile, src, value, target_res, target_field, allowed_values
                )
                continue

            # Array field: "rules[].repo"
            prefix, _, sub_field = src.partition("[].")
            array = item.get(prefix, []) or []
            for elem in array:
                value = elem.get(sub_field)
                _check_single_reference(
                    profile,
                    f"{prefix}[].{sub_field}",
                    value,
                    target_res,
                    target_field,
                    allowed_values,
                )

        result.append(item)

    return result


def _build_allowed_values(
    target_res: str,
    target_field: str,
    cache_by_resource: Mapping[str, Iterable[Mapping[str, Any]]],
) -> set[Any]:
    return {
        target[target_field]
        for target in cache_by_resource.get(target_res, [])
        if target_field in target and target[target_field] is not None
    }


def _check_single_reference(
    profile: ResourceProfile,
    src_field: str,
    value: Any,
    target_res: str,
    target_field: str,
    allowed_values: set[Any],
) -> None:
    if value and value not in allowed_values:
        raise ValueError(
            f"Resource '{profile.name}' invalid: field '{src_field}' "
            f"references non-existent {target_res}.{target_field}='{value}'"
        )
