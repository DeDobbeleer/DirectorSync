"""Diff engine for DirectorSync V3.

This module computes the difference between desired and current state
for a given resource, based on comparison rules provided by the
ResourceProfile.

It is fully generic and resource-agnostic. It only knows about:
- desired items (list[dict])
- current items (list[dict])
- comparison configuration:

    comparison:
      identity_keys:
        - policy_name
      significant_fields:
        - catch_all
        - routing_criteria
      canonicalization:
        sort_arrays:
          - routing_criteria
        ignore_fields:
          - used_size

The diff produces PlannedAction objects with action types:
- create
- update
- delete
- noop
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Tuple

from lp_sync.utils.logging import get_logger


@dataclass
class PlannedAction:
    """Planned change for a resource item."""

    action: str  # create / update / delete / noop
    key: Tuple[Any, ...] | None
    desired: Dict[str, Any] | None
    current: Dict[str, Any] | None
    reason: str | None = None


class DiffEngine:
    """Generic diff computation based entirely on profile rules."""

    def __init__(self) -> None:
        self._logger = get_logger(self.__class__.__name__)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def diff(
        self,
        profile: Any,
        desired: List[Dict[str, Any]],
        current: List[Dict[str, Any]],
    ) -> List[PlannedAction]:
        """Compute planned actions between desired and current state.

        Args:
            profile: ResourceProfile instance providing comparison rules.
            desired: List of desired items (already validated & normalized).
            current: List of current items as returned by Director.

        Returns:
            A list of PlannedAction objects describing what should be done
            to reconcile current state with desired state.
        """
        comparison = self._get_comparison(profile)
        identity_keys: List[str] = list(
            comparison.get("identity_keys", []) or []
        )
        significant_fields: List[str] = list(
            comparison.get("significant_fields", []) or []
        )
        canonicalization: Dict[str, Any] = comparison.get(
            "canonicalization", {}
        ) or {}

        # Build maps keyed by identity tuple
        desired_map: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        current_map: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

        for item in desired:
            key = self._make_key(item, identity_keys)
            if key is None:
                self._logger.warning(
                    "Desired item missing identity keys %s; ignoring item: %r",
                    identity_keys,
                    item,
                )
                continue
            desired_map[key] = self._canonical(item, canonicalization)

        for item in current:
            key = self._make_key(item, identity_keys)
            if key is None:
                self._logger.warning(
                    "Current item missing identity keys %s; ignoring item: %r",
                    identity_keys,
                    item,
                )
                continue
            current_map[key] = self._canonical(item, canonicalization)

        actions: List[PlannedAction] = []

        # Pass 1: desired → current (create/update/noop)
        for key, d_item in desired_map.items():
            c_item = current_map.get(key)

            if c_item is None:
                actions.append(
                    PlannedAction(
                        action="create",
                        key=key,
                        desired=d_item,
                        current=None,
                        reason="Missing in current state",
                    )
                )
                continue

            if self._equal_on_significant(
                d_item, c_item, significant_fields
            ):
                actions.append(
                    PlannedAction(
                        action="noop",
                        key=key,
                        desired=d_item,
                        current=c_item,
                        reason="No significant differences",
                    )
                )
            else:
                actions.append(
                    PlannedAction(
                        action="update",
                        key=key,
                        desired=d_item,
                        current=c_item,
                        reason="Differences on significant fields",
                    )
                )

        # Pass 2: current → desired (delete)
        for key, c_item in current_map.items():
            if key not in desired_map:
                actions.append(
                    PlannedAction(
                        action="delete",
                        key=key,
                        desired=None,
                        current=c_item,
                        reason="Not present in desired state",
                    )
                )

        return actions

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _get_comparison(self, profile: Any) -> Mapping[str, Any]:
        """Extract comparison config from a profile-like object."""
        # Most likely the profile already exposes a mapping attribute
        comp = getattr(profile, "comparison", None)
        if isinstance(comp, Mapping):
            return comp

        # Fallback if profile stores raw YAML in .raw
        raw = getattr(profile, "raw", None)
        if isinstance(raw, Mapping):
            raw_comp = raw.get("comparison")
            if isinstance(raw_comp, Mapping):
                return raw_comp

        # Last resort: empty mapping
        return {}

    def _make_key(
        self,
        item: Dict[str, Any],
        identity_keys: List[str],
    ) -> Tuple[Any, ...] | None:
        """Build an identity tuple from the configured identity_keys.

        If any identity key is missing, returns None.
        """
        if not identity_keys:
            # No identity keys configured, we cannot compute a stable key.
            return None

        values: List[Any] = []
        for field in identity_keys:
            if field not in item:
                return None
            values.append(item.get(field))
        return tuple(values)

    def _canonical(
        self,
        item: Dict[str, Any],
        canonicalization: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Apply canonicalization rules (ignore_fields, sort_arrays)."""
        out: Dict[str, Any] = dict(item)  # shallow copy

        ignore_fields = canonicalization.get("ignore_fields", []) or []
        for field in ignore_fields:
            out.pop(field, None)

        sort_arrays = canonicalization.get("sort_arrays", []) or []
        for field in sort_arrays:
            value = out.get(field)
            if isinstance(value, list):
                try:
                    # Sort based on string representation to be generic
                    out[field] = sorted(value, key=lambda x: str(x))
                except Exception:
                    self._logger.warning(
                        "Could not sort array field '%s' during canonicalization.",
                        field,
                    )

        return out

    def _equal_on_significant(
        self,
        a: Dict[str, Any],
        b: Dict[str, Any],
        significant_fields: List[str],
    ) -> bool:
        """Compare only the significant fields between two items."""
        if not significant_fields:
            # If no significant fields are configured, treat as equal.
            return True

        for field in significant_fields:
            if a.get(field) != b.get(field):
                return False
        return True
