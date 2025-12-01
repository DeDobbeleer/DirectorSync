"""Generic transformer to build Director API payloads.

This transformer reads the `mapping` section from the resource profile:

    mapping:
      desired_to_api:
        policy_name: "policy_name"
        catch_all: "catch_all"
        active: "active"

      arrays:
        - source: "criteria_rows"
          dest: "routing_criteria"
          fields:
            repo: "repo"
            drop: "drop"
            type: "type"
            key: "key"
            value: "value"

The resulting payload is attached to the item under the "_payload" key:

    item["_payload"] = { ... }
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from lp_sync.core.profiles import ResourceProfile
from lp_sync.transformers.base import BaseTransformer
from lp_sync.utils.logging import get_logger


class BuildPayloadsTransformer(BaseTransformer):
    """Build API payloads based on profile.mapping."""

    def __init__(self) -> None:
        self._logger = get_logger(self.__class__.__name__)

    def run(
        self,
        item: Dict[str, Any],
        context: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        """Build an API payload for the given item.

        Args:
            item: Configuration item containing desired state fields.
            context: Pipeline context; must contain "profile".
            params: Transformer-specific parameters (unused here).

        Returns:
            The item with an additional "_payload" key containing the API
            payload dictionary.
        """
        profile = self._get_profile(context)
        if profile is None:
            self._logger.warning(
                "No profile in context; skipping payload construction."
            )
            return item

        mapping = profile.mapping or {}
        payload: Dict[str, Any] = {}

        # 1. Simple field mappings (desired_to_api)
        simple_map: Mapping[str, str] = mapping.get("desired_to_api", {})
        for src_field, dest_field in simple_map.items():
            if src_field in item and item[src_field] is not None:
                payload[dest_field] = item[src_field]

        # 2. Array mappings (arrays)
        arrays: List[Mapping[str, Any]] = mapping.get("arrays", []) or []
        for array_def in arrays:
            source_name = str(array_def.get("source", ""))
            dest_name = str(array_def.get("dest", ""))
            field_mappings: Mapping[str, str] = array_def.get("fields", {}) or {}

            if not source_name or not dest_name:
                self._logger.warning(
                    "Invalid array mapping in resource '%s': %r",
                    profile.name,
                    array_def,
                )
                continue

            collection = item.get(source_name)
            if not isinstance(collection, list):
                # Nothing to build for this array.
                continue

            array_values: List[Dict[str, Any]] = []
            for element in collection:
                if not isinstance(element, Mapping):
                    continue
                elem_payload: Dict[str, Any] = {}
                for src_field, dest_field in field_mappings.items():
                    if src_field in element and element[src_field] is not None:
                        elem_payload[dest_field] = element[src_field]
                array_values.append(elem_payload)

            payload[dest_name] = array_values

        item["_payload"] = payload
        return item

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _get_profile(self, context: Dict[str, Any]) -> ResourceProfile | None:
        profile = context.get("profile")
        if isinstance(profile, ResourceProfile):
            return profile
        return None
