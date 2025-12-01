"""Generic transformer to validate required fields for a resource.

The list of required fields is taken from:

    profile.constraints["required_fields"]

If any of these fields is missing or empty for a given item, the item
is dropped from the pipeline (the transformer returns None).
"""

from __future__ import annotations

from typing import Any, Dict, List

from lp_sync.core.profiles import ResourceProfile
from lp_sync.transformers.base import BaseTransformer
from lp_sync.utils.logging import get_logger


class ValidateRequiredTransformer(BaseTransformer):
    """Ensure that required fields are present and non-empty."""

    def __init__(self) -> None:
        self._logger = get_logger(self.__class__.__name__)

    def run(
        self,
        item: Dict[str, Any],
        context: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        """Validate that the required fields are present for this item.

        Args:
            item: Configuration item representing desired state for a resource.
            context: Shared pipeline context. Must contain a "profile" entry.
            params: Transformer-specific parameters (unused here).

        Returns:
            The original item if validation passes, or None if the item must be
            skipped because required fields are missing.
        """
        profile = self._get_profile(context)
        if profile is None:
            # Without a profile we cannot know the required fields.
            # Fail safe: keep the item and log a warning.
            self._logger.warning(
                "No profile in context; skipping required field validation."
            )
            return item

        required_fields: List[str] = list(
            profile.constraints.get("required_fields", [])
        )
        if not required_fields:
            # Nothing to validate for this resource.
            return item

        missing: List[str] = []
        for field in required_fields:
            value = item.get(field)
            if value is None or value == "":
                missing.append(field)

        if missing:
            tenant = item.get("tenant")
            self._logger.warning(
                "Dropping item for resource '%s', tenant='%s': missing "
                "required fields: %s",
                profile.name,
                tenant,
                ", ".join(missing),
            )
            return None

        return item

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _get_profile(self, context: Dict[str, Any]) -> ResourceProfile | None:
        profile = context.get("profile")
        if isinstance(profile, ResourceProfile):
            return profile
        return None
