"""Generic transformer to validate required fields."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from lp_sync.transformers.base import BaseTransformer


class ValidateRequiredTransformer(BaseTransformer):
    """Ensure that required fields are present and non-empty."""

    def run(
        self,
        item: Dict[str, Any],
        context: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        """Validate that the required fields are present.

        Args:
            item: The configuration item to validate.
            context: Context information (unused here but kept for symmetry).
            params: Parameters, must contain a "fields" iterable.

        Returns:
            The original item if validation passes.

        Raises:
            ValueError: If a required field is missing or empty.
        """
        fields: Iterable[str] = params.get("fields", [])
        missing: List[str] = []
        for field in fields:
            value = item.get(field)
            if value is None or value == "":
                missing.append(field)

        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        return item
