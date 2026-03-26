"""Base classes and interfaces for transformers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseTransformer(ABC):
    """Abstract base class for all transformers."""

    @abstractmethod
    def run(
        self,
        item: Dict[str, Any],
        context: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        """Transform a single item.

        Args:
            item: The configuration item to transform.
            context: Shared context for the pipeline.
            params: Transformer-specific parameters.

        Returns:
            A modified item, or None to indicate that the item should be
            skipped for the remainder of the pipeline.
        """
        raise NotImplementedError
