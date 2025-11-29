"""Transformer pipeline execution.

This module orchestrates running preprocess and postprocess transformers
defined in the resource profile.

Each step in the pipeline is defined in YAML and resolved dynamically to a
`BaseTransformer` subclass. The pipeline is fully generic and does not
contain any resource-specific logic.
"""

from __future__ import annotations

import importlib
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple, Type

from lp_sync.transformers.base import BaseTransformer
from lp_sync.utils.logging import get_logger


class TransformerPipeline:
    """Execute a sequence of transformers on items."""

    def __init__(self) -> None:
        self._logger = get_logger(self.__class__.__name__)
        self._cache: Dict[str, Type[BaseTransformer]] = {}

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def run(
        self,
        pipeline_config: Sequence[Any],
        items: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Run transformers defined in a pipeline on a list of items.

        A pipeline entry can be either:

        - a simple string:
            "generic.validate_required"

        - or a mapping:
            name: "generic.validate_required"
            params:
              fields: ["tenant", "name"]

        Args:
            pipeline_config: Sequence of transformer definitions from YAML.
            items: Items to transform.
            context: Shared context (tenant, resource name, profile, etc.).

        Returns:
            The transformed list of items. Items for which a transformer
            returned ``None`` are removed from the result.
        """
        steps = self._prepare_steps(pipeline_config)
        if not steps:
            return list(items)

        result: List[Dict[str, Any]] = []
        for item in items:
            current: Dict[str, Any] | None = item
            for step_name, transformer_cls, params in steps:
                if current is None:
                    break

                transformer = transformer_cls()
                try:
                    current = transformer.run(current, context, params)
                except Exception:
                    self._logger.exception(
                        "Transformer '%s' failed for item with context %r",
                        step_name,
                        context,
                    )
                    raise

            if current is not None:
                result.append(current)

        return result

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _prepare_steps(
        self,
        pipeline_config: Sequence[Any],
    ) -> List[Tuple[str, Type[BaseTransformer], Dict[str, Any]]]:
        """Normalise pipeline entries and resolve transformer classes."""
        steps: List[Tuple[str, Type[BaseTransformer], Dict[str, Any]]] = []

        for entry in pipeline_config or []:
            if isinstance(entry, str):
                name = entry
                params: Dict[str, Any] = {}
            elif isinstance(entry, Mapping):
                raw_name = entry.get("name")
                if not raw_name:
                    raise ValueError(
                        "Transformer entry is missing a 'name' key: "
                        f"{entry!r}"
                    )
                name = str(raw_name)
                params = dict(entry.get("params") or {})
            else:
                raise TypeError(
                    "Invalid transformer entry in pipeline_config: "
                    f"{entry!r}"
                )

            transformer_cls = self._resolve_transformer(name)
            steps.append((name, transformer_cls, params))

        return steps

    def _resolve_transformer(self, name: str) -> Type[BaseTransformer]:
        """Resolve a transformer name to a `BaseTransformer` subclass.

        Naming convention:

        - YAML name: "generic.validate_required"
          → module: "lp_sync.transformers.generic.validate_required"
          → class:  "ValidateRequiredTransformer"

        This keeps the mapping purely convention-based and avoids resource-
        specific code paths.
        """
        if name in self._cache:
            return self._cache[name]

        if "." not in name:
            # Fallback: assume "generic.<name>"
            namespace = "generic"
            short = name
        else:
            namespace, short = name.rsplit(".", 1)

        module_path = f"lp_sync.transformers.{namespace}.{short}"
        class_name = self._build_class_name(short)

        try:
            module = importlib.import_module(module_path)
        except ImportError as exc:  # pragma: no cover - defensive
            raise RuntimeError(
                f"Could not import transformer module '{module_path}' "
                f"for transformer '{name}'."
            ) from exc

        try:
            cls = getattr(module, class_name)
        except AttributeError as exc:  # pragma: no cover - defensive
            raise RuntimeError(
                f"Transformer class '{class_name}' not found in module "
                f"'{module_path}'."
            ) from exc

        if not issubclass(cls, BaseTransformer):
            raise TypeError(
                f"Resolved transformer '{class_name}' is not a "
                f"BaseTransformer subclass."
            )

        self._cache[name] = cls
        return cls

    @staticmethod
    def _build_class_name(short_name: str) -> str:
        """Convert a snake_case short name to a Transformer class name."""
        parts = short_name.split("_")
        camel = "".join(part.capitalize() for part in parts)
        return f"{camel}Transformer"
