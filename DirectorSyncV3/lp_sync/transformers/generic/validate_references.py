"""Generic transformer to validate cross-resource references.

Reference rules are defined in the resource profile under:

    constraints.references:

    - source_field: "catch_all"
      target_resource: "repos"
      target_field: "name"
      on_missing: "error"

    - source_field: "criteria_rows[].repo"
      target_resource: "repos"
      target_field: "name"
      on_missing: "skip_policy"

The transformer expects the context to provide a dependency index:

    context["dependency_index"] = {
        "repos": {"repoA", "repoB", ...},
        ...
    }

If a referenced value is not present in the corresponding set, the
transformer returns None (dropping the item), according to the
'on_missing' policy.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Set

from lp_sync.core.profiles import ResourceProfile
from lp_sync.transformers.base import BaseTransformer
from lp_sync.utils.logging import get_logger


class ValidateReferencesTransformer(BaseTransformer):
    """Validate cross-resource references based on profile constraints."""

    def __init__(self) -> None:
        self._logger = get_logger(self.__class__.__name__)

    def run(
        self,
        item: Dict[str, Any],
        context: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        """Validate that all configured references resolve.

        Args:
            item: Configuration item to validate.
            context: Pipeline context; must contain "profile" and may contain
                "dependency_index".
            params: Transformer-specific parameters (unused here).

        Returns:
            The original item if all references are valid, or None if an
            on_missing policy requires skipping the item.
        """
        profile = self._get_profile(context)
        if profile is None:
            self._logger.warning(
                "No profile in context; skipping reference validation."
            )
            return item

        constraints = profile.constraints
        references: Iterable[Dict[str, Any]] = constraints.get(
            "references", []
        )
        if not references:
            return item

        dep_index: Dict[str, Set[Any]] = context.get("dependency_index") or {}
        resource_name = profile.name
        tenant = item.get("tenant")

        for ref in references:
            src_field = str(ref.get("source_field", ""))
            target_res = str(ref.get("target_resource", ""))
            target_field = str(ref.get("target_field", ""))
            policy = str(ref.get("on_missing", "error")).lower()

            if not src_field or not target_res:
                self._logger.warning(
                    "Invalid reference rule in resource '%s': %r",
                    resource_name,
                    ref,
                )
                continue

            allowed_values: Set[Any] = set(dep_index.get(target_res, set()))
            if not allowed_values:
                # No index of allowed values: we log and keep the item.
                self._logger.debug(
                    "No dependency index for target_resource='%s'; skipping "
                    "reference validation for this rule.",
                    target_res,
                )
                continue

            values = self._extract_values(item, src_field)
            missing_values = [
                v for v in values if v is not None and v not in allowed_values
            ]

            if not missing_values:
                continue

            self._log_missing(
                resource_name=resource_name,
                tenant=tenant,
                src_field=src_field,
                target_res=target_res,
                target_field=target_field,
                missing_values=missing_values,
                policy=policy,
            )

            # In all current policies, we drop the item from the flow.
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

    def _extract_values(self, item: Dict[str, Any], path: str) -> List[Any]:
        """Extract one or more values from an item using a dotted path.

        The path syntax supports list expansion using '[]', e.g.:

            "criteria_rows[].repo"

        which means: for each element in item["criteria_rows"], take
        element["repo"].
        """
        if not path:
            return []

        segments = path.split(".")
        current: List[Any] = [item]

        for segment in segments:
            next_values: List[Any] = []
            is_list = segment.endswith("[]")
            key = segment[:-2] if is_list else segment

            for value in current:
                if not isinstance(value, dict):
                    continue
                if key not in value:
                    continue

                candidate = value[key]
                if is_list:
                    if isinstance(candidate, list):
                        next_values.extend(candidate)
                else:
                    next_values.append(candidate)

            current = next_values

            if not current:
                break

        # At the end, current may contain scalars or dicts; we just return as-is.
        # The caller decides how to interpret them.
        flat: List[Any] = []
        for v in current:
            flat.append(v)
        return flat

    def _log_missing(
        self,
        resource_name: str,
        tenant: Any,
        src_field: str,
        target_res: str,
        target_field: str,
        missing_values: List[Any],
        policy: str,
    ) -> None:
        values_str = ", ".join(str(v) for v in missing_values)
        msg = (
            "Dropping item for resource '%s', tenant='%s': field '%s' "
            "references non-existent %s.%s values: %s "
            "(policy=%s)"
        )
        self._logger.warning(
            msg,
            resource_name,
            tenant,
            src_field,
            target_res,
            target_field,
            values_str,
            policy,
        )
