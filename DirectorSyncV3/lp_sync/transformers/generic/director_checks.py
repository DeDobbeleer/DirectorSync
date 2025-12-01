"""Generic transformer to perform Director-side pre-checks.

Director checks are defined in the resource profile under:

    constraints.director_checks:
      - type: "filesystem_path_exists"
        target: "hiddenrepopath[].path"
        operation: "check_repo_path"
        on_failure: "error"

The API section must define matching precheck operations:

    api:
      prechecks:
        - name: "check_repo_path"
          method: POST
          path: "{base_path}/Repos/CheckPath"
          request_template: |
            { "path": "{{ path }}" }
          success_condition: "status == 200"

This transformer is intentionally implemented as a safe no-op skeleton
for now: it logs what it *would* check, and keeps the item unchanged.
The actual HTTP calls will be wired in once DirectorClient exposes a
stable precheck interface.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from lp_sync.core.profiles import ResourceProfile
from lp_sync.transformers.base import BaseTransformer
from lp_sync.utils.logging import get_logger


class DirectorChecksTransformer(BaseTransformer):
    """Skeleton transformer for Director pre-checks."""

    def __init__(self) -> None:
        self._logger = get_logger(self.__class__.__name__)

    def run(
        self,
        item: Dict[str, Any],
        context: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        """Run Director-side checks, if configured.

        For now, this transformer only logs the configured checks and
        returns the item unchanged. It is designed to be extended with
        real HTTP calls to Director.

        Args:
            item: Configuration item to validate.
            context: Pipeline context; must contain "profile" and may contain
                "director_client".
            params: Transformer-specific parameters (unused here).

        Returns:
            The original item.
        """
        profile = self._get_profile(context)
        if profile is None:
            self._logger.warning(
                "No profile in context; skipping Director checks."
            )
            return item

        constraints = profile.constraints
        checks: Iterable[Dict[str, Any]] = constraints.get(
            "director_checks", []
        )
        if not checks:
            return item

        tenant = item.get("tenant")
        resource_name = profile.name

        for check in checks:
            check_type = str(check.get("type", ""))
            target = str(check.get("target", ""))
            operation = str(check.get("operation", ""))
            on_failure = str(check.get("on_failure", "error"))

            self._logger.info(
                "Director check (skeleton) for resource='%s', tenant='%s': "
                "type='%s', target='%s', operation='%s', on_failure='%s'. "
                "No actual HTTP call is performed yet.",
                resource_name,
                tenant,
                check_type,
                target,
                operation,
                on_failure,
            )

        # Future behaviour:
        # - Extract values from `target` similar to ValidateReferencesTransformer.
        # - Resolve the matching precheck in profile.api.prechecks.
        # - Call director_client.<method>(...) and evaluate success_condition.
        # - If failure and on_failure requires it, return None.

        return item

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _get_profile(self, context: Dict[str, Any]) -> ResourceProfile | None:
        profile = context.get("profile")
        if isinstance(profile, ResourceProfile):
            return profile
        return None
