"""Apply engine for DirectorSync V3.

This module is responsible for executing planned actions against the
Director API (create, update, delete).

At this stage, the implementation focuses on:
- providing a clear structure,
- handling dry-run semantics,
- logging what would or will be executed.

Actual HTTP calls will be wired in once the DirectorClient and
PlannedAction carry enough endpoint/payload details.
"""

from __future__ import annotations

from typing import Any, Iterable, List

from lp_sync.utils.logging import get_logger

from .diff_engine import PlannedAction


class ApplyEngine:
    """Execute planned actions using a Director client."""

    def __init__(self, director_client: Any) -> None:
        """Create a new ApplyEngine.

        Args:
            director_client: Abstraction over the Director HTTP API.
                The concrete interface will evolve as the project matures.
        """
        self._client = director_client
        self._logger = get_logger(self.__class__.__name__)

    def apply(
        self,
        actions: Iterable[PlannedAction],
        dry_run: bool = False,
    ) -> List[PlannedAction]:
        """Apply actions against Director.

        Args:
            actions: The planned actions to execute.
            dry_run: If True, do not perform any HTTP calls. Actions are
                returned unchanged except for an updated `reason` field.

        Returns:
            The list of actions, potentially enriched with results or errors.
        """
        result: List[PlannedAction] = []

        for action in actions:
            # No operation or explicitly skipped actions: just propagate.
            if action.action in ("noop", "skip"):
                self._logger.debug(
                    "Skipping action '%s' for key=%s",
                    action.action,
                    action.key,
                )
                result.append(action)
                continue

            if dry_run:
                # Mark that this action was not actually executed.
                suffix = "dry-run; no HTTP call performed"
                if action.reason:
                    action.reason = f"{action.reason} ({suffix})"
                else:
                    action.reason = suffix

                self._logger.info(
                    "Dry-run: would %s resource with key=%s",
                    action.action,
                    action.key,
                )
                result.append(action)
                continue

            # Real execution path: currently only logs the intent.
            # Integration with DirectorClient (POST/PUT/DELETE) will be added
            # when PlannedAction carries endpoint/payload details.
            self._logger.info(
                "Executing action '%s' for key=%s "
                "(HTTP integration not implemented yet)",
                action.action,
                action.key,
            )

            # TODO: call self._client.<method>(...) once the interface is fixed.

            result.append(action)

        return result
