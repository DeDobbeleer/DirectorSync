"""Sync engine orchestration for DirectorSync V3.

This module coordinates the end-to-end sync pipeline for a given
resource and tenant:

1. Load desired state from DB
2. Run preprocess transformers
3. Load current state from Director
4. Compute diff
5. Apply actions (honouring dry-run)
6. Optionally run postprocess transformers

It is generic and driven by ResourceProfile, DirectorClient,
DesiredStateLoader, TransformerPipeline, DiffEngine, and ApplyEngine.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from lp_sync.core.desired_state_loader import DesiredStateLoader
from lp_sync.core.diff_engine import DiffEngine, PlannedAction
from lp_sync.core.profiles import ResourceProfile
from lp_sync.core.apply_engine import ApplyEngine
from lp_sync.core.transformer_pipeline import TransformerPipeline
from lp_sync.utils.logging import get_logger


class SyncEngine:
    """High-level orchestrator for resource synchronization."""

    def __init__(
        self,
        profiles: Mapping[str, ResourceProfile],
        director_client: Any,
        db_connection: Any,
    ) -> None:
        """Create a new SyncEngine.

        Args:
            profiles: Mapping from resource_name to ResourceProfile.
            director_client: Abstraction over Director HTTP API.
            db_connection: DB-API compatible connection used by
                DesiredStateLoader.
        """
        self._profiles = dict(profiles)
        self._director_client = director_client
        self._loader = DesiredStateLoader(db_connection)
        self._transformers = TransformerPipeline()
        self._diff_engine = DiffEngine()
        self._apply_engine = ApplyEngine(director_client)
        self._logger = get_logger(self.__class__.__name__)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def sync_resource_for_tenant(
        self,
        resource_name: str,
        tenant_code: str,
        dry_run: bool = False,
    ) -> List[PlannedAction]:
        """Synchronize a single resource for a single tenant.

        Args:
            resource_name: Name of the resource (e.g. "repos").
            tenant_code: Tenant identifier.
            dry_run: If True, no HTTP calls are performed.

        Returns:
            List of PlannedAction objects describing the performed or
            planned changes.
        """
        profile = self._profiles.get(resource_name)
        if profile is None:
            raise ValueError(f"Unknown resource '{resource_name}'")

        if not profile.enabled:
            self._logger.info(
                "Resource '%s' is disabled; nothing to do.",
                resource_name,
            )
            return []

        # 1. Load desired state from DB
        desired_raw = self._loader.load(profile, tenant_code)

        # 2. Build dependency index (minimal version)
        dependency_index = self._build_dependency_index(tenant_code)

        # 3. Preprocess desired items through transformers
        preprocess_config = (
            profile.pipeline.get("preprocess") if profile.pipeline else []
        )
        context: Dict[str, Any] = {
            "tenant_code": tenant_code,
            "resource_name": resource_name,
            "profile": profile,
            "director_client": self._director_client,
            "dependency_index": dependency_index,
        }

        desired_prepared = self._transformers.run(
            pipeline_config=preprocess_config,
            items=desired_raw,
            context=context,
        )

        # 4. Load current state from Director
        current_items = self._list_current_from_director(
            resource_name=resource_name,
            profile=profile,
            tenant_code=tenant_code,
        )

        # 5. Compute diff
        actions = self._diff_engine.diff(
            profile=profile,
            desired=desired_prepared,
            current=current_items,
        )

        # 6. Apply actions
        applied_actions = self._apply_engine.apply(
            actions=actions,
            dry_run=dry_run,
        )

        # 7. Postprocess (optional)
        postprocess_config = (
            profile.pipeline.get("postprocess") if profile.pipeline else []
        )
        if postprocess_config:
            # Postprocess works on actions; we pass them via context if needed.
            # For now, we just run the pipeline on a "report" representation.
            # This can be extended later if you want postprocessing on actions.
            self._logger.debug(
                "Postprocess pipeline is configured for resource '%s', but "
                "no standard representation is defined yet. Skipping.",
                resource_name,
            )

        return applied_actions

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _list_current_from_director(
        self,
        resource_name: str,
        profile: ResourceProfile,
        tenant_code: str,
    ) -> List[Dict[str, Any]]:
        """Retrieve current state for a resource from Director.

        This is a thin wrapper around the DirectorClient abstraction.
        The exact DirectorClient interface is intentionally left flexible.

        Expected DirectorClient responsibility:
        - take profile.api.list configuration into account
        - perform the appropriate HTTP requests
        - return a list[dict] representing current items
        """
        try:
            # Placeholder convention; adjust once DirectorClient is final:
            return self._director_client.list_resources(
                resource_name=resource_name,
                profile=profile,
                tenant_code=tenant_code,
            )
        except AttributeError:
            self._logger.error(
                "Director client does not implement 'list_resources'; "
                "returning an empty current state for resource '%s'.",
                resource_name,
            )
            return []

    def _build_dependency_index(self, tenant_code: str) -> Dict[str, Any]:
        """Build a minimal dependency index for ValidateReferences.

        For a first implementation, we only populate what is absolutely
        required by existing constraints (e.g. repos by name).

        A simple strategy:
        - for each resource in profiles that is a potential target of a
          reference, load its desired state and build a set of names.

        This can be optimized later (caching, using current state, etc.).
        """
        index: Dict[str, Any] = {}

        # Basic implementation: only compute repos names if present.
        repos_profile = self._profiles.get("repos")
        if repos_profile is not None and repos_profile.enabled:
            desired_repos = self._loader.load(repos_profile, tenant_code)
            repo_names = {
                r.get("name")
                for r in desired_repos
                if r.get("name") is not None
            }
            index["repos"] = repo_names

        return index
