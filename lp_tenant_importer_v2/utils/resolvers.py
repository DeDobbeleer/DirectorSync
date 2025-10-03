# lp_tenant_importer_v2/utils/resolvers.py


"""
Resolver cache primitives.

Importers can store API results by (pool_uuid, node_id, resource) to avoid
re-fetching data repeatedly within a single run.
"""

from __future__ import annotations
from typing import Any, Dict, Tuple


class ResolverCache:
    """A tiny in-memory cache keyed by (pool_uuid, node_id, resource)."""
    def __init__(self) -> None:
        self._cache: Dict[Tuple[str, str, str], Any] = {}

    def get(self, pool_uuid: str, node_id: str, resource: str):
        """Return a cached value or None."""
        return self._cache.get((pool_uuid, node_id, resource))

    def set(self, pool_uuid: str, node_id: str, resource: str, value: Any) -> None:
        """Store a value under the composite cache key."""
        self._cache[(pool_uuid, node_id, resource)] = value
