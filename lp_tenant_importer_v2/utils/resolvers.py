"""
Resolvers and caches (name→id) per node.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple


class ResolverCache:
    def __init__(self) -> None:
        # key: (pool_uuid, node_id, resource), value: list/dict from API
        self._cache: Dict[Tuple[str, str, str], Any] = {}

    def get(self, pool_uuid: str, node_id: str, resource: str):
        return self._cache.get((pool_uuid, node_id, resource))

    def set(self, pool_uuid: str, node_id: str, resource: str, value: Any) -> None:
        self._cache[(pool_uuid, node_id, resource)] = value
