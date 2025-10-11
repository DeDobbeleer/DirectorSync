"""
HTTP-based inventories provider with per-run in-memory cache.

Usage:
    client = DirectorClient(base_url, token="...")
    inventories = HttpInventories(client)
    nodes = inventories("nodes")  # -> list[dict]
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .director_client import DirectorClient, HttpError

__all__ = ["HttpInventories", "InventoryError"]


class InventoryError(RuntimeError):
    """Raised when an inventory cannot be fetched from the remote service."""


def _extract_items(payload: Any) -> List[Dict[str, Any]]:
    """
    Accept either:
      - {"items": [...]}
      - [...]
    Return a list of dicts (empty list if structure unknown).
    """
    if isinstance(payload, list):
        return list(payload)
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return list(items)
    return []


class HttpInventories:
    """
    Callable inventories provider backed by DirectorClient.

    - One HTTP call per inventory name per run (results cached in memory).
    - Endpoints can be overridden via the `endpoints` attribute (public).
    - Optionally prefixes endpoints with `base_path`.

    Example:
        inv = HttpInventories(client, base_path="/api/v1")
        inv("nodes")     # fetches /api/v1/nodes (or custom endpoint if configured)
        inv("policies")  # fetches /api/v1/policies
    """

    DEFAULT_ENDPOINTS: Dict[str, str] = {
        "nodes": "/nodes",
        "policies": "/policies",
    }

    def __init__(
        self,
        client: DirectorClient,
        *,
        endpoints: Optional[Dict[str, str]] = None,
        base_path: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.client = client
        self.base_path = base_path or ""
        self.endpoints: Dict[str, str] = dict(self.DEFAULT_ENDPOINTS)
        if endpoints:
            self.endpoints.update(endpoints)
        self._cache: Dict[str, List[Dict[str, Any]]] = {}
        self.logger = logger or logging.getLogger("ds.inv")

    def _full_path(self, endpoint: str) -> str:
        if not self.base_path:
            return endpoint
        # join without duplicating slashes
        if endpoint.startswith("/"):
            return f"{self.base_path.rstrip('/')}{endpoint}"
        return f"{self.base_path.rstrip('/')}/{endpoint}"

    def __call__(self, name: str) -> List[Dict[str, Any]]:
        # Cache hit
        if name in self._cache:
            return self._cache[name]

        endpoint = self.endpoints.get(name, f"/{name}")
        path = self._full_path(endpoint)

        try:
            payload = self.client.get_json(path)
        except HttpError as e:
            # 4xx: DirectorClient does not retry; convert to InventoryError
            # 5xx/timeouts: DirectorClient may have retried already; convert if still failing
            self.logger.warning(
                "Inventory fetch failed: inventory=%s status=%s url=%s",
                name,
                getattr(e, "status", None),
                getattr(e, "url", path),
            )
            raise InventoryError(f"Failed to fetch inventory '{name}': {e}") from e

        items = _extract_items(payload)
        self._cache[name] = items
        self.logger.debug("Inventory loaded: name=%s count=%d", name, len(items))
        return items
