from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ResourceProfile:
    """
    Thin wrapper around the raw YAML profile for a single resource.

    It provides convenience accessors for common sections such as:
    - data_source
    - api
    - mapping
    - comparison
    - constraints
    - pipeline
    """

    name: str
    raw: Mapping[str, Any]

    @property
    def data_source(self) -> Mapping[str, Any]:
        return self.raw.get("data_source", {})

    @property
    def api(self) -> Mapping[str, Any]:
        return self.raw.get("api", {})

    @property
    def mapping(self) -> Mapping[str, Any]:
        return self.raw.get("mapping", {})

    @property
    def comparison(self) -> Mapping[str, Any]:
        return self.raw.get("comparison", {})

    @property
    def constraints(self) -> Mapping[str, Any]:
        return self.raw.get("constraints", {})

    @property
    def pipeline(self) -> Mapping[str, Any]:
        return self.raw.get("pipeline", {})

    @property
    def depends_on(self) -> list[str]:
        depends = self.raw.get("depends_on") or []
        return list(depends)

    @property
    def order(self) -> int:
        return int(self.raw.get("order", 0))
