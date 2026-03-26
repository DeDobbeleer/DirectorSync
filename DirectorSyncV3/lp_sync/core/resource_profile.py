"""Resource profile handling.

This module will be responsible for loading and validating YAML resource
profiles and exposing them as convenient Python objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ResourceProfile:
    """Representation of a single resource profile."""

    name: str
    raw: Dict[str, Any]


def load_profile(name: str) -> ResourceProfile:
    """Load a resource profile by name.

    Args:
        name: The resource name, for example "repos".

    Returns:
        A ResourceProfile instance.

    Note:
        This function is a placeholder and does not yet read actual YAML
        files from disk.
    """
    return ResourceProfile(name=name, raw={})
