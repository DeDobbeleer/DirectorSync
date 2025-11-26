"""Miscellaneous helper functions for DirectorSync V3."""

from __future__ import annotations

from typing import Iterable, List, TypeVar


T = TypeVar("T")


def unique_preserve_order(items: Iterable[T]) -> List[T]:
    """Return a list of unique items while preserving input order.

    Args:
        items: Iterable of items.

    Returns:
        A list of unique items.
    """
    seen: set[T] = set()
    result: List[T] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
