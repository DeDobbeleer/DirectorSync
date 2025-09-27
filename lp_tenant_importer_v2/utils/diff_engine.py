"""
Diff engine for DirectorSync v2.

Provides a minimal decision model to determine whether a resource should
be created, updated, skipped, or left as-is (NOOP) based on a subset
comparison between **desired** and **existing** representations.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal


Op = Literal["NOOP", "CREATE", "UPDATE", "SKIP"]


@dataclass(frozen=True)
class Decision:
    """Represents a diff outcome for a single desired item.

    Attributes:
        op: One of ``"NOOP"``, ``"CREATE"``, ``"UPDATE"``, or ``"SKIP"``.
        reason: Human-friendly explanation of the decision.
        desired: Canonical desired representation (subset used for comparison).
        existing: Canonical existing representation (subset used for comparison).
    """
    op: Op
    reason: str
    desired: Dict[str, Any] | None = None
    existing: Dict[str, Any] | None = None


def decide(desired: Dict[str, Any], existing: Dict[str, Any] | None, *, compare_keys: List[str]) -> Decision:
    """Compute a :class:`Decision` from desired vs existing states.

    The comparison is limited to ``compare_keys`` so importers can ignore
    volatile or server-managed fields.

    Returns:
        A :class:`Decision` with ``op`` set to ``"CREATE"``, ``"UPDATE"``, or ``"NOOP"``.
        (``"SKIP"`` is reserved for importers to set explicitly when validation fails.)
    """
    if existing is None:
        return Decision(op="CREATE", reason="Not found", desired=desired)

    # compare subset
    for k in compare_keys:
        if desired.get(k) != existing.get(k):
            return Decision(op="UPDATE", reason=f"Field differs: {k}", desired=desired, existing=existing)

    return Decision(op="NOOP", reason="Identical subset", desired=desired, existing=existing)
