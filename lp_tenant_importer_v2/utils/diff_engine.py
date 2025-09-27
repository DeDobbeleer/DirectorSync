"""
Diff engine producing NOOP/CREATE/UPDATE/SKIP operations.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional


Op = Literal["NOOP", "CREATE", "UPDATE", "SKIP"]


@dataclass(frozen=True)
class Decision:
    op: Op
    reason: str
    desired: Dict[str, Any] | None = None
    existing: Dict[str, Any] | None = None


def decide(desired: Dict[str, Any], existing: Dict[str, Any] | None, *, compare_keys: List[str]) -> Decision:
    """
    Decide the operation based on desired vs existing (subset comparison).
    """
    if existing is None:
        return Decision(op="CREATE", reason="Not found", desired=desired)

    # compare subset
    for k in compare_keys:
        if desired.get(k) != existing.get(k):
            return Decision(op="UPDATE", reason=f"Field differs: {k}", desired=desired, existing=existing)

    return Decision(op="NOOP", reason="Identical subset", desired=desired, existing=existing)
