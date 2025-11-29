from __future__ import annotations
from typing import Any, Dict, List, Tuple
from dataclasses import dataclass

from lp_sync.utils.logging import get_logger


@dataclass
class PlannedAction:
    action: str                   # create / update / delete / noop / skip
    key: Tuple[Any, ...] | None
    desired: Dict[str, Any] | None
    current: Dict[str, Any] | None
    reason: str | None = None


class DiffEngine:
    """Generic diff computation based entirely on YAML profile rules."""

    def __init__(self) -> None:
        self._logger = get_logger(self.__class__.__name__)

    # ------------------------------------------------------
    def diff(
        self,
        profile: Any,
        desired: List[Dict[str, Any]],
        current: List[Dict[str, Any]],
    ) -> List[PlannedAction]:

        comp = profile.comparison or {}
        id_keys = comp.get("identity_keys", [])
        sig_fields = comp.get("significant_fields", [])
        canon = comp.get("canonicalization", {})

        # Canonicalize both sets
        desired_map = {
            self._make_key(item, id_keys): self._canonical(item, canon)
            for item in desired
        }
        current_map = {
            self._make_key(item, id_keys): self._canonical(item, canon)
            for item in current
        }

        actions: List[PlannedAction] = []

        # ----- Pass 1: desired → current (create + update + noop)
        for key, d in desired_map.items():
            c = current_map.get(key)

            if c is None:
                actions.append(
                    PlannedAction(
                        action="create",
                        key=key,
                        desired=d,
                        current=None,
                        reason="Missing on Director"
                    )
                )
                continue

            if not self._equal_on_significant(d, c, sig_fields):
                actions.append(
                    PlannedAction(
                        action="update",
                        key=key,
                        desired=d,
                        current=c,
                        reason="Differences on significant fields"
                    )
                )
            else:
                actions.append(
                    PlannedAction(
                        action="noop",
                        key=key,
                        desired=d,
                        current=c,
                        reason="No significant difference"
                    )
                )

        # ----- Pass 2: current → desired (delete)
        for key, c in current_map.items():
            if key not in desired_map:
                actions.append(
                    PlannedAction(
                        action="delete",
                        key=key,
                        desired=None,
                        current=c,
                        reason="Not present in desired state"
                    )
                )

        return actions

    # ------------------------------------------------------
    def _make_key(self, item: Dict[str, Any], id_keys: List[str]) -> Tuple[Any, ...]:
        """Make resource identity key defined in YAML."""
        return tuple(item.get(k) for k in id_keys)

    # ------------------------------------------------------
    def _canonical(self, item: Dict[str, Any], canon: Dict[str, Any]) -> Dict[str, Any]:
        """Apply canonicalization rules from YAML."""
        out = dict(item)

        # Remove ignore_fields
        ignore_fields = canon.get("ignore_fields", [])
        for f in ignore_fields:
            out.pop(f, None)

        # Sort arrays
        sort_arrays = canon.get("sort_arrays", [])
        for field in sort_arrays:
            v = out.get(field)
            if isinstance(v, list):
                try:
                    out[field] = sorted(v, key=lambda x: str(x))
                except Exception:
                    self._logger.warning(
                        "Could not sort field '%s' for canonicalization", field
                    )

        return out

    # ------------------------------------------------------
    def _equal_on_significant(
        self,
        a: Dict[str, Any],
        b: Dict[str, Any],
        sig_fields: List[str],
    ) -> bool:
        """Compare only significant fields."""
        for field in sig_fields:
            if a.get(field) != b.get(field):
                return False
        return True
