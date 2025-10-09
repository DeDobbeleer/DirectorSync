"""
Generic Importer (Step 5, no HTTP).

Objective:
- Execute the declarative pipeline for a given ResourceProfile:
  map_row -> precheck -> build_payload -> normalize -> decide status.
- No network calls here. Remote state is passed as a list/dict of objects.
- Error-safe at row level (never aborts the whole run).
- PEP-8 / typed / docstrings.

Statuses:
  CREATED, UPDATED, UNCHANGED, SKIP, ERROR, EXCEPTION
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .profiles import (
    ProfileValidationError,
    ResourceProfile,
    TransformError,
)


RowDict = Dict[str, Any]
Payload = Dict[str, Any]


@dataclass(frozen=True)
class RowResult:
    """Result for one input row."""
    index: int
    natural_key: Tuple[Any, ...]
    status: str
    reason: str = ""
    error: str = ""


class _NullAdapter(logging.LoggerAdapter):
    """A no-op LoggerAdapter used if the caller does not provide one."""

    def __init__(self) -> None:
        base = logging.getLogger("ds.null")
        base.addHandler(logging.NullHandler())
        super().__init__(base, {})

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        return msg, kwargs


class GenericImporter:
    """
    Stateless executor for a profile against an in-memory dataset.

    Notes:
    - `remote_items` must be comparable with profile.make_comparable().
      In practice, it should be the normalized "current" payload the Director API returns.
    - The importer indexes remote items by the profile's natural key, taken from
      the *mapped* row fields (e.g., 'name').
    """

    def __init__(self, profile: ResourceProfile, logger: Optional[logging.LoggerAdapter] = None) -> None:
        self.profile = profile
        self.log = logger or _NullAdapter()

    @staticmethod
    def _index_remote(profile: ResourceProfile, items: Iterable[Payload]) -> Dict[Tuple[Any, ...], Payload]:
        """
        Build an index of remote items keyed by the profile's natural key.
        Assumes the remote items expose the same logical fields used in the payload.
        """
        index: Dict[Tuple[Any, ...], Payload] = {}
        for it in items:
            key = tuple(it.get(k) for k in profile.natural_key)
            index[key] = it
        return index

    def run(
        self,
        rows: Iterable[RowDict],
        remote_items: Iterable[Payload],
    ) -> Tuple[List[RowResult], Dict[str, int]]:
        """
        Execute the importer against provided rows and the remote state.

        Args:
            rows: iterable of raw input rows (header -> value).
            remote_items: iterable of current remote objects (payload-like dicts).

        Returns:
            (results, summary_counts) where results is a RowResult list and summary_counts
            maps each status to its occurrence count.
        """
        results: List[RowResult] = []
        counts: Dict[str, int] = {}

        remote_index = self._index_remote(self.profile, remote_items)
        self.log.debug("Indexed remote items", extra={"remote_len": len(remote_index)})

        for idx, raw in enumerate(rows):
            try:
                mapped = self.profile.map_row(raw)
                ok, reason = self.profile.precheck(mapped)
                key = self.profile.key_tuple(mapped)

                if not ok:
                    res = RowResult(index=idx, natural_key=key, status="SKIP", reason=reason)
                    self._accumulate(results, counts, res)
                    self.log.warning("Row skipped: %s", reason)
                    continue

                desired = self.profile.build_payload(mapped)
                desired_cmp = self.profile.make_comparable(desired)

                current = remote_index.get(key)
                if current is None:
                    status = "CREATED"
                    res = RowResult(index=idx, natural_key=key, status=status)
                    self._accumulate(results, counts, res)
                    self.log.info("Row will create: key=%s", key)
                    continue

                current_cmp = self.profile.make_comparable(current)

                if current_cmp == desired_cmp:
                    status = "UNCHANGED"
                    res = RowResult(index=idx, natural_key=key, status=status)
                    self._accumulate(results, counts, res)
                    self.log.info("Row unchanged: key=%s", key)
                else:
                    status = "UPDATED"
                    res = RowResult(index=idx, natural_key=key, status=status)
                    self._accumulate(results, counts, res)
                    self.log.info("Row will update: key=%s", key)

            except (ProfileValidationError, TransformError) as e:
                res = RowResult(index=idx, natural_key=tuple(), status="ERROR", error=str(e))
                self._accumulate(results, counts, res)
                self.log.error("Row error: %s", e)
            except Exception as e:  # unexpected
                res = RowResult(index=idx, natural_key=tuple(), status="EXCEPTION", error=str(e))
                self._accumulate(results, counts, res)
                self.log.exception("Row exception: %s", e)

        return results, counts

    @staticmethod
    def _accumulate(results: List[RowResult], counts: Dict[str, int], res: RowResult) -> None:
        results.append(res)
        counts[res.status] = counts.get(res.status, 0) + 1
