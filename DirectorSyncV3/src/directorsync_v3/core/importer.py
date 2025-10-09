"""
Generic Importer (Step 6: resolve & hooks, no HTTP).

Lifecycle:
  map_row -> resolve -> preprocess_row(hook) -> precheck -> build_payload -> post_payload(hook)
  -> normalize -> decide (CREATED/UPDATED/UNCHANGED/SKIP/ERROR/EXCEPTION)

- No network calls. Remote state and inventories are injected in-memory.
- Row-level isolation (never abort the run).
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from .profiles import (
    ProfileValidationError,
    ResourceProfile,
    TransformError,
)

RowDict = Dict[str, Any]
Payload = Dict[str, Any]
HookFunc = Callable[..., Any]
InventoryProvider = Callable[[str], List[Dict[str, Any]]]


@dataclass(frozen=True)
class RowResult:
    """Result for one input row."""
    index: int
    natural_key: Tuple[Any, ...]
    status: str
    reason: str = ""
    error: str = ""


class _NullAdapter(logging.LoggerAdapter):
    def __init__(self) -> None:
        base = logging.getLogger("ds.null")
        base.addHandler(logging.NullHandler())
        super().__init__(base, {})

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        return msg, kwargs


class GenericImporter:
    """
    Stateless executor for a profile against an in-memory dataset, with resolve & hooks.

    - remote_items are indexed by the profile's natural key (from mapped row).
    - inventories are fetched via an InventoryProvider and cached per run.
    - hooks can be passed as a dict {name: callable}, or resolved as 'module:function'.
    """

    def __init__(
        self,
        profile: ResourceProfile,
        logger: Optional[logging.LoggerAdapter] = None,
        inventories: Optional[InventoryProvider] = None,
        hooks: Optional[Dict[str, HookFunc]] = None,
    ) -> None:
        self.profile = profile
        self.log = logger or _NullAdapter()
        self._provider = inventories or (lambda name: [])
        self._hooks = hooks or {}
        self._inv_cache: Dict[str, List[Dict[str, Any]]] = {}

    @staticmethod
    def _index_remote(profile: ResourceProfile, items: Iterable[Payload]) -> Dict[Tuple[Any, ...], Payload]:
        index: Dict[Tuple[Any, ...], Payload] = {}
        for it in items:
            key = tuple(it.get(k) for k in profile.natural_key)
            index[key] = it
        return index

    def _get_inventory(self, name: str) -> List[Dict[str, Any]]:
        if name not in self._inv_cache:
            inv = self._provider(name) or []
            if not isinstance(inv, list):
                raise ProfileValidationError(f"Inventory provider must return list for '{name}'")
            self._inv_cache[name] = inv
        return self._inv_cache[name]

    def _provider_wrapper(self, name: str) -> List[Dict[str, Any]]:
        return self._get_inventory(name)

    def _resolve_hook(self, ref: Optional[str]) -> Optional[HookFunc]:
        if not ref:
            return None
        if ref in self._hooks:
            return self._hooks[ref]
        if ":" in ref:
            mod, func = ref.split(":", 1)
            try:
                module = importlib.import_module(mod)
                return getattr(module, func)
            except Exception as e:
                raise ProfileValidationError(f"Cannot import hook '{ref}': {e}") from e
        # name not found
        raise ProfileValidationError(f"Unknown hook reference '{ref}'")

    def run(
        self,
        rows: Iterable[RowDict],
        remote_items: Iterable[Payload],
    ) -> Tuple[List[RowResult], Dict[str, int]]:
        results: List[RowResult] = []
        counts: Dict[str, int] = {}

        remote_index = self._index_remote(self.profile, remote_items)
        self.log.debug("Indexed remote items", extra={"remote_len": len(remote_index)})

        # Load hook fns if declared
        hooks_cfg = self.profile.cfg.get("hooks", {}) or {}
        h_preprocess = self._resolve_hook(hooks_cfg.get("preprocess_row")) if hooks_cfg else None
        h_post_payload = self._resolve_hook(hooks_cfg.get("post_payload")) if hooks_cfg else None

        for idx, raw in enumerate(rows):
            try:
                mapped = self.profile.map_row(raw)

                # Resolve inventories
                mapped = self.profile.resolve(mapped, self._provider_wrapper)

                # Hook: preprocess_row(mapped) -> mapped
                if h_preprocess:
                    try:
                        mapped = h_preprocess(mapped)
                    except Exception as e:
                        raise ProfileValidationError(f"preprocess_row hook failed: {e}")

                # Prechecks
                ok, reason = self.profile.precheck(mapped)
                key = self.profile.key_tuple(mapped)

                if not ok:
                    res = RowResult(index=idx, natural_key=key, status="SKIP", reason=reason)
                    self._accumulate(results, counts, res)
                    self.log.warning("Row skipped: %s", reason)
                    continue

                desired = self.profile.build_payload(mapped)

                # Hook: post_payload(payload, mapped) -> payload
                if h_post_payload:
                    try:
                        desired = h_post_payload(desired, mapped)
                    except Exception as e:
                        raise ProfileValidationError(f"post_payload hook failed: {e}") from e

                desired_cmp = self.profile.make_comparable(desired)
                current = remote_index.get(key)

                if current is None:
                    res = RowResult(index=idx, natural_key=key, status="CREATED")
                    self._accumulate(results, counts, res)
                    self.log.info("Row will create: key=%s", key)
                    continue

                current_cmp = self.profile.make_comparable(current)

                if current_cmp == desired_cmp:
                    res = RowResult(index=idx, natural_key=key, status="UNCHANGED")
                    self._accumulate(results, counts, res)
                    self.log.info("Row unchanged: key=%s", key)
                else:
                    res = RowResult(index=idx, natural_key=key, status="UPDATED")
                    self._accumulate(results, counts, res)
                    self.log.info("Row will update: key=%s", key)

            except (ProfileValidationError, TransformError) as e:
                res = RowResult(index=idx, natural_key=tuple(), status="ERROR", error=str(e))
                self._accumulate(results, counts, res)
                self.log.error("Row error: %s", e)
            except Exception as e:
                res = RowResult(index=idx, natural_key=tuple(), status="EXCEPTION", error=str(e))
                self._accumulate(results, counts, res)
                self.log.exception("Row exception: %s", e)

        return results, counts

    @staticmethod
    def _accumulate(results: List[RowResult], counts: Dict[str, int], res: RowResult) -> None:
        results.append(res)
        counts[res.status] = counts.get(res.status, 0) + 1
