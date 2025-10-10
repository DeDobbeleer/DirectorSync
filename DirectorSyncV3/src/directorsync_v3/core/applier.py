"""
CRUD Applier for DirectorSync v3 (Step 8).

- Fetches current remote state via profile.endpoint.list (JSON).
- For each input row: map -> resolve -> preprocess_hook -> precheck -> build payload
  -> post_payload_hook -> compare -> decide -> apply (POST/PUT) as needed.
- URL formatting supports placeholders from context, mapped/desired values, and current.id.
- No monitoring yet (will be added in a later step).

This module intentionally reuses ResourceProfile methods to avoid duplicating mapping logic.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .director_client import DirectorClient, HttpError
from .profiles import ProfileValidationError, ResourceProfile, TransformError

RowDict = Dict[str, Any]
Payload = Dict[str, Any]
HookFunc = Callable[..., Any]
InventoryProvider = Callable[[str], List[Dict[str, Any]]]


@dataclass(frozen=True)
class ApplyResult:
    """Outcome for one row after apply phase (may be no-op)."""
    index: int
    natural_key: Tuple[Any, ...]
    status: str            # CREATED / UPDATED / UNCHANGED / SKIP / ERROR / EXCEPTION
    reason: str = ""
    error: str = ""
    url: str = ""          # endpoint called if any


class CrudApplier:
    """
    Apply create/update decisions to the Director API using DirectorClient.

    Minimal expectations for the profile:
      endpoint:
        list:   "/path"
        create: "/path"
        update: "/path/{id}"

    Placeholders in endpoints may reference:
      - context keys (e.g., "tenant", "pool_uuid")
      - mapped/desired fields (e.g., "node_id")
      - "id" (taken from current remote object via profile.id_field)
    """

    def __init__(
        self,
        profile: ResourceProfile,
        client: DirectorClient,
        *,
        context: Optional[Dict[str, Any]] = None,
        logger: Optional[logging.LoggerAdapter] = None,
        inventories: Optional[InventoryProvider] = None,
        hooks: Optional[Dict[str, HookFunc]] = None,
    ) -> None:
        self.profile = profile
        self.client = client
        self.ctx = context or {}
        self.log = logger or logging.getLogger("ds.applier")
        self._provider = inventories or (lambda name: [])
        self._hooks = hooks or {}

        # Resolve hooks names declared in profile (if any)
        hooks_cfg = self.profile.cfg.get("hooks", {}) or {}
        self.h_preprocess = self._resolve_hook(hooks_cfg.get("preprocess_row"))
        self.h_post_payload = self._resolve_hook(hooks_cfg.get("post_payload"))

    # ---------- Utilities ----------

    def _resolve_hook(self, ref: Optional[str]) -> Optional[HookFunc]:
        if not ref:
            return None
        if ref in self._hooks:
            return self._hooks[ref]
        if ":" in ref:
            import importlib
            mod, func = ref.split(":", 1)
            module = importlib.import_module(mod)
            return getattr(module, func)
        raise ProfileValidationError(f"Unknown hook reference '{ref}'")

    def _format_url(self, template: str, *, mapped: Dict[str, Any], desired: Dict[str, Any], current: Optional[Dict[str, Any]]) -> str:
        """
        Safe placeholder formatting: replaces {key} with str(value) from combined sources.
        Missing keys are replaced by empty string.
        """
        sources: Dict[str, Any] = {}
        sources.update(self.ctx)
        sources.update(mapped or {})
        sources.update(desired or {})
        if current:
            # prefer the id_field value as "id"
            id_field = self.profile.id_field
            if id_field in current:
                sources.setdefault("id", current[id_field])
            # also expose all current fields
            sources.update(current)

        def repl(m: re.Match[str]) -> str:
            k = m.group(1)
            v = sources.get(k, "")
            return str(v if v is not None else "")

        return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", repl, template)

    def _normalize_remote(self, items_json: Any) -> List[Dict[str, Any]]:
        """Accept either a list or an object with 'items'."""
        if isinstance(items_json, list):
            return [i for i in items_json if isinstance(i, dict)]
        if isinstance(items_json, dict) and isinstance(items_json.get("items"), list):
            return [i for i in items_json["items"] if isinstance(i, dict)]
        raise ProfileValidationError("List endpoint must return a JSON list or an object with 'items' list")

    def _index_remote(self, items: Iterable[Payload]) -> Dict[Tuple[Any, ...], Payload]:
        index: Dict[Tuple[Any, ...], Payload] = {}
        for it in items:
            key = tuple(it.get(k) for k in self.profile.natural_key)
            index[key] = it
        return index

    # ---------- Public API ----------

    def apply(self, rows: Iterable[RowDict]) -> Tuple[List[ApplyResult], Dict[str, int]]:
        """Run list → decide → apply. Returns (row results, summary counts)."""
        # 1) List current state
        list_tpl = self.profile.cfg.get("endpoint", {}).get("list")
        if not list_tpl:
            raise ProfileValidationError("Profile missing endpoint.list")
        list_url = self._format_url(list_tpl, mapped={}, desired={}, current=None)

        try:
            items_json = self.client.get_json(list_url)
            current_items = self._normalize_remote(items_json)
        except HttpError as e:
            raise ProfileValidationError(f"Failed to list current items: {e}") from e

        current_index = self._index_remote(current_items)

        results: List[ApplyResult] = []
        counts: Dict[str, int] = {}

        # 2) Per-row decisions and applies
        for idx, raw in enumerate(rows):
            try:
                mapped = self.profile.map_row(raw)
                mapped = self.profile.resolve(mapped, lambda name: self._provider(name))
                if self.h_preprocess:
                    mapped = self.h_preprocess(mapped)

                ok, reason = self.profile.precheck(mapped)
                key = self.profile.key_tuple(mapped)
                if not ok:
                    self._append(results, counts, ApplyResult(idx, key, "SKIP", reason=reason))
                    continue

                desired = self.profile.build_payload(mapped)
                if self.h_post_payload:
                    desired = self.h_post_payload(desired, mapped)

                desired_cmp = self.profile.make_comparable(desired)
                current = current_index.get(key)
                if current is None:
                    # CREATE
                    url = self._format_url(self.profile.cfg["endpoint"]["create"], mapped=mapped, desired=desired, current=None)
                    self.client.post_json(url, desired)
                    self._append(results, counts, ApplyResult(idx, key, "CREATED", url=url))
                    continue

                current_cmp = self.profile.make_comparable(current)
                if current_cmp == desired_cmp:
                    self._append(results, counts, ApplyResult(idx, key, "UNCHANGED"))
                else:
                    # UPDATE
                    url = self._format_url(self.profile.cfg["endpoint"]["update"], mapped=mapped, desired=desired, current=current)
                    self.client.put_json(url, desired)
                    self._append(results, counts, ApplyResult(idx, key, "UPDATED", url=url))

            except (ProfileValidationError, TransformError) as e:
                self._append(results, counts, ApplyResult(idx, tuple(), "ERROR", error=str(e)))
            except HttpError as e:
                self._append(results, counts, ApplyResult(idx, tuple(), "ERROR", error=str(e)))
            except Exception as e:
                self._append(results, counts, ApplyResult(idx, tuple(), "EXCEPTION", error=str(e)))

        return results, counts

    @staticmethod
    def _append(results: List[ApplyResult], counts: Dict[str, int], res: ApplyResult) -> None:
        results.append(res)
        counts[res.status] = counts.get(res.status, 0) + 1
