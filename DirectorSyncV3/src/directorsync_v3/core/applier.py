from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .director_client import DirectorClient, HttpError
from .job_monitor import JobMonitor, MonitorConfig, MonitorError, MonitorTimeout
from .profiles import ProfileValidationError, ResourceProfile, TransformError

RowDict = Dict[str, Any]
Payload = Dict[str, Any]
HookFunc = Callable[..., Any]
InventoryProvider = Callable[[str], List[Dict[str, Any]]]


@dataclass(frozen=True)
class ApplyResult:
    index: int
    natural_key: Tuple[Any, ...]
    status: str
    reason: str = ""
    error: str = ""
    url: str = ""


class CrudApplier:
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

        hooks_cfg = self.profile.cfg.get("hooks", {}) or {}
        self.h_preprocess = self._resolve_hook(hooks_cfg.get("preprocess_row"))
        self.h_post_payload = self._resolve_hook(hooks_cfg.get("post_payload"))

        # Optional monitor config
        mon_cfg = (self.profile.cfg.get("monitor") or {})
        self.monitor = None
        if mon_cfg.get("path"):
            poll = mon_cfg.get("poll", {}) or {}
            self.monitor = JobMonitor(
                self.client,
                MonitorConfig(
                    path=mon_cfg["path"],
                    status_field=mon_cfg.get("status_field", "status"),
                    ok_states=list(mon_cfg.get("ok_states") or []),
                    fail_states=list(mon_cfg.get("fail_states") or []),
                    interval_sec=float(poll.get("interval_sec", 0.05)),
                    timeout_sec=float(poll.get("timeout_sec", 5.0)),
                ),
            )

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
        sources: Dict[str, Any] = {}
        sources.update(self.ctx)
        sources.update(mapped or {})
        sources.update(desired or {})
        if current:
            id_field = self.profile.id_field
            if id_field in current:
                sources.setdefault("id", current[id_field])
            sources.update(current)

        def repl(m: re.Match[str]) -> str:
            k = m.group(1)
            v = sources.get(k, "")
            return str(v if v is not None else "")

        return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", repl, template)

    def _normalize_remote(self, items_json: Any) -> List[Dict[str, Any]]:
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

    def apply(self, rows: Iterable[RowDict]) -> Tuple[List[ApplyResult], Dict[str, int]]:
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
                    resp = self.client.post_json(url, desired)
                    # Monitor if configured and job present
                    status = "CREATED"
                    if self.monitor:
                        job_id = (resp or {}).get("job_id") or ((resp or {}).get("job") or {}).get("id")
                        if job_id:
                            try:
                                self.monitor.wait(context={**self.ctx, **mapped, **desired, "job_id": job_id})
                            except (MonitorError, MonitorTimeout) as e:
                                self._append(results, counts, ApplyResult(idx, key, "ERROR", error=str(e), url=url))
                                continue
                    self._append(results, counts, ApplyResult(idx, key, status, url=url))
                    continue

                current_cmp = self.profile.make_comparable(current)
                if current_cmp == desired_cmp:
                    self._append(results, counts, ApplyResult(idx, key, "UNCHANGED"))
                else:
                    # UPDATE
                    url = self._format_url(self.profile.cfg["endpoint"]["update"], mapped=mapped, desired=desired, current=current)
                    resp = self.client.put_json(url, desired)
                    status = "UPDATED"
                    if self.monitor:
                        job_id = (resp or {}).get("job_id") or ((resp or {}).get("job") or {}).get("id")
                        if job_id:
                            try:
                                self.monitor.wait(context={**self.ctx, **mapped, **desired, **current, "job_id": job_id})
                            except (MonitorError, MonitorTimeout) as e:
                                self._append(results, counts, ApplyResult(idx, key, "ERROR", error=str(e), url=url))
                                continue
                    self._append(results, counts, ApplyResult(idx, key, status, url=url))

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
