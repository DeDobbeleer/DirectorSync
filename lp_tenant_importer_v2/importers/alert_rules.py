# lp_tenant_importer_v2/importers/alert_rules.py
from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .base import BaseImporter, NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError
from ..utils.resource_profiles import ResourceProfile
from ..utils.resolvers import normalize_repo_list_for_tenant
from ..utils import logging_utils

log = logging_utils.get_logger(__name__)

RESOURCE = "AlertRules"


def _s(v: Any) -> str:
    return str(v).strip() if isinstance(v, str) else ""


def _split_multi(cell: Any, seps: Tuple[str, ...]) -> List[str]:
    if cell is None:
        return []
    if isinstance(cell, list):
        return [x.strip() for x in cell if isinstance(x, str) and x.strip()]
    text = str(cell)
    for sep in seps:
        text = text.replace(sep, "\n")
    return [x.strip() for x in text.split("\n") if x.strip()]


class AlertRulesImporter(BaseImporter):
    SHEET_NAME = "AlertRules"

    def __init__(self) -> None:
        super().__init__()
        self.profile: Optional[ResourceProfile] = None
        self.split_seps: Tuple[str, ...] = ("|", ",", "\n")

    # ------------------------------- lifecycle -------------------------------
    @property
    def sheet_names(self) -> List[str]:
        return [self.SHEET_NAME]

    def validate(self, sheets: Iterable[str]) -> None:
        self.require_sheets(sheets, self.sheet_names)

    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef,
    ) -> Dict[str, Dict[str, Any]]:
        """Return {searchname -> object} from MyAlertRules/fetch (tolerant)."""
        path = client.configapi(pool_uuid, node.id, f"{RESOURCE}/MyAlertRules/fetch")
        items: List[Dict[str, Any]] = []
        try:
            data = client.post_json(path, {"data": {}}) or []
            if isinstance(data, dict):
                items = (
                    data.get("items") or data.get("data") or data.get("results") or []
                )
                if not isinstance(items, list):
                    items = []
            elif isinstance(data, list):
                items = data
        except Exception as exc:
            log.warning("fetch_existing failed [node=%s]: %s", node.name, exc)
            items = []
        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            if not isinstance(it, dict):
                continue
            key = _s(it.get("searchname") or it.get("name"))
            if key:
                out[key] = it
        log.info("fetch_existing: %d rules [node=%s]", len(out), node.name)
        return out

    # ---------------------------- profile handling ----------------------------
    def _load_profile(self) -> ResourceProfile:
        if self.profile:
            return self.profile
        self.profile = ResourceProfile.load(RESOURCE)  # reads resources/profiles.yml
        # options
        seps = self.profile.get_option("list_split_separators", default=["|", ",", "\n"])  # type: ignore
        if isinstance(seps, list) and all(isinstance(x, str) for x in seps):
            self.split_seps = tuple(seps)  # type: ignore
        return self.profile

    def _resolve_owner(self, desired: Dict[str, Any]) -> str:
        # 0) explicit (future proof)
        ov = _s(desired.get("owner"))
        if ov:
            return ov
        # 1) profiles.yml
        prof = self._load_profile()
        owner_from_profile = _s(prof.get_option("default_owner", default=""))
        if owner_from_profile:
            log.debug("owner resolved from profiles.yml: %s", owner_from_profile)
            return owner_from_profile
        # 2) env
        env_owner = _s(os.getenv("LP_ALERT_OWNER", ""))
        if env_owner:
            log.debug("owner resolved from env LP_ALERT_OWNER: %s", env_owner)
            return env_owner
        # 3) context
        ctx = getattr(self, "ctx", None)
        for attr in ("owner_id", "user_id", "username"):
            v = _s(getattr(ctx, attr, None)) if ctx else ""
            if v:
                log.debug("owner resolved from context %s: %s", attr, v)
                return v
        return ""

    # --------------------------- XLSX row -> desired --------------------------
    def iter_desired_rows(self, xlsx_path: str) -> Iterable[Dict[str, Any]]:
        prof = self._load_profile()
        df = self.xlsx_reader.read(self.SHEET_NAME)
        for row in df.to_dict(orient="records"):
            desired: Dict[str, Any] = {}
            for col in prof.iter_columns():
                src = col.source
                api_name = col.rename or col.source
                if api_name is None:
                    continue
                value: Any = None
                # pull value from XLSX if source path provided
                if src:
                    value = self.get_nested_value(row, src)
                    if col.split and isinstance(value, (str, list)):
                        value = _split_multi(value, self.split_seps)
                # apply default_from for owner (or other fields) if empty
                if (value is None or value == "") and col.default_from:
                    if col.default_from == "profiles.options.default_owner" and api_name == "owner":
                        value = self._resolve_owner(desired)
                # apply simple defaults
                if (value is None or value == "") and col.has_default:
                    value = col.default
                # normalize booleans on/off
                if col.bool_onoff and isinstance(value, bool):
                    value = "on" if value else None
                # type coercion
                try:
                    value = col.coerce(value)
                except Exception as exc:
                    raise ValidationError(f"column {src or api_name}: {exc}") from exc
                # accumulate
                if value is not None and value != "":
                    desired[api_name] = value
            # ensure single timerange key according to priority
            prio = prof.get_option("timerange_priority", default=["minute", "hour", "day"])  # type: ignore
            tr_keys = [f"timerange_{k}" for k in prio]
            picked = None
            for k in tr_keys:
                if desired.get(k) not in (None, "", 0):
                    picked = k
                    break
            for k in tr_keys:
                if k != picked and k in desired:
                    desired.pop(k)
            # normalize repos if requested
            if prof.get_option("repos_normalize", default=True):
                repos = desired.get("repos", [])
                repos = normalize_repo_list_for_tenant(
                    repos,
                    tenant_ctx=self.ctx,
                    use_tenant_ip=bool(prof.get_option("repos_use_tenant_ip_private", default=True)),
                    enable_repo_sheet_mapping=bool(prof.get_option("repo_sheet_mapping_enabled", default=True)),
                    xlsx_reader=self.xlsx_reader,
                )
                desired["repos"] = repos
            # owner resolve (final guard)
            desired.setdefault("owner", self._resolve_owner(desired))
            log.debug(
                "XLSX row parsed name=%s repos=%d timerange_keys=%s",
                desired.get("searchname"), len(desired.get("repos", [])),
                [k for k in ("timerange_minute","timerange_hour","timerange_day") if k in desired],
            )
            yield desired

    # --------------------------- payload builders ----------------------------
    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        payload = {k: v for k, v in desired_row.items() if v not in (None, "")}
        # required guards
        if not _s(payload.get("owner")):
            raise ValidationError("owner is required and could not be resolved from context")
        repos = payload.get("repos") or []
        if not isinstance(repos, list) or not repos:
            raise ValidationError("repos is required and must be a non-empty list")
        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing: Dict[str, Any]) -> Dict[str, Any]:
        payload = self.build_payload_create(desired_row)
        payload.pop("searchname", None)
        return payload

    # ------------------------------- apply ops -------------------------------
    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        action: str,
        name: str,
        desired_row: Dict[str, Any],
        existing_id: Optional[str],
        dry_run: bool,
    ) -> Dict[str, Any]:
        try:
            if action == "create":
                payload = self.build_payload_create(desired_row)
                log.debug("CREATE payload=%s", payload)
                if dry_run:
                    return {"status": "Dry-run", "action": action}
                return client.create_resource(pool_uuid, node.id, RESOURCE, payload)
            elif action == "update":
                payload = self.build_payload_update(desired_row, {})
                log.debug("UPDATE payload=%s", payload)
                if dry_run:
                    return {"status": "Dry-run", "action": action}
                assert existing_id
                return client.update_resource(pool_uuid, node.id, RESOURCE, existing_id, payload)
            elif action == "noop":
                return {"status": "Noop"}
            else:
                return {"status": "Skipped", "reason": f"unknown action {action}"}
        except ValidationError as ve:
            log.warning(
                "SKIP %s alert=%s [node=%s] reason=%s (no API call)",
                action.upper(), name, node.name, ve,
            )
            return {"status": "Skipped", "reason": str(ve)}
        except Exception as exc:
            return {"status": "Failed", "error": str(exc)}