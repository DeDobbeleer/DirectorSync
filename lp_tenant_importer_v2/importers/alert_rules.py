# lp_tenant_importer_v2/importers/alert_rules.py
from __future__ import annotations

import os
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter, NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError
from ..utils.resource_profiles import ResourceProfile
from ..utils.resolvers import normalize_repo_list_for_tenant

log = logging.getLogger(__name__)

RESOURCE = "AlertRules"


# ------------------------------ ALIASES --------------------------------------
# Pour chaque *clé canonique*, on liste les colonnes XLSX acceptées (par ordre de priorité).
ALIASES: Dict[str, List[str]] = {
    "name": ["name", "Name"],
    "settings.risk": ["settings.risk", "risk", "Risk"],
    "settings.aggregate": ["settings.aggregate", "aggregate", "Aggregate"],

    "settings.condition.condition_option": [
        "settings.condition.condition_option",
        "settings.condition.option",
        "condition_option",
        "condition.option",
    ],
    "settings.condition.condition_value": [
        "settings.condition.condition_value",
        "settings.condition.value",
        "condition_value",
        "condition.value",
    ],

    "settings.livesearch_data.limit": [
        "settings.livesearch_data.limit",
        "settings.limit",
        "limit",
    ],

    "settings.repos": [
        "settings.repos",
        "repos",
        "settings.livesearch_data.repos",
    ],

    # Timerange : on accepte livesearch_data.* ou settings.timerange.*
    "timerange_minute": [
        "settings.livesearch_data.timerange_minute",
        "settings.timerange.minute",
        "timerange_minute",
        "timerange.minute",
        "settings.time_range_minutes",
    ],
    "timerange_hour": [
        "settings.livesearch_data.timerange_hour",
        "settings.timerange.hour",
        "timerange_hour",
        "timerange.hour",
    ],
    "timerange_day": [
        "settings.livesearch_data.timerange_day",
        "settings.timerange.day",
        "timerange_day",
        "timerange.day",
    ],
    "timerange_second": [
        "settings.livesearch_data.timerange_second",
        "settings.timerange.second",
        "timerange_second",
        "timerange.second",
        "settings.time_range_seconds",
    ],

    "query": [
        "settings.livesearch_data.query",
        "settings.extra_config.query",
        "settings.query",
        "query",
    ],

    "settings.description": ["settings.description", "description", "Description"],

    "settings.livesearch_data.search_interval_minute": [
        "settings.livesearch_data.search_interval_minute",
        "settings.search_interval_minute",
        "search_interval_minute",
    ],

    "settings.flush_on_trigger": ["settings.flush_on_trigger", "flush_on_trigger"],
    "settings.throttling_enabled": ["settings.throttling_enabled", "throttling_enabled"],
    "settings.throttling_field": ["settings.throttling_field", "throttling_field"],
    "settings.throttling_time_range": ["settings.throttling_time_range", "throttling_time_range"],

    "settings.log_source": ["settings.log_source", "log_source"],
    "settings.context_template": ["settings.context_template", "context_template"],
    "settings.active": ["settings.active", "active"],
}


# ------------------------------- helpers -------------------------------------
def _s(v: Any) -> str:
    return v.strip() if isinstance(v, str) else (str(v).strip() if v is not None else "")


def _int_or_none(v: Any) -> Optional[int]:
    if v is None or v == "":
        return None
    try:
        iv = int(v)
        return iv
    except Exception:
        try:
            fv = float(str(v).replace(",", "."))
            return int(fv)
        except Exception:
            return None


def _split_multi(cell: Any, seps: Tuple[str, ...]) -> List[str]:
    if cell is None:
        return []
    if isinstance(cell, list):
        return [x.strip() for x in cell if isinstance(x, str) and x.strip()]
    text = str(cell)
    for sep in seps:
        text = text.replace(sep, "\n")
    return [x.strip() for x in text.split("\n") if x.strip()]


def _first(row: pd.Series, keys: List[str]) -> Any:
    """Retourne la première valeur non vide parmi les clés données."""
    for k in keys:
        if k in row:
            v = row.get(k)
            if isinstance(v, list) and v:
                return v
            if _s(v) != "":
                return v
    return None


def _first_list(row: pd.Series, keys: List[str], seps: Tuple[str, ...]) -> List[str]:
    v = _first(row, keys)
    return _split_multi(v, seps) if v is not None else []


# ----------------------------- importer --------------------------------------
class AlertRulesImporter(BaseImporter):
    """
    Importeur AlertRules (MyAlertRules) calqué sur les autres modules v2.

    - Aliases de colonnes (XLSX) : on prend la première non vide.
    - Mapping piloté par profiles.yml (owner, options).
    - Normalisation repos (legacy -> ip:port[:Repo_CLEANED]) via util commun.
    - Timerange : on émet une seule clé parmi minute/hour/day.
    - Validations avant POST/PUT -> pas de 400.
    """

    SHEET_ALERT = "Alert"
    SHEET_REPO = "Repo"  # facultatif : mapping old -> cleaned

    def __init__(self) -> None:
        super().__init__()
        self.profile: Optional[ResourceProfile] = None
        self.split_seps: Tuple[str, ...] = ("|", ",", "\n")

    # ------------------------------- lifecycle -------------------------------
    @property
    def sheet_names(self) -> List[str]:
        # Repo est optionnel
        return [self.SHEET_ALERT]

    def _load_profile(self) -> ResourceProfile:
        if self.profile is None:
            self.profile = ResourceProfile.load(RESOURCE)  # lit resources/profiles.yml
            seps = self.profile.get_option("list_split_separators", default=["|", ",", "\n"])
            if isinstance(seps, list) and all(isinstance(x, str) for x in seps):
                self.split_seps = tuple(seps)  # type: ignore
        return self.profile

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        if self.SHEET_ALERT not in sheets:
            raise ValidationError(f"Missing required sheet: {self.SHEET_ALERT}")
        df = sheets[self.SHEET_ALERT]

        def need_alias(canon: str) -> None:
            cand = ALIASES.get(canon, [canon])
            if not any(col in df.columns for col in cand):
                raise ValidationError(f"Alert: missing required column (any of) {cand}")

        need_alias("name")
        need_alias("settings.risk")
        need_alias("settings.aggregate")
        need_alias("settings.condition.condition_option")
        need_alias("settings.condition.condition_value")
        need_alias("settings.livesearch_data.limit")
        need_alias("settings.repos")
        # Timerange: au moins une des 4 unités
        if not any(
            any(col in df.columns for col in ALIASES.get(canon, [canon]))
            for canon in ["timerange_minute", "timerange_hour", "timerange_day", "timerange_second"]
        ):
            raise ValidationError("Alert: missing timerange column (minute/hour/day/second)")

    # -------------------------- director state --------------------------
    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """
        Retourne {searchname -> objet} depuis MyAlertRules/fetch.
        Tolère plusieurs formes de payload; ne lève pas d'exception.
        """
        path = client.configapi(pool_uuid, node.id, f"{RESOURCE}/MyAlertRules/fetch")
        items: List[Dict[str, Any]] = []
        try:
            data = client.post_json(path, {"data": {}}) or []
            if isinstance(data, dict):
                items = data.get("items") or data.get("data") or data.get("results") or []
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

    # --------------------------- XLSX → desired ---------------------------
    def iter_desired(self, sheets: Dict[str, pd.DataFrame]) -> Iterable[Dict[str, Any]]:
        prof = self._load_profile()
        df: pd.DataFrame = sheets[self.SHEET_ALERT].copy()

        # repo mapping sheet (optionnel)
        repo_map_df: Optional[pd.DataFrame] = (
            sheets.get(self.SHEET_REPO) if isinstance(sheets.get(self.SHEET_REPO), pd.DataFrame) else None
        )

        for _, row in df.iterrows():
            # Résolution via alias (première non vide)
            name = _s(_first(row, ALIASES["name"]))
            if not name:
                continue

            # Timerange bruts
            t_min = _int_or_none(_first(row, ALIASES["timerange_minute"]))
            t_hour = _int_or_none(_first(row, ALIASES["timerange_hour"]))
            t_day = _int_or_none(_first(row, ALIASES["timerange_day"]))
            t_sec = _int_or_none(_first(row, ALIASES["timerange_second"]))  # ignoré côté API MyRules

            desired: Dict[str, Any] = {
                # interne (sera renommé en searchname au build du payload)
                "name": name,

                # RISK / AGGREGATE
                "risk": _s(_first(row, ALIASES["settings.risk"])),
                "aggregate": _s(_first(row, ALIASES["settings.aggregate"])),

                # CONDITION
                "condition_option": _s(_first(row, ALIASES["settings.condition.condition_option"])) or "count",
                "condition_value": _int_or_none(_first(row, ALIASES["settings.condition.condition_value"])) or 0,

                # LIMIT / QUERY
                "limit": _int_or_none(_first(row, ALIASES["settings.livesearch_data.limit"])) or 0,
                "query": _s(_first(row, ALIASES["query"])),

                # DESCRIPTION / LOG SOURCE
                "description": _s(_first(row, ALIASES["settings.description"])),
                "log_source": _first_list(row, ALIASES["settings.log_source"], self.split_seps),

                # INTERVAL / FLUSH / THROTTLING
                "search_interval_minute": _int_or_none(
                    _first(row, ALIASES["settings.livesearch_data.search_interval_minute"])
                ) or 0,
                "flush_on_trigger": _s(_first(row, ALIASES["settings.flush_on_trigger"])).lower()
                in {"on", "true", "1", "yes"},
                "throttling_enabled": _s(_first(row, ALIASES["settings.throttling_enabled"])).lower()
                in {"on", "true", "1", "yes"},
                "throttling_field": _s(_first(row, ALIASES["settings.throttling_field"])),
                "throttling_time_range": _int_or_none(_first(row, ALIASES["settings.throttling_time_range"])) or 0,

                # CONTEXT / ACTIVE
                "alert_context_template": _s(_first(row, ALIASES["settings.context_template"])),
                "active": _s(_first(row, ALIASES["settings.active"])).lower() in {"on", "true", "1", "yes"},

                # REPOS normalisés (mapping appliqué si feuille Repo dispo)
                "repos": _first_list(row, ALIASES["settings.repos"], self.split_seps),

                # Timerange bruts (convertis plus tard)
                "timerange_minute": t_min,
                "timerange_hour": t_hour,
                "timerange_day": t_day,
                "timerange_second": t_sec,
            }

            # Normalisation repos via util commun (comme autres modules)
            desired["repos"] = normalize_repo_list_for_tenant(
                desired.get("repos", []),
                tenant_ctx=self.ctx,
                use_tenant_ip=bool(prof.get_option("repos_use_tenant_ip_private", default=True)),
                enable_repo_sheet_mapping=bool(prof.get_option("repo_sheet_mapping_enabled", default=True)),
                xlsx_reader=self.xlsx_reader,  # BaseImporter fournit un reader si besoin pour la feuille Repo
                repo_map_df=repo_map_df,       # on passe direct si déjà lue
            )

            # Choisir une seule unité de timerange
            prio = prof.get_option("timerange_priority", default=["minute", "hour", "day"])
            pick = None
            for unit in prio:
                key = f"timerange_{unit}"
                val = desired.get(key)
                if isinstance(val, int) and val > 0:
                    pick = key
                    break
            for unit in ("minute", "hour", "day"):
                key = f"timerange_{unit}"
                if key != pick and key in desired:
                    desired.pop(key)
            # on ignore seconds côté API MyRules
            desired.pop("timerange_second", None)

            log.debug(
                "XLSX row parsed name=%s repos=%d timerange_keys=%s",
                name,
                len(desired.get("repos", [])),
                [k for k in ("timerange_minute", "timerange_hour", "timerange_day") if k in desired],
            )
            yield desired

    # -------------------------- existing map key --------------------------
    def desired_key(self, desired_row: Dict[str, Any]) -> str:  # used by BaseImporter
        # La clé de correspondance est le searchname (ici "name" dans desired)
        return _s(desired_row.get("name"))

    # --------------------------- payload builders ---------------------------
    def _resolve_owner(self, desired_row: Dict[str, Any]) -> str:
        # 0) si déjà présent (future-proof)
        ov = _s(desired_row.get("owner"))
        if ov:
            return ov

        prof = self._load_profile()

        # 1) profiles.yml
        owner_from_profile = _s(prof.get_option("default_owner", default=""))
        if owner_from_profile:
            log.debug("owner resolved from profiles.yml: %s", owner_from_profile)
            return owner_from_profile

        # 2) env
        env_owner = _s(os.getenv("LP_ALERT_OWNER", ""))
        if env_owner:
            log.debug("owner resolved from env LP_ALERT_OWNER: %s", env_owner)
            return env_owner

        # 3) contexte (token)
        ctx = getattr(self, "ctx", None)
        if ctx is not None:
            for attr in ("owner_id", "user_id", "username"):
                v = _s(getattr(ctx, attr, None))
                if v:
                    log.debug("owner resolved from context %s: %s", attr, v)
                    return v

        return ""

    def build_payload_create(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        # mappe "name" -> "searchname" + applique owner & garde-fous
        payload: Dict[str, Any] = {}

        # Champs whitelists (profiles.yml)
        prof = self._load_profile()
        whitelist_post = set(
            (prof.get("api") or {}).get("methods", {}).get("post", {}).get("whitelist", [])  # type: ignore
        )
        if not whitelist_post:
            # fallback safe si le profil est incomplet
            whitelist_post = {
                "searchname", "owner", "risk", "repos", "aggregate",
                "condition_option", "condition_value", "limit",
                "timerange_minute", "timerange_hour", "timerange_day",
                "query", "description", "log_source", "search_interval_minute",
                "flush_on_trigger", "throttling_enabled", "throttling_field",
                "throttling_time_range", "alert_context_template",
            }

        # Remap name -> searchname
        name = _s(desired_row.get("name"))
        if name:
            payload["searchname"] = name

        # Copier le reste
        for k, v in desired_row.items():
            if k == "name":
                continue
            if v in (None, ""):
                continue
            payload[k] = v

        # Owner
        payload["owner"] = self._resolve_owner(desired_row)

        # Gardes obligatoires
        if not _s(payload.get("owner")):
            raise ValidationError("owner is required and could not be resolved from context")

        repos = payload.get("repos") or []
        if not isinstance(repos, list) or not repos:
            raise ValidationError("repos is required and must be a non-empty list")

        # Timerange : au max une clé (déjà géré plus haut, garde au cas où)
        present_tr = [k for k in ("timerange_minute", "timerange_hour", "timerange_day") if k in payload]
        if len(present_tr) > 1:
            # garder la première selon priorité profile
            prio = prof.get_option("timerange_priority", default=["minute", "hour", "day"])
            keep = None
            for unit in prio:
                key = f"timerange_{unit}"
                if key in payload:
                    keep = key
                    break
            for k in ("timerange_minute", "timerange_hour", "timerange_day"):
                if k != keep and k in payload:
                    payload.pop(k, None)

        # Booleans: true -> "on", false -> absent (convention MyRules)
        def onoff(key: str) -> None:
            if key in payload:
                val = payload.get(key)
                if isinstance(val, bool):
                    if val:
                        payload[key] = "on"
                    else:
                        payload.pop(key, None)

        onoff("flush_on_trigger")
        onoff("throttling_enabled")

        # Appliquer whitelist POST
        payload = {k: v for k, v in payload.items() if k in whitelist_post}

        return payload

    def build_payload_update(self, desired_row: Dict[str, Any], existing: Dict[str, Any]) -> Dict[str, Any]:
        payload = self.build_payload_create(desired_row)
        payload.pop("searchname", None)  # pas modifiable en update
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
            # Ne pas faire exploser le run, renvoyer une erreur propre
            log.error("API error for alert=%s [node=%s]: %s", name, node.name, exc)
            return {"status": "Failed", "error": str(exc)}
