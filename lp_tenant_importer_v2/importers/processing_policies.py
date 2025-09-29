# lp_tenant_importer_v2/importers/processing_policies.py
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

from .base import BaseImporter
from ..core.config import NodeRef
from ..core.director_client import DirectorClient
from ..utils.validators import ValidationError, require_columns

log = logging.getLogger(__name__)


# ------------------------- Helpers ------------------------- #

_EMPTY_SENTINELS = {"", "nan", "none", "null", "-"}


def _is_blank(x: Any) -> bool:
    """Return True if value is considered empty per project conventions."""
    if x is None:
        return True
    if isinstance(x, float) and pd.isna(x):
        return True
    s = str(x).strip()
    return s == "" or s.lower() in _EMPTY_SENTINELS


def _norm_str(x: Any) -> str:
    """Trim string and normalize empties to empty string."""
    if _is_blank(x):
        return ""
    return str(x).strip()


def _node_tag(node: NodeRef) -> str:
    name = getattr(node, "name", None) or getattr(node, "id", "")
    nid = getattr(node, "id", "")
    return f"{name}|{nid}"


@dataclass(frozen=True)
class _DesiredPP:
    """Intermediate desired row (names only; ids resolved per node at apply-time)."""

    name: str
    norm_policy: str
    enrich_policy_name: str  # empty string means "not set" (== API 'None')
    routing_policy_name: str  # REQUIRED; empty means invalid and will be SKIPPED


# ------------------------ Importer ------------------------ #

class ProcessingPoliciesImporter(BaseImporter):
    """
    Processing Policies importer (DirectorSync v2).

    Excel contract
    --------------
    Required sheets:
      * ProcessingPolicy
      * EnrichmentPolicy
      * RoutingPolicy

    Expected columns (case-insensitive):
      * ProcessingPolicy:
          - cleaned_policy_name (preferred) or original_policy_name (fallback)
          - norm_policy (name of a Normalization Policy)
          - enrich_policy (source EP "policy_id"; may be empty meaning "None")
          - routing_policy_id (source RP "policy_id"; REQUIRED)
      * EnrichmentPolicy: policy_id, policy_name
      * RoutingPolicy:    policy_id, cleaned_policy_name

    Diff model
    ----------
    We compare **names** only to stay node-agnostic during the diff phase:
      compare_keys = ("norm_policy", "enrich_policy_name", "routing_policy_name")

    At apply-time, names are resolved to IDs per node. If a dependency (NP/EP/RP)
    is missing on the node, we **SKIP** with an explicit reason.

    API payload (create/update)
    ---------------------------
    {
      "policy_name": <str>,                 # desired.name
      "active": true,                       # XLSX "active" intentionally ignored
      "norm_policy": <str>,                 # desired.norm_policy
      "enrich_policy": <uuid|string|'None'>,# EP id or literal "None"
      "routing_policy": <uuid|string>       # RP id
    }
    """

    # ---- BaseImporter contract ----
    resource_name = "processing_policies"
    sheet_names = ("ProcessingPolicy", "EnrichmentPolicy", "RoutingPolicy")
    # Per-sheet validation is custom (we don't use BaseImporter.required_columns here)
    compare_keys = ("norm_policy", "enrich_policy_name", "routing_policy_name")

    # Director API resource name
    RESOURCE = "ProcessingPolicy"

    def __init__(self) -> None:
        super().__init__()
        # Per-node caches (filled in fetch_existing)
        self._norm_names: Dict[str, set] = {}              # node.id -> {NP names}
        self._ep_name_to_id: Dict[str, Dict[str, str]] = {}  # node.id -> {EP name: id}
        self._ep_id_to_name: Dict[str, Dict[str, str]] = {}  # node.id -> {EP id: name}
        self._rp_name_to_id: Dict[str, Dict[str, str]] = {}  # node.id -> {RP name: id}
        self._rp_id_to_name: Dict[str, Dict[str, str]] = {}  # node.id -> {RP id: name}

        # XLSX-level caches (source-id -> name) for validation / mapping
        self._xlsx_ep_id_to_name: Dict[str, str] = {}
        self._xlsx_rp_id_to_name: Dict[str, str] = {}

    # ------------------------------ Validate ------------------------------ #

    def validate(self, sheets: Dict[str, pd.DataFrame]) -> None:  # type: ignore[override]
        # Sheets presence
        for sh in self.sheet_names:
            if sh not in sheets:
                raise ValidationError(f"Missing required sheet '{sh}'")

        pp = sheets["ProcessingPolicy"]
        ep = sheets["EnrichmentPolicy"]
        rp = sheets["RoutingPolicy"]

        # Required headers per sheet (case-insensitive)
        def _cols(df: pd.DataFrame) -> Dict[str, str]:
            return {str(c).strip().lower(): str(c) for c in df.columns}

        pp_cols = _cols(pp)
        ep_cols = _cols(ep)
        rp_cols = _cols(rp)

        # ProcessingPolicy columns (allow original_policy_name fallback)
        need_pp = ["norm_policy", "enrich_policy", "routing_policy_id"]
        for col in need_pp:
            if col not in pp_cols:
                raise ValidationError(f"ProcessingPolicy: missing required column '{col}'")
        if "cleaned_policy_name" not in pp_cols and "original_policy_name" not in pp_cols:
            raise ValidationError(
                "ProcessingPolicy: one of 'cleaned_policy_name' or 'original_policy_name' is required"
            )

        # EnrichmentPolicy / RoutingPolicy mapping columns
        for col in ("policy_id", "policy_name"):
            if col not in ep_cols:
                raise ValidationError(f"EnrichmentPolicy: missing required column '{col}'")
        for col in ("policy_id", "cleaned_policy_name"):
            if col not in rp_cols:
                raise ValidationError(f"RoutingPolicy: missing required column '{col}'")

        log.info("processing_policies: validation passed (sheets present & columns OK)")

    # --------------------------- Desired from XLSX --------------------------- #

    def iter_desired(self, sheets: Dict[str, "pd.DataFrame"]) -> Iterable[Dict[str, Any]]:
        """Yield desired rows with names only; IDs are resolved per node at apply-time."""
        pp = sheets["ProcessingPolicy"].copy()
        ep = sheets["EnrichmentPolicy"].copy()
        rp = sheets["RoutingPolicy"].copy()

        # Normalize headers (preserve original names in dataframes)
        pp.columns = [str(c).strip() for c in pp.columns]
        ep.columns = [str(c).strip() for c in ep.columns]
        rp.columns = [str(c).strip() for c in rp.columns]

        # Build source-id -> name maps at workbook level (used for early sanity)
        self._xlsx_ep_id_to_name = {
            str(r["policy_id"]): _norm_str(r["policy_name"])
            for _, r in ep.iterrows()
            if "policy_id" in r and "policy_name" in r and not _is_blank(r["policy_id"])
        }
        self._xlsx_rp_id_to_name = {
            str(r["policy_id"]): _norm_str(r["cleaned_policy_name"])
            for _, r in rp.iterrows()
            if "policy_id" in r and "cleaned_policy_name" in r and not _is_blank(r["policy_id"])
        }

        # Resolve policy_name + dependency names per PP row
        def _pp_name(sr: pd.Series) -> str:
            name = _norm_str(sr.get("cleaned_policy_name"))
            if not name:
                name = _norm_str(sr.get("original_policy_name"))
            return name

        for _, row in pp.iterrows():
            name = _pp_name(row)
            if not name:
                # Silently ignore rows without a name (aligns with v1 tolerance)
                continue

            norm_policy = _norm_str(row.get("norm_policy"))

            # EP source-id -> name (empty id means "None")
            ep_src_id = _norm_str(row.get("enrich_policy"))
            ep_name = self._xlsx_ep_id_to_name.get(ep_src_id, "") if ep_src_id else ""

            # RP source-id -> name (REQUIRED)
            rp_src_id = _norm_str(row.get("routing_policy_id"))
            rp_name = self._xlsx_rp_id_to_name.get(rp_src_id, "") if rp_src_id else ""

            desired = _DesiredPP(
                name=name,
                norm_policy=norm_policy,
                enrich_policy_name=ep_name,
                routing_policy_name=rp_name,
            )
            yield {
                "name": desired.name,
                "norm_policy": desired.norm_policy,
                "enrich_policy_name": desired.enrich_policy_name,
                "routing_policy_name": desired.routing_policy_name,
            }

    def key_fn(self, desired_row: Dict[str, Any]) -> str:
        return str(desired_row.get("name") or "").strip()

    # ------------------------ Canonical for diff ------------------------ #

    def canon_desired(self, desired_row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "norm_policy": _norm_str(desired_row.get("norm_policy")),
            "enrich_policy_name": _norm_str(desired_row.get("enrich_policy_name")),
            "routing_policy_name": _norm_str(desired_row.get("routing_policy_name")),
        }

    def canon_existing(self, existing_obj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not existing_obj:
            return None
        # fetch_existing enriches objects with *_name fields
        return {
            "norm_policy": _norm_str(existing_obj.get("norm_policy")),
            "enrich_policy_name": _norm_str(
                existing_obj.get("enrich_policy_name")
                or existing_obj.get("enrich_name")  # safety
            ),
            "routing_policy_name": _norm_str(
                existing_obj.get("routing_policy_name")
                or existing_obj.get("routing_name")  # safety
            ),
        }

    # ------------------------- Director API I/O ------------------------- #

    def fetch_existing(
        self, client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, Dict[str, Any]]:
        """
        Return {policy_name -> existing_obj} for the node.
        Also fills per-node caches for NP/EP/RP to support SKIP and id resolution.
        """
        node_t = _node_tag(node)
        log.info("fetch_existing: start [node=%s]", node_t)

        # --- NormalizationPolicy (names only) ---
        self._norm_names[node.id] = self._list_normalization_names(client, pool_uuid, node)

        # --- EnrichmentPolicy (name <-> id maps) ---
        ep_map = self._list_enrichment_policies(client, pool_uuid, node)  # name->id
        self._ep_name_to_id[node.id] = ep_map
        self._ep_id_to_name[node.id] = {v: k for k, v in ep_map.items()}

        # --- RoutingPolicies (name <-> id maps) ---
        rp_map = self._list_routing_policies(client, pool_uuid, node)  # name->id
        self._rp_name_to_id[node.id] = rp_map
        self._rp_id_to_name[node.id] = {v: k for k, v in rp_map.items()}

        # --- ProcessingPolicy (existing list) ---
        data = client.list_resource(pool_uuid, node.id, self.RESOURCE) or []
        if isinstance(data, dict):
            items_any = data.get("data") or data.get("items") or data.get("results") or []
            items = [x for x in items_any if isinstance(x, dict)]
        elif isinstance(data, list):
            items = [x for x in data if isinstance(x, dict)]
        else:
            items = []

        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            # API may use "name" or "policy_name"
            name = _norm_str(it.get("name") or it.get("policy_name"))
            if not name:
                continue

            # Attach name-friendly fields for diff
            ep_id = _norm_str(it.get("enrich_policy"))
            rp_id = _norm_str(it.get("routing_policy"))

            it["enrich_policy_name"] = self._ep_id_to_name[node.id].get(ep_id, "")
            it["routing_policy_name"] = self._rp_id_to_name[node.id].get(rp_id, "")

            out[name] = it

        log.info("fetch_existing: found %d processing policies [node=%s]", len(out), node_t)
        log.debug("fetch_existing: names=%s [node=%s]", sorted(out.keys()), node_t)
        return out

    # ----------------------------- Apply ops ---------------------------- #

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: NodeRef,
        decision,
        existing_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Apply the decision (CREATE/UPDATE/NOOP/SKIP) with strict dependency checks.
        """
        desired = dict(decision.desired or {})
        name = desired.get("name") or "(unnamed)"
        node_t = _node_tag(node)

        log.info(
            "apply: op=%s policy=%s [node=%s]",
            getattr(decision, "op", "?"),
            name,
            node_t,
        )

        # ---- Dependency checks on the node ----
        norm_name = _norm_str(desired.get("norm_policy"))
        ep_name = _norm_str(desired.get("enrich_policy_name"))
        rp_name = _norm_str(desired.get("routing_policy_name"))

        # 1) Routing policy is required
        if not rp_name:
            msg = "Missing mandatory routing_policy (name empty from XLSX mapping)"
            log.warning("apply: SKIP policy=%s reason=%s [node=%s]", name, msg, node_t)
            return {"status": "Skipped", "error": msg}

        # 2) Normalization policy must exist by name on the node
        if norm_name and norm_name not in self._norm_names.get(node.id, set()):
            msg = f"Unknown norm_policy on node: '{norm_name}'"
            log.warning("apply: SKIP policy=%s reason=%s [node=%s]", name, msg, node_t)
            return {"status": "Skipped", "error": msg}

        # 3) Enrichment policy (if provided) must exist on the node
        if ep_name and ep_name not in self._ep_name_to_id.get(node.id, {}):
            msg = f"Unknown enrich_policy on node: '{ep_name}'"
            log.warning("apply: SKIP policy=%s reason=%s [node=%s]", name, msg, node_t)
            return {"status": "Skipped", "error": msg}

        # 4) Routing policy must exist on the node
        if rp_name not in self._rp_name_to_id.get(node.id, {}):
            msg = f"Unknown routing_policy on node: '{rp_name}'"
            log.warning("apply: SKIP policy=%s reason=%s [node=%s]", name, msg, node_t)
            return {"status": "Skipped", "error": msg}

        # ---- Build API payload (resolve names -> ids) ----
        ep_id = self._ep_name_to_id.get(node.id, {}).get(ep_name, "None") if ep_name else "None"
        rp_id = self._rp_name_to_id.get(node.id, {}).get(rp_name, "")

        payload = {
            "policy_name": desired["name"],
            "active": True,  # keep consistent with RP importer (XLSX 'active' ignored)
            "norm_policy": norm_name,
            "enrich_policy": ep_id if ep_id else "None",
            "routing_policy": rp_id,
        }
        log.debug("apply: payload=%s [node=%s]", payload, node_t)

        # ---- Execute via generic client helpers ----
        if decision.op == "CREATE":
            res = client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
            return {
                "status": res.get("status"),
                "monitor_ok": res.get("monitor_ok"),
                "monitor_branch": res.get("monitor_branch"),
            }

        if decision.op == "UPDATE" and existing_id:
            res = client.update_resource(pool_uuid, node.id, self.RESOURCE, existing_id, payload)
            return {
                "status": res.get("status"),
                "monitor_ok": res.get("monitor_ok"),
                "monitor_branch": res.get("monitor_branch"),
            }

        # NOOP / SKIP (BaseImporter handles SKIP in the planning phase; here we just report success)
        log.info("apply: NOOP policy=%s [node=%s]", name, node_t)
        return {"status": "Success"}

    # ------------------------------- Internals ------------------------------- #

    @staticmethod
    def _list_normalization_names(client: DirectorClient, pool_uuid: str, node: NodeRef) -> set:
        """Return a set of available NormalizationPolicy names on the node."""
        names: set = set()
        try:
            data = client.list_resource(pool_uuid, node.id, "NormalizationPolicy") or {}
            items = (data.get("data") if isinstance(data, dict) else data) or []
            for it in items:
                nm = _norm_str(it.get("name"))
                if nm:
                    names.add(nm)
        except Exception as exc:  # pragma: no cover (defensive)
            log.error("list_normalization_names: failed [node=%s] err=%s", _node_tag(node), exc)
        return names

    @staticmethod
    def _list_enrichment_policies(
        client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, str]:
        """Return {name -> id} for EnrichmentPolicy."""
        out: Dict[str, str] = {}
        try:
            data = client.list_resource(pool_uuid, node.id, "EnrichmentPolicy") or {}
            items = (data.get("data") if isinstance(data, dict) else data) or []
            for it in items:
                nm = _norm_str(it.get("name") or it.get("policy_name"))
                pid = _norm_str(it.get("id"))
                if nm and pid:
                    out[nm] = pid
        except Exception as exc:  # pragma: no cover (defensive)
            log.error("list_enrichment_policies: failed [node=%s] err=%s", _node_tag(node), exc)
        return out

    @staticmethod
    def _list_routing_policies(
        client: DirectorClient, pool_uuid: str, node: NodeRef
    ) -> Dict[str, str]:
        """Return {name -> id} for RoutingPolicies."""
        out: Dict[str, str] = {}
        try:
            data = client.list_resource(pool_uuid, node.id, "RoutingPolicies") or {}
            items = (data.get("data") if isinstance(data, dict) else data) or []
            for it in items:
                nm = _norm_str(it.get("name") or it.get("policy_name"))
                pid = _norm_str(it.get("id"))
                if nm and pid:
                    out[nm] = pid
        except Exception as exc:  # pragma: no cover (defensive)
            log.error("list_routing_policies: failed [node=%s] err=%s", _node_tag(node), exc)
        return out
