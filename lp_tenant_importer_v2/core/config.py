"""
Configuration loader: .env + tenants.yml (global targets only).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from dotenv import find_dotenv, load_dotenv

from .logging_utils import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class NodeRef:
    id: str
    name: str


@dataclass
class TenantConfig:
    name: str
    pool_uuid: str
    siems: Dict[str, List[NodeRef]]  # keys: backends, search_heads, all_in_one
    defaults: Dict[str, Any]  # expected to contain "target" (global)


@dataclass
class Config:
    director_url: str
    api_token: str
    tenants_file: Path

    @classmethod
    def from_env(cls) -> "Config":
        env_path = find_dotenv(usecwd=True) or ""
        load_dotenv(env_path, override=True)
        director_url = os.getenv("LP_DIRECTOR_URL")
        api_token = os.getenv("LP_DIRECTOR_API_TOKEN")
        tenants_file = os.getenv("LP_TENANTS_FILE")

        if not director_url or not api_token or not tenants_file:
            raise ValueError("Missing env: LP_DIRECTOR_URL, LP_DIRECTOR_API_TOKEN, LP_TENANTS_FILE")

        return cls(director_url=director_url, api_token=api_token, tenants_file=Path(tenants_file))

    def load_tenants(self) -> Dict[str, Any]:
        with open(self.tenants_file, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if "tenants" not in data or "defaults" not in data:
            raise ValueError("tenants.yml must contain 'tenants' and 'defaults' top-level keys")
        return data

    def get_tenant(self, tenant_name: str) -> TenantConfig:
        data = self.load_tenants()
        t_block = data["tenants"].get(tenant_name)
        if not t_block:
            raise KeyError(f"Tenant '{tenant_name}' not found in {self.tenants_file}")

        pool_uuid = t_block.get("pool_uuid")
        if not pool_uuid:
            raise ValueError(f"Tenant '{tenant_name}' missing 'pool_uuid'")

        siems = t_block.get("siems") or {}
        # warn & ignore tenant-level defaults.target
        t_defaults = t_block.get("defaults") or {}
        if "target" in t_defaults:
            log.warning("Ignoring tenant-level defaults.target for tenant '%s' (global-only targets used).", tenant_name)

        defaults = data.get("defaults") or {}
        if "target" not in defaults:
            raise ValueError("Global 'defaults.target' missing in tenants.yml")

        def to_nodes(lst: Optional[List[Dict[str, str]]]) -> List[NodeRef]:
            res: List[NodeRef] = []
            for it in lst or []:
                nid, nname = it.get("id"), it.get("name")
                if not nid or not nname:
                    raise ValueError("Every node must have 'id' and 'name' fields")
                res.append(NodeRef(id=str(nid), name=str(nname)))
            return res

        siems_norm = {
            "backends": to_nodes(siems.get("backends")),
            "search_heads": to_nodes(siems.get("search_heads")),
            "all_in_one": to_nodes(siems.get("all_in_one")),
        }

        return TenantConfig(
            name=tenant_name,
            pool_uuid=str(pool_uuid),
            siems=siems_norm,
            defaults=defaults,
        )

    def get_targets(self, tenant: TenantConfig, element: str) -> List[NodeRef]:
        """
        Resolve target roles for a given element from global defaults ONLY.
        Raises if element is absent. Returns a de-duplicated list of nodes.
        """
        targets_cfg = (tenant.defaults.get("target") or {}).get(element)
        if not targets_cfg:
            raise ValueError(f"Global defaults.target.{element} missing in tenants.yml")

        role_to_nodes = {
            "backends": tenant.siems["backends"],
            "search_heads": tenant.siems["search_heads"],
            "all_in_one": tenant.siems["all_in_one"],
        }

        nodes: List[NodeRef] = []
        for role in targets_cfg:
            nodes.extend(role_to_nodes.get(role, []))
        # Dedup by (id, name)
        d = {(n.id, n.name): n for n in nodes}
        return list(d.values())
