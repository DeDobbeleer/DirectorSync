"""
Configuration loader for DirectorSync v2.

This module resolves environment configuration and parses the tenants YAML.
The **public contract** is intentionally identical to v1 for end-users,
but internally we enforce *global-only* `defaults.target[...]`.

Key rules:
  * `.env` provides LP_DIRECTOR_URL, LP_DIRECTOR_API_TOKEN, LP_TENANTS_FILE
  * `tenants.yml` must have top-level `tenants` and `defaults`
  * We **ignore** tenant-level `defaults.target` with a WARNING
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

class ConfigError(Exception):
    """Raised when runtime configuration cannot be resolved."""
    pass


@dataclass(frozen=True)
class NodeRef:
    """A minimal reference to a SIEM node (id + name)."""
    id: str
    name: str


@dataclass
class TenantConfig:
    """Resolved tenant configuration object.

    Attributes:
        name: Tenant name.
        pool_uuid: Pool UUID where tenant resources live.
        siems: Mapping of roles to node lists: ``backends``, ``search_heads``, ``all_in_one``.
        defaults: Global defaults block (must include ``target``).
    """
    name: str
    pool_uuid: str
    siems: Dict[str, List[NodeRef]]
    defaults: Dict[str, Any]


@dataclass
class Config:
    """Runtime configuration resolved from `.env` and `tenants.yml`."""
    director_url: str
    api_token: str
    tenants_file: Path

    @classmethod
    def from_env(cls) -> "Config":
        """Load `.env` and build a :class:`Config` instance.
        Raises:
            ConfigError: If required environment variables are missing.
        """
        env_path = find_dotenv(usecwd=True) or ""
        load_dotenv(env_path, override=True)
        director_url = os.getenv("LP_DIRECTOR_URL")
        api_token = os.getenv("LP_DIRECTOR_API_TOKEN")
        tenants_file = os.getenv("LP_TENANTS_FILE")

        missing = [k for k, v in {
            "LP_DIRECTOR_URL": director_url,
            "LP_DIRECTOR_API_TOKEN": api_token,
            "LP_TENANTS_FILE": tenants_file,
        }.items() if not v]
        if missing:
            hint = (
                "Create a .env at the repo root or export them in your shell. "
                "Example:\n"
                "  LP_DIRECTOR_URL=https://director.example.local\n"
                "  LP_DIRECTOR_API_TOKEN=***\n"
                "  LP_TENANTS_FILE=./tenants.yml\n"
            )
            raise ConfigError(
                "Missing required environment variables: "
                + ", ".join(missing)
                + ". " + hint
            )

        return cls(director_url=director_url, api_token=api_token, tenants_file=Path(tenants_file))

    def load_tenants(self) -> Dict[str, Any]:
        """Read and parse the tenants YAML into a raw dict.

        Raises:
            ConfigError: If mandatory top-level keys are missing.
        """
        with open(self.tenants_file, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if "tenants" not in data or "defaults" not in data:
            raise ConfigError("tenants.yml must contain 'tenants' and 'defaults' top-level keys")
        return data

    def get_tenant(self, tenant_name: str) -> TenantConfig:
        """Resolve a :class:`TenantConfig` by tenant name.

        Notes:
            If a tenant has `defaults.target`, it is ignored and a WARNING is logged.
        """
        data = self.load_tenants()
        t_block = data["tenants"].get(tenant_name)
        if not t_block:
            raise ConfigError(f"Tenant '{tenant_name}' not found in {self.tenants_file}")

        pool_uuid = t_block.get("pool_uuid")
        if not pool_uuid:
            raise ConfigError(f"Tenant '{tenant_name}' missing 'pool_uuid'")

        siems = t_block.get("siems") or {}
        # warn & ignore tenant-level defaults.target
        t_defaults = t_block.get("defaults") or {}
        if "target" in t_defaults:
            log.warning("Ignoring tenant-level defaults.target for tenant '%s' (global-only targets used).", tenant_name)

        defaults = data.get("defaults") or {}
        if "target" not in defaults:
            raise ConfigError("Global 'defaults.target' missing in tenants.yml")

        def to_nodes(lst: Optional[List[Dict[str, str]]]) -> List[NodeRef]:
            res: List[NodeRef] = []
            for it in lst or []:
                nid, nname = it.get("id"), it.get("name")
                if not nid or not nname:
                    raise ConfigError("Every node must have 'id' and 'name' fields")
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
        """Resolve target nodes for a given element from **global** defaults only.

        Args:
            tenant: Resolved tenant configuration.
            element: Element key, e.g. ``"repos"`` or ``"processing_policies"``.

        Returns:
            De-duplicated list of :class:`NodeRef` representing the target nodes.

        Raises:
            ConfigError: If the element is not configured under ``defaults.target``.
        """
        targets_cfg = (tenant.defaults.get("target") or {}).get(element)
        if not targets_cfg:
            raise ConfigError(f"Global defaults.target.{element} missing in tenants.yml")

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
