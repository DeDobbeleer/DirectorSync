# lp_tenant_importer_v2/importers/registry.py
"""Importer registry for DirectorSync v2.

This tiny module centralizes importer discovery so that `main.py` can
programmatically generate CLI subcommands and route to a single generic
handler. Adding a new importer now means adding **one entry** below.

Keep entries minimal: no heavy imports at module import time; dynamic import is
used when the command actually runs.
"""
from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Callable, Dict, Optional, Type


@dataclass(frozen=True)
class ImporterSpec:
    """Declarative description of an importer.

    Attributes:
        key: Stable key used by tenants.yml defaults.target (e.g. "repos").
        cli: CLI subcommand name (e.g. "import-repos").
        help: Short help string for argparse.
        module: Python module path to import (lazy imported at runtime).
        class_name: Importer class symbol inside the module.
        element_key: defaults.target key used to resolve target nodes.
    """

    key: str
    cli: str
    help: str
    module: str
    class_name: str
    element_key: str

    def load_class(self):
        mod = import_module(self.module)
        return getattr(mod, self.class_name)


# --- Registry ---------------------------------------------------------------

_IMPORTERS: Dict[str, ImporterSpec] = {
    # Repositories
    "repos": ImporterSpec(
        key="repos",
        cli="import-repos",
        help="Import repositories",
        module="lp_tenant_importer_v2.importers.repos",
        class_name="ReposImporter",
        element_key="repos",
    ),
    # Routing Policies
    "routing_policies": ImporterSpec(
        key="routing_policies",
        cli="import-routing-policies",
        help="Import routing policies",
        module="lp_tenant_importer_v2.importers.routing_policies",
        class_name="RoutingPoliciesImporter",
        element_key="routing_policies",
    ),
    # Normalization Policies
    "normalization_policies": ImporterSpec(
        key="normalization_policies",
        cli="import-normalization-policies",
        help="Import normalization policies",
        module="lp_tenant_importer_v2.importers.normalization_policies",
        class_name="NormalizationPoliciesImporter",
        element_key="normalization_policies",
    ),    
    # Enrichment Policies
    "enrichment_policies": ImporterSpec(
        key="enrichment_policies",
        cli="import-enrichment-policies",
        help="Import enrichment policies",
        module="lp_tenant_importer_v2.importers.enrichment_policies",
        class_name="EnrichmentPoliciesImporter",
        element_key="enrichment_policies",
    ),
    # Processing Policies
    "processing_policies": ImporterSpec(
        key="processing_policies",
        cli="import-processing-policies",
        help="Import processing policies",
        module="lp_tenant_importer_v2.importers.processing_policies",
        class_name="ProcessingPoliciesImporter",
        element_key="processing_policies",
    ),
    
    # DeviceGroups
    "device_groups": ImporterSpec(
        key="device_groups",
        cli="import-device-groups",
        help="Import device groups",
        module="lp_tenant_importer_v2.importers.device_groups",
        class_name="DeviceGroupsImporter",
        element_key="device_groups",
    ),

}


def get_spec_by_key(key: str) -> ImporterSpec:
    return _IMPORTERS[key]


def iter_specs():
    return _IMPORTERS.values()