# lp_tenant_importer_v2/importers/registry.py
"""Importer registry for DirectorSync v2."""

from __future__ import annotations
from dataclasses import dataclass
from importlib import import_module
from typing import Callable, Dict, Iterable, Type

# -------- Importer classes (full pipeline) ----------------------------------

@dataclass(frozen=True)
class ImporterSpec:
    key: str                # defaults.targets key in tenants.yml
    cli: str                # subcommand name
    help: str               # argparse help
    module: str             # module path
    class_name: str         # class symbol in module
    element_key: str        # same as key in most cases

    def load_class(self):
        mod = import_module(self.module)
        return getattr(mod, self.class_name)

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
    # Device Groups
    "device_groups": ImporterSpec(
        key="device_groups",
        cli="import-device-groups",
        help="Import device groups",
        module="lp_tenant_importer_v2.importers.device_groups",
        class_name="DeviceGroupsImporter",
        element_key="device_groups",
    ),
    # Devices
    "devices": ImporterSpec(
        key="devices",
        cli="import-devices",
        help="Import devices",
        module="lp_tenant_importer_v2.importers.devices",
        class_name="DevicesImporter",
        element_key="devices",
    ),
    # Syslog Collectors
    "syslog_collectors": ImporterSpec(
        key="syslog_collectors",
        cli="import-syslog-collectors",
        help="Import syslog collectors",
        module="lp_tenant_importer_v2.importers.syslog_collectors",
        class_name="SyslogCollectorsImporter",
        element_key="syslog_collectors",
    ),
    # Alert Rules
    "alert_rules": ImporterSpec(
        key="alert_rules",
        cli="import-alert-rules",
        help="Import alert rules",
        module="lp_tenant_importer_v2.importers.alert_rules",
        class_name="AlertRulesImporter",
        element_key="alert_rules",
    ),
    # Alert Rules - Report-only XLSX lister
    "alert_rules_report": ImporterSpec(
        key="alert_rules_report",
        element_key="alert_rules",
        cli="list-alert-users",
        help="List AlertRules Name/Owner/Assign_to/Visible_for from XLSX",
        module="lp_tenant_importer_v2.importers.alert_rules_report",
        class_name="AlertRulesXlsxLister",
    ),
    
}

def get_spec_by_key(key: str) -> ImporterSpec:
    return _IMPORTERS[key]

def iter_specs() -> Iterable[ImporterSpec]:
    return _IMPORTERS.values()
