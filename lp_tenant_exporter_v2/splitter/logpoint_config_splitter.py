import argparse
import json
import os
import sys
import logging
import pandas as pd
from typing import List, Dict
import re
from collections import defaultdict

from device_tenant_resolver import determine_device_tenant  # <= NEW
# === NEW (alerts) ===
from alert_export import load_alerts_df, write_alert_sheet_per_tenant, ALERT_SHEET  # <= NEW

SCRIPT_NAME = "logpoint_config_splitter"
DEFAULT_CONFIG_NAME = f"{SCRIPT_NAME}-config.json"
EXCLUDED_REPOS = {"default", "_logpoint", "_LogPointAlerts"}
EXCLUDED_NORMPOLICIES = {"_logpoint", "_LogPointAlerts"}

# Configure logging (identique à l’original)
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

def load_json(filepath: str) -> Dict:
    """Load JSON file with error handling."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"File '{filepath}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode JSON - {e}")
        sys.exit(1)

def clean_name(name: str, tenant_list: List[str]) -> str:
    """
    Clean a name by removing tenant identifiers and joining remaining parts with underscore.
    Handles separators like -, _, and .
    """
    normalized = re.sub(r"[-_.]+", "_", name)
    tokens = normalized.split("_")
    tenant_set = {t.lower() for t in tenant_list}
    cleaned_tokens = [t for t in tokens if t.lower() not in tenant_set and t != ""]
    return "_".join(cleaned_tokens)

# --- NEW: simple fallback name matcher (même logique que str.contains) -----
def match_tenant_by_name(name: str, tenant_list: List[str]) -> str | None:
    low = (name or "").lower()
    # on itère par longueur décroissante pour éviter les collisions genre "es" avant "esrin"
    for t in sorted(tenant_list, key=lambda x: len(x), reverse=True):
        if t.lower() in low:
            return t
    return None

# === EXPORTS D’ENTITÉS — inchangés par rapport à l’original (copy) ===

def extract_repos(sync_data: Dict, tenant_list: List[str]) -> pd.DataFrame:
    """Extract Repo information from the configuration JSON."""
    repos_raw = sync_data.get("Repo", [])
    repo_rows = []

    for repo in repos_raw:
        repo_name = repo.get("name", "")
        if repo_name in EXCLUDED_REPOS:
            continue

        active = repo.get("active", "")
        used_size = repo.get("used_size", "")
        repo_number = repo.get("repo_number", "")
        repopaths = repo.get("repopath", [])

        paths = [path.get("path", "") for path in repopaths]
        retentions = [str(path.get("retention", "")) for path in repopaths]

        cleaned_name = clean_name(repo_name, tenant_list)

        repo_rows.append({
            "repo_number": repo_number,
            "original_repo_name": repo_name,
            "cleaned_repo_name": cleaned_name,
            "storage_paths": " | ".join(paths),
            "retention_days": " | ".join(retentions),
            "active": active,
            "used_size": used_size
        })

    return pd.DataFrame(repo_rows)

def extract_routing_policies(sync_data: Dict, tenant_list: List[str]) -> pd.DataFrame:
    """Extract RoutingPolicy details including rule criteria."""
    policies = sync_data.get("RoutingPolicy", [])
    rows = []

    for policy in policies:
        policy_name = policy.get("policy_name", "")
        active = policy.get("active", "")
        catch_all = policy.get("catch_all", "")
        routing_criteria = policy.get("routing_criteria", [])
        policy_id = policy.get("_id", "")

        cleaned_policy_name = clean_name(policy_name, tenant_list)

        if routing_criteria:
            for criterion in routing_criteria:
                rows.append({
                    "original_policy_name": policy_name,
                    "cleaned_policy_name": cleaned_policy_name,
                    "active": active,
                    "catch_all": catch_all,
                    "rule_type": criterion.get("type", ""),
                    "key": criterion.get("key", ""),
                    "value": criterion.get("value", ""),
                    "repo": criterion.get("repo", ""),
                    "drop": criterion.get("drop", ""),
                    "policy_id": policy_id
                })
        else:
            rows.append({
                "original_policy_name": policy_name,
                "cleaned_policy_name": cleaned_policy_name,
                "active": active,
                "catch_all": catch_all,
                "rule_type": "",
                "key": "",
                "value": "",
                "repo": "",
                "drop": "",
                "policy_id": policy_id
            })

    return pd.DataFrame(rows)

def extract_normalization_policies(sync_data: Dict) -> pd.DataFrame:
    """Extract NormalizationPolicy information, excluding default system policies."""
    policies = sync_data.get("NormPolicy", [])
    filtered = [p for p in policies if p.get("name") not in EXCLUDED_NORMPOLICIES]
    rows = []

    for policy in filtered:
        rows.append({
            "policy_name": policy.get("name", ""),
            "normalization_packages": " | ".join(policy.get("normalization_packages", [])),
            "compiled_normalizer": " | ".join(policy.get("compiled_normalizer", []))
        })

    return pd.DataFrame(rows)

def extract_enrichment_policy_tables(sync_data: Dict) -> Dict[str, pd.DataFrame]:
    policies = sync_data.get("EnrichmentPolicy", [])
    summary_rows = []
    rule_rows = []
    criteria_rows = []

    for policy in policies:
        name = policy.get("name", "")
        description = policy.get("description", "")
        tags = policy.get("tags", [])
        active = policy.get("active", "")
        policy_id = policy.get("_id", "")

        for spec_index, spec in enumerate(policy.get("specifications", [])):
            source = spec.get("source", "")

            summary_rows.append({
                "spec_index": spec_index,
                "policy_name": name,
                "description": description,
                "tags": " | ".join(tags),
                "active": active,
                "source": source,
                "policy_id": policy_id
            })

            for rule in spec.get("rules", []):
                rule_rows.append({
                    "policy_name": name,
                    "source": source,
                    "spec_index": spec_index,
                    "category": rule.get("category", ""),
                    "source_key": rule.get("source_key", ""),
                    "prefix": rule.get("prefix", ""),
                    "operation": rule.get("operation", ""),
                    "type": rule.get("type", ""),
                    "event_key": rule.get("event_key", "")
                })

            for criterion in spec.get("criteria", []):
                criteria_rows.append({
                    "policy_name": name,
                    "source": source,
                    "spec_index": spec_index,
                    "type": criterion.get("type", ""),
                    "key": criterion.get("key", ""),
                    "value": criterion.get("value", "")
                })

    return {
        "EnrichmentPolicy": pd.DataFrame(summary_rows),
        "EnrichmentRules": pd.DataFrame(rule_rows),
        "EnrichmentCriteria": pd.DataFrame(criteria_rows)
    }

def extract_processing_policies(sync_data: Dict, tenant_list: List[str]) -> pd.DataFrame:
    policies = sync_data.get("ProcessingPolicy", [])
    rows = []

    for policy in policies:
        name = policy.get("policy_name", "")
        if name in EXCLUDED_REPOS:
            continue

        cleaned_name = clean_name(name, tenant_list)

        rows.append({
            "original_policy_name": name,
            "cleaned_policy_name": cleaned_name,
            "active": policy.get("active", ""),
            "norm_policy": policy.get("norm_policy", ""),
            "enrich_policy": policy.get("enrich_policy", ""),
            "routing_policy_id": policy.get("routing_policy", ""),
            "policy_id": policy.get("_id", "")
        })

    return pd.DataFrame(rows)

def extract_devices(sync_data: Dict) -> Dict[str, pd.DataFrame]:
    devices = sync_data.get("Device", [])
    device_rows = []
    fetcher_rows = []

    for device in devices:
        device_id = device.get("_id", "")
        row = {
            "device_id": device_id,
            "name": device.get("name", ""),
            "description": device.get("description", ""),
            "type": device.get("type", ""),
            "tags": " | ".join(device.get("tags", [])),
            "ip": " | ".join(device.get("ip", [])),
            "fqdn": device.get("fqdn", ""),
            "active": device.get("active", ""),
            "timezone": device.get("timezone", ""),
            "has_hostname": device.get("has_hostname", ""),
            "device_groups": " | ".join(device.get("device_groups", [])),
            "distributed_collector": " | ".join(device.get("distributed_collector", [])),
            "confidentiality": device.get("risk_values", {}).get("confidentiality", ""),
            "integrity": device.get("risk_values", {}).get("integrity", ""),
            "availability": device.get("risk_values", {}).get("availability", "")
        }
        device_rows.append(row)

        for fetcher in device.get("col_apps", []):
            fetch = {"device_id": device_id, "device_name": device.get("name", "")}
            for k, v in fetcher.items():
                fetch[k] = v
            fetcher_rows.append(fetch)

    return {
        "Device": pd.DataFrame(device_rows),
        "DeviceFetcher": pd.DataFrame(fetcher_rows)
    }

def extract_device_groups(sync_data: Dict) -> pd.DataFrame:
    """Extract all DeviceGroups (multitenant, non filtrés)."""
    groups = sync_data.get("DeviceGroup", [])
    rows = []

    for group in groups:
        rows.append({
            "group_id": group.get("_id", ""),
            "name": group.get("name", ""),
            "description": group.get("description", ""),
            "active": group.get("active", ""),
            "device_ids": " | ".join(group.get("devices", [])),
            "tags": " | ".join(group.get("tags", []))
        })

    return pd.DataFrame(rows)

def extract_users(sync_data: Dict) -> pd.DataFrame:
    """
    Extract users as a flat DataFrame. Dashboards are intentionally ignored.
    The function is non-opinionated (no tenant routing); replication is handled later.
    """
    users = sync_data.get("User", [])
    rows = []
    for user in users:
        rows.append({
            "user_id": user.get("_id", ""),
            "username": user.get("username", ""),
            "fullname": user.get("fullname", ""),
            "email": user.get("email", ""),
            "active": user.get("active", ""),
            "usergroup_id": user.get("usergroup_id", ""),
            # nested fields are JSON-encoded to preserve fidelity
            "preferences": json.dumps(user.get("preferences", {}), ensure_ascii=False),
            "tags": " | ".join(user.get("tags", [])) if isinstance(user.get("tags", []), list) else user.get("tags", ""),
            # NOTE: user dashboards are intentionally skipped
        })
    return pd.DataFrame(rows)

def extract_user_groups(sync_data: Dict) -> pd.DataFrame:
    """Extract user groups as a flat DataFrame (global, no tenant routing)."""
    groups = sync_data.get("UserGroup", [])
    rows = []
    for group in groups:
        rows.append({
            "group_id": group.get("_id", ""),
            "name": group.get("name", ""),
            "description": group.get("description", ""),
            "active": group.get("active", ""),
            "permission_group": json.dumps(group.get("permission_group", {}), ensure_ascii=False),
            "object_permission": json.dumps(group.get("object_permission", {}), ensure_ascii=False),
            "tags": " | ".join(group.get("tags", [])) if isinstance(group.get("tags", []), list) else group.get("tags", ""),
        })
    return pd.DataFrame(rows)

def load_tenant_list(config_dir: str) -> List[str]:
    config_path = os.path.join(config_dir, DEFAULT_CONFIG_NAME)
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
            return config_data.get("tenant_list", [])
    except FileNotFoundError:
        logging.error(f"Config file '{config_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode tenant config JSON - {e}")
        sys.exit(1)

# --- NEW: charger la config complète (pour collector_to_tenant, etc.) ------
def load_full_config(config_dir: str) -> Dict:
    config_path = os.path.join(config_dir, DEFAULT_CONFIG_NAME)
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Config file '{config_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode config JSON - {e}")
        sys.exit(1)

# === split & export ===
def split_entities_by_tenant(entities: Dict[str, pd.DataFrame],
                             tenant_list: List[str],
                             output_dir: str,
                             config_dict: Dict,
                             alerts_df=None) -> None:  # <= NEW param, défaut None
    os.makedirs(output_dir, exist_ok=True)
    unmatched_records_by_entity = defaultdict(list)

    # --- mapping device_id -> tenant (collector-first) ---
    device_df = entities.get("Device", pd.DataFrame())
    device_id_to_tenant: Dict[str, str] = {}
    if not device_df.empty:
        for _, row in device_df.iterrows():
            row_dict = row.to_dict()
            tenant = determine_device_tenant(
                row_dict,
                tenant_list,
                config_dict,
                name_matcher=match_tenant_by_name,
                default_unassigned="Unassigned"
            )
            device_id = str(row_dict.get("device_id", "")).strip()
            if device_id:
                device_id_to_tenant[device_id] = tenant

    # --- mapping repo_name -> tenant (pour Alert routing) ---
    repo_name_to_tenant: Dict[str, str] = {}
    repo_df = entities.get("Repo", pd.DataFrame())
    if not repo_df.empty:
        name_col = "original_repo_name" if "original_repo_name" in repo_df.columns else (
                   "cleaned_repo_name" if "cleaned_repo_name" in repo_df.columns else None)
        if name_col:
            for _, r in repo_df.iterrows():
                repo_name = str(r.get(name_col, "")).strip()
                if not repo_name:
                    continue
                t = match_tenant_by_name(repo_name, tenant_list)
                if t and repo_name not in repo_name_to_tenant:
                    repo_name_to_tenant[repo_name] = t

    # --- boucle tenants ---
    for tenant in tenant_list:
        output_path = os.path.join(output_dir, f"{tenant}_config.xlsx")
        with pd.ExcelWriter(output_path, engine="xlsxwriter") as writer:  # engine identique à l’original
            for entity_name, df in entities.items():
                # Entités exportées complètes (inchangées)
                if entity_name in {"NormalizationPolicy", "EnrichmentPolicy", "EnrichmentRules", "EnrichmentCriteria", 
                                   "DeviceGroups", "User", "UserGroup"}:
                    df.to_excel(writer, sheet_name=entity_name, index=False)
                    continue

                # Device / DeviceFetcher filtrés via mapping collector-first
                if entity_name == "Device":
                    if df.empty:
                        continue
                    mask = df["device_id"].astype(str).map(device_id_to_tenant.get) == tenant
                    tenant_df = df[mask].copy()
                    if not tenant_df.empty:
                        tenant_df.to_excel(writer, sheet_name="Device", index=False)
                    continue

                if entity_name == "DeviceFetcher":
                    if df.empty:
                        continue
                    mask = df["device_id"].astype(str).map(device_id_to_tenant.get) == tenant
                    tenant_df = df[mask].copy()
                    if not tenant_df.empty:
                        tenant_df.to_excel(writer, sheet_name="DeviceFetcher", index=False)
                    continue

                # Autres entités : matching par nom (inchangé)
                column_candidates = ["original_repo_name", "original_policy_name", "policy_name", "name", "device_name"]
                tenant_df = pd.DataFrame()
                for col in column_candidates:
                    if col in df.columns:
                        tenant_df = df[df[col].astype(str).str.lower().str.contains(tenant.lower(), na=False)]
                        break

                if not tenant_df.empty:
                    df_name = entity_name.replace(" ", "_")
                    tenant_df.to_excel(writer, sheet_name=df_name[:31], index=False)

            # === NEW: feuille Alert par tenant ===
            if alerts_df is not None and not alerts_df.empty:
                try:
                    write_alert_sheet_per_tenant(
                        writer=writer,
                        tenant_name=tenant,
                        alerts_df=alerts_df,
                        all_tenants=tenant_list,
                        repo_name_to_tenant=repo_name_to_tenant
                    )
                except Exception as e:
                    logging.warning(f"Alerts: failed to write for tenant {tenant}: {e}")

        logging.info(f"Tenant config exported to '{output_path}'")

    # After processing all tenants: warn for unmatched records
    for entity_name, df in entities.items():
        if entity_name in {"NormalizationPolicy", "EnrichmentPolicy", "EnrichmentRules", "EnrichmentCriteria", 
                           "DeviceGroups", "Alert", "User", "UserGroup"}:
            continue

        # NEW: détection des Devices non assignés
        if entity_name == "Device" and not df.empty:
            unassigned = []
            for _, row in df.iterrows():
                did = str(row.get("device_id", "")).strip()
                t = device_id_to_tenant.get(did)
                if not t or t == "Unassigned":
                    unassigned.append(row.get("name", row.get("device_id", "UNKNOWN")))
            if unassigned:
                for name in unassigned:
                    logging.warning(f"[Device] '{name}' does not match any tenant (collector+name).")
            continue

        column_candidates = ["original_repo_name", "original_policy_name", "policy_name", "name", "device_name", "original_group_name"]
        matched = pd.Series([False] * len(df))
        for tenant in tenant_list:
            for col in column_candidates:
                if col in df.columns:
                    matched = matched | df[col].astype(str).str.lower().str.contains(tenant.lower(), na=False)
                    break

        unmatched = df[~matched]
        if not unmatched.empty:
            id_col = next((col for col in column_candidates if col in df.columns), None)
            for _, row in unmatched.iterrows():
                record_name = row.get(id_col, "UNKNOWN")
                logging.warning(f"[{entity_name}] Record '{record_name}' does not match any tenant.")

def main():
    parser = argparse.ArgumentParser(description="Extract and convert Logpoint configuration by tenant to Excel.")
    parser.add_argument("--input", required=True, help="Path to the JSON configuration file")
    parser.add_argument("--config-dir", default=".", help="Directory containing the tenant config JSON")
    parser.add_argument("--output-dir", default="tenants_output", help="Output directory for tenant-based exports")
    # === NEW flag ===
    parser.add_argument("--input-sh", default="", help="Optional Search-Head JSON for alerts (overrides --input for alerts)")
    parser.add_argument("--log-file", help="Optional path to a log file")

    args = parser.parse_args()
    json_path = args.input
    config_dir = args.config_dir
    output_dir = args.output_dir
    
    # Setup optional file logging (inchangé)
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        logging.getLogger().addHandler(file_handler)

    json_data = load_json(json_path)

    if "Sync" not in json_data:
        logging.error("JSON does not contain 'Sync' key.")
        sys.exit(1)

    # === NEW: Alerts source selection (AIO vs --input-sh) ===
    alerts_source = args.input_sh if args.input_sh else json_path
    try:
        alerts_df = load_alerts_df(alerts_source)
    except Exception as e:
        logging.warning(f"Alerts: unable to load from {alerts_source}: {e}")
        alerts_df = None

    tenant_list = load_tenant_list(config_dir)
    config_dict = load_full_config(config_dir)  # <= NEW

    enrichment_entities = extract_enrichment_policy_tables(json_data["Sync"])
    device_entities = extract_devices(json_data["Sync"])

    entities = {
        "Repo": extract_repos(json_data["Sync"], tenant_list),
        "RoutingPolicy": extract_routing_policies(json_data["Sync"], tenant_list),
        "NormalizationPolicy": extract_normalization_policies(json_data["Sync"]),
        "ProcessingPolicy": extract_processing_policies(json_data["Sync"], tenant_list),
        **enrichment_entities,
        **device_entities,
        "DeviceGroups": extract_device_groups(json_data["Sync"]),
        "User": extract_users(json_data["Sync"]),
        "UserGroup": extract_user_groups(json_data["Sync"]),
    }

    # <= signature mise à jour (on passe la config complète + alerts_df)
    split_entities_by_tenant(entities, tenant_list, output_dir, config_dict, alerts_df=alerts_df)

if __name__ == "__main__":
    main()
