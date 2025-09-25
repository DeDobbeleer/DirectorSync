import logging
import pandas as pd
from typing import Dict, List, Any, Tuple
import json

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)

def import_enrichment_policies_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List[Node]],
    xlsx_path: str,
    dry_run: bool,
    targets: List[str],
) -> Tuple[List[Dict[str, Any]], bool]:
    """Import enrichment policies for specified nodes.

    Loads 'EnrichmentPolicy', 'EnrichmentRules', and 'EnrichmentCriteria' sheets from XLSX,
    groups by policy_name and spec_index, validates sources via API,
    and performs CREATE/UPDATE/NOOP/SKIP actions with async monitoring.

    Args:
        client (DirectorClient): Instance for API calls.
        pool_uuid (str): Tenant pool UUID.
        nodes (Dict[str, List[Node]]): Dictionary of node types and instances.
        xlsx_path (str): Path to the configuration XLSX file.
        dry_run (bool): If True, simulate without API calls.
        targets (List[str]): List of target node roles (e.g., ['backends', 'all_in_one']).

    Returns:
        Tuple[List[Dict[str, Any]], bool]: Tuple of (list of results, error indicator).
        Results include: siem, node, name, specs_count, action, result, error.

    Raises:
        Exception: If XLSX loading or API calls fail.
    """
    rows = []
    any_error = False

    # Load Excel sheets with error handling
    try:
        policy_df = pd.read_excel(xlsx_path, sheet_name="EnrichmentPolicy", skiprows=0)
        rules_df = pd.read_excel(xlsx_path, sheet_name="EnrichmentRules", skiprows=0)
        criteria_df = pd.read_excel(xlsx_path, sheet_name="EnrichmentCriteria", skiprows=0)
        logger.debug("Loaded sheets: EnrichmentPolicy (%d rows), Rules (%d rows), Criteria (%d rows)",
                     len(policy_df), len(rules_df), len(criteria_df))
    except Exception as e:
        logger.error("Failed to load enrichment sheets from %s: %s", xlsx_path, e)
        return [], True

    # Group rules and criteria by policy_name and spec_index
    rules_grouped = rules_df.groupby(['policy_name', 'spec_index'])
    criteria_grouped = criteria_df.groupby(['policy_name', 'spec_index'])

    # Process each policy
    for _, row in policy_df.iterrows():
        policy_name = row['policy_name']
        description = row.get('description', '') if pd.notna(row.get('description', '')) else ""
        policy_id = row.get('policy_id', '') if pd.notna(row.get('policy_id', '')) else None

        # Collect specifications
        specifications = []
        spec_indices = rules_df[rules_df['policy_name'] == policy_name]['spec_index'].unique()
        for spec_index in spec_indices:
            source = row['source']
            rules_key = (policy_name, spec_index)
            criteria_key = (policy_name, spec_index)

            rules = []
            if rules_key in rules_grouped.groups:
                for _, rule_row in rules_grouped.get_group(rules_key).iterrows():
                    rules.append({
                        "category": rule_row['category'],
                        "source_key": rule_row['source_key'],
                        "prefix": bool(rule_row['prefix']),
                        "operation": rule_row['operation'],
                        "type": rule_row['type'],
                        "event_key": rule_row['event_key']
                    })

            criteria = []
            if criteria_key in criteria_grouped.groups:
                for _, crit_row in criteria_grouped.get_group(criteria_key).iterrows():
                    criteria.append({
                        "type": crit_row['type'],
                        "key": crit_row['key'],
                        "value": crit_row.get('value', '') if pd.notna(crit_row.get('value', '')) else ""
                    })

            if rules or criteria:
                specifications.append({"source": source, "rules": rules, "criteria": criteria})

        if not specifications:
            logger.warning("No valid specifications for policy %s, skipping", policy_name)
            continue

        policy = {"name": policy_name, "description": description, "specifications": specifications}

        # Process per target node
        for target_type in targets:
            for node in nodes.get(target_type, []):
                logpoint_id = node.id
                siem = node.name

                # Fetch available enrichment sources
                try:
                    available_sources = client.get_enrichment_sources(pool_uuid, logpoint_id)
                    logger.debug("Available sources on %s: %s", siem, available_sources)
                except Exception as e:
                    logger.error("Failed to fetch sources for %s: %s", siem, e)
                    rows.append({
                        "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                        "action": "NONE", "result": "Fail", "error": str(e)
                    })
                    any_error = True
                    continue

                # Validate sources
                if not all(spec["source"] in available_sources for spec in specifications):
                    logger.warning("Source(s) not found on %s for policy %s, skipping", siem, policy_name)
                    rows.append({
                        "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                        "action": "SKIP", "result": "MISSING_SOURCE", "error": ""
                    })
                    continue

                # Fetch existing policies
                try:
                    existing_policies = client.get_enrichment_policies(pool_uuid, logpoint_id)
                    logger.debug("Found %d existing policies on %s", len(existing_policies), siem)
                except Exception as e:
                    logger.error("Failed to fetch policies for %s: %s", siem, e)
                    rows.append({
                        "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                        "action": "NONE", "result": "Fail", "error": str(e)
                    })
                    any_error = True
                    continue

                # Find matching policy
                existing = next((p for p in existing_policies if p.get("name") == policy_name), None)
                if existing:
                    # Compare for NOOP or UPDATE
                    existing_specs = set(json.dumps(sorted(spec.items()), sort_keys=True)
                                        for spec in existing.get("specifications", []))
                    current_specs = set(json.dumps(sorted(spec.items()), sort_keys=True)
                                       for spec in policy["specifications"])
                    if existing.get("description") == description and existing_specs == current_specs:
                        logger.info("No changes needed for policy %s on %s", policy_name, siem)
                        rows.append({
                            "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                            "action": "NOOP", "result": "N/A", "error": ""
                        })
                        continue

                    # UPDATE
                    policy["id"] = existing["id"]
                    payload = {"data": policy}
                    if dry_run:
                        logger.info("Dry-run: Would update %s on %s", policy_name, siem)
                        rows.append({
                            "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                            "action": "UPDATE", "result": "Dry-run", "error": ""
                        })
                        continue

                    try:
                        result = client.update_enrichment_policy(pool_uuid, logpoint_id, policy["id"], payload)
                        if result["status"] == "Success":
                            logger.info("Successfully updated %s on %s", policy_name, siem)
                            rows.append({
                                "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                                "action": "UPDATE", "result": "Success", "error": ""
                            })
                        else:
                            logger.error("Update failed for %s on %s: %s", policy_name, siem, result.get("error"))
                            rows.append({
                                "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                                "action": "UPDATE", "result": "Fail", "error": result.get("error")
                            })
                            any_error = True
                    except Exception as e:
                        logger.error("Exception updating %s on %s: %s", policy_name, siem, e)
                        rows.append({
                            "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                            "action": "UPDATE", "result": "Fail", "error": str(e)
                        })
                        any_error = True
                else:
                    # CREATE
                    payload = {"data": policy}
                    if dry_run:
                        logger.info("Dry-run: Would create %s on %s", policy_name, siem)
                        rows.append({
                            "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                            "action": "CREATE", "result": "Dry-run", "error": ""
                        })
                        continue

                    try:
                        result = client.create_enrichment_policy(pool_uuid, logpoint_id, payload)
                        if result["status"] == "Success":
                            logger.info("Successfully created %s on %s", policy_name, siem)
                            rows.append({
                                "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                                "action": "CREATE", "result": "Success", "error": ""
                            })
                        else:
                            logger.error("Creation failed for %s on %s: %s", policy_name, siem, result.get("error"))
                            rows.append({
                                "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                                "action": "CREATE", "result": "Fail", "error": result.get("error")
                            })
                            any_error = True
                    except Exception as e:
                        logger.error("Exception creating %s on %s: %s", policy_name, siem, e)
                        rows.append({
                            "siem": siem, "node": node.name, "name": policy_name, "specs_count": len(specifications),
                            "action": "CREATE", "result": "Fail", "error": str(e)
                        })
                        any_error = True

    return rows, any_error