import logging
import pandas as pd
from typing import Dict, List, Any, Tuple
import json

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)


def build_enrichment_payloads(
    df_policy: pd.DataFrame,
    df_rules: pd.DataFrame,
    df_criteria: pd.DataFrame
) -> Tuple[Dict[str, Dict], Dict[str, List[str]]]:
    """
    Builds the enrichment policy payloads from the provided DataFrames.

    Groups data by policy_id from the EnrichmentPolicy sheet, extracts fixed fields,
    and constructs specifications by grouping on source. Filters rules and criteria
    by policy_name and source, matching spec_index where applicable.

    Parameters:
    df_policy (pd.DataFrame): DataFrame from "EnrichmentPolicy" sheet.
    df_rules (pd.DataFrame): DataFrame from "EnrichmentRules" sheet.
    df_criteria (pd.DataFrame): DataFrame from "EnrichmentCriteria" sheet.

    Returns:
    Tuple[Dict[str, Dict], Dict[str, List[str]]]: A dictionary of payloads keyed by policy_id,
    and a dictionary of lists of enrichment sources (ES) used per policy_id.
    """
    payloads = {}
    es_per_policy = {}

    # Group policy DataFrame by policy_id
    grouped_policy = df_policy.groupby('policy_id')

    for policy_id, group in grouped_policy:
        # Extract fixed fields (assume consistent across group)
        policy_name = group['policy_name'].iloc[0]
        description = group['description'].iloc[0] if 'description' in group.columns else ""
        tags = group['tags'].iloc[0] if 'tags' in group.columns else ""
        active = group['active'].iloc[0] if 'active' in group.columns else True

        # Initialize specifications list and set for ES used
        specifications = []
        es_used = set()

        # Group the policy group by source
        grouped_source = group.groupby('source')

        for source, source_group in grouped_source:
            es_used.add(source)

            # Get list of spec_index for this source
            spec_indices = source_group['spec_index'].tolist()

            # Filter rules and criteria by policy_name and source
            rules_filtered = df_rules[
                (df_rules['policy_name'] == policy_name) &
                (df_rules['source'] == source)
            ]
            criteria_filtered = df_criteria[
                (df_criteria['policy_name'] == policy_name) &
                (df_criteria['source'] == source)
            ]

            # Build rules list
            rules = []
            for _, row in rules_filtered.iterrows():
                rule = {
                    "category": row.get('category', ''),
                    "source_key": row.get('source_key', ''),
                    "prefix": row.get('prefix', False),
                    "operation": row.get('operation', ''),
                    "type": row.get('type', ''),
                    "event_key": row.get('event_key', '')
                }
                rules.append(rule)

            # Build criteria list
            criteria = []
            for _, row in criteria_filtered.iterrows():
                criterion = {
                    "type": row.get('type', ''),
                    "key": row.get('key', ''),
                    "value": row.get('value', '')
                }
                criteria.append(criterion)

            # Create specification object for this source
            spec = {
                "source": source,
                "rules": rules,
                "criteria": criteria
            }
            specifications.append(spec)

        # Construct payload
        payload = {
            "data": {
                "id": policy_id,
                "name": policy_name,
                "description": description,
                "tags": tags,
                "active": active,
                "specifications": specifications
            }
        }

        # Log for debugging
        logger.debug(f"Built payload for policy_id {policy_id}: {payload}")

        payloads[policy_id] = payload
        es_per_policy[policy_id] = list(es_used)

    return payloads, es_per_policy

def check_existing_per_node(
    client,
    pool_uuid: str,
    nodes: List[Dict],
    payloads: Dict[str, Dict],
    es_per_policy: Dict[str, List[str]]
) -> Dict[str, Dict]:
    """
    Checks existing Enrichment Policies (EP) and Enrichment Sources (ES) per node.

    For each node, fetches the list of existing EPs and ESs, matches by case-sensitive
    policy_name and source_name, and determines the action (NOOP, SKIP, CREATE, UPDATE).

    Parameters:
    client: DirectorClient instance for API calls.
    pool_uuid (str): UUID of the pool.
    nodes (List[Dict]): List of node dictionaries with 'id' and 'name'.
    payloads (Dict[str, Dict]): Dictionary of payloads keyed by policy_id.
    es_per_policy (Dict[str, List[str]]): Dictionary of ES lists per policy_id.

    Returns:
    Dict[str, Dict]: Dictionary of results per policy_id, with node-specific actions.
    """
    results = {policy_id: {} for policy_id in payloads.keys()}

    for node in nodes:
        node_id = node['id']
        node_name = node['name']

        # Fetch existing ES list for this node
        es_url = f"/configapi/{pool_uuid}/{node_id}/EnrichmentSource"
        try:
            es_response = client.get(es_url)
            existing_es = {es['name']: es for es in es_response.json().get('data', [])}
            logger.debug(f"Fetched ES list for node {node_name}: {existing_es.keys()}")
        except Exception as e:
            logger.error(f"Failed to fetch ES list for node {node_name}: {str(e)}")
            continue

        # Fetch existing EP list for this node
        ep_url = f"/configapi/{pool_uuid}/{node_id}/EnrichmentPolicy"
        try:
            ep_response = client.get(ep_url)
            existing_eps = {ep['name']: ep for ep in ep_response.json().get('data', [])}
            logger.debug(f"Fetched EP list for node {node_name}: {existing_eps.keys()}")
        except Exception as e:
            logger.error(f"Failed to fetch EP list for node {node_name}: {str(e)}")
            continue

        for policy_id, payload in payloads.items():
            policy_name = payload['data']['name']
            es_list = es_per_policy[policy_id]

            # Check if all required ES exist
            missing_es = [es for es in es_list if es not in existing_es]
            if missing_es:
                results[policy_id][node_name] = {
                    'action': 'SKIP',
                    'error': f"Missing ES: {', '.join(missing_es)}"
                }
                logger.warning(f"Skipping {policy_name} on {node_name} due to missing ES: {missing_es}")
                continue

            # Check if EP exists and compare
            if policy_name in existing_eps:
                existing_ep = existing_eps[policy_name]
                existing_specs = existing_ep.get('specifications', [])
                new_specs = payload['data']['specifications']

                # Case-sensitive comparison of specifications
                if _compare_specifications(existing_specs, new_specs):
                    results[policy_id][node_name] = {'action': 'NOOP'}
                    logger.info(f"NOOP for {policy_name} on {node_name}")
                else:
                    results[policy_id][node_name] = {
                        'action': 'UPDATE',
                        'existing_id': existing_ep.get('id')
                    }
                    logger.info(f"UPDATE needed for {policy_name} on {node_name}")
            else:
                results[policy_id][node_name] = {'action': 'CREATE'}
                logger.info(f"CREATE needed for {policy_name} on {node_name}")

    return results

def _compare_specifications(existing: List[Dict], new: List[Dict]) -> bool:
    """
    Compares two lists of specifications for equality.

    Performs a case-sensitive comparison of source, rules, and criteria.

    Parameters:
    existing (List[Dict]): Existing specifications.
    new (List[Dict]): New specifications.

    Returns:
    bool: True if specifications are identical, False otherwise.
    """
    if len(existing) != len(new):
        return False
    for ex_spec, new_spec in zip(existing, new):
        if ex_spec.get('source') != new_spec.get('source'):
            return False
        if sorted(ex_spec.get('rules', [])) != sorted(new_spec.get('rules', [])):
            return False
        if sorted(ex_spec.get('criteria', [])) != sorted(new_spec.get('criteria', [])):
            return False
    return True

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