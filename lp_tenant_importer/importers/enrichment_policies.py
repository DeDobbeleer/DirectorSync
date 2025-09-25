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
    node: List[Dict],
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


    node_id = node.id
    node_name = node.name

   # Fetch existing ES list for this node, handling both list and dict responses
    es_url = f"/configapi/{pool_uuid}/{node_id}/EnrichmentSource"
    try:
        es_response = client.get(es_url)
        es_data = es_response.json()
        existing_es = {}
        if isinstance(es_data, list):
            existing_es = {item.get('name', ''): item for item in es_data}
        else:
            existing_es = {es['name']: es for es in es_data.get('data', [])}
        logger.debug(f"Fetched ES list for node {node_name}: {existing_es.keys()}")
    except Exception as e:
        logger.error(f"Failed to fetch ES list for node {node_name}: {str(e)}")
        return results

    # Fetch existing EP list for this node
    ep_url = f"/configapi/{pool_uuid}/{node_id}/EnrichmentPolicy"
    try:
        ep_response = client.get(ep_url)
        ep_data = ep_response.json()
        existing_eps = {}
        if isinstance(ep_data, list):
            existing_eps = {item.get('name', ''): item for item in ep_data}
        else:
            existing_eps = {ep['name']: ep for ep in ep_data.get('data', [])}
        logger.debug(f"Fetched EP list for node {node_name}: {existing_eps.keys()}")
    except Exception as e:
        logger.error(f"Failed to fetch EP list for node {node_name}: {str(e)}")
        return results

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

def execute_actions_per_node(
    client,
    pool_uuid: str,
    nodes: List[Dict],
    payloads: Dict[str, Dict],
    check_results: Dict[str, Dict]
) -> List[Dict]:
    """
    Executes the actions (CREATE, UPDATE) for each policy per node.

    Loops over nodes first, then over policies, using the payloads and check_results.
    Monitors jobs and collects results in a list of dictionaries conforming to the
    structure in processing_policies.py (siem, node, name, result, action, error).

    Parameters:
    client: DirectorClient instance for API calls.
    pool_uuid (str): UUID of the pool.
    nodes (List[Dict]): List of node dictionaries with 'id' and 'name'.
    payloads (Dict[str, Dict]): Dictionary of payloads keyed by policy_id.
    check_results (Dict[str, Dict]): Results from check_existing_per_node, keyed by policy_id.

    Returns:
    List[Dict]: List of result dictionaries for the output table.
    """
    results = []

    for node in nodes:
        node_id = node['id']
        node_name = node['name']
        siem = node_name  # Assuming siem is same as node_name, adjust if needed

        for policy_id, payload in payloads.items():
            policy_name = payload['data']['name']
            node_result = check_results.get(policy_id, {}).get(node_name, {})
            action = node_result.get('action', 'NONE')

            result_entry = {
                'siem': siem,
                'node': node_name,
                'name': policy_name,
                'result': 'N/A',
                'action': action,
                'error': None
            }

            if action == 'SKIP' or action == 'NOOP':
                result_entry['result'] = 'Skipped' if action == 'SKIP' else 'Noop'
                logger.info(f"{action} for {policy_name} on {node_name}")
            elif action == 'CREATE':
                try:
                    # Use create_enrichment_policy if available, or general post
                    response = client.create_enrichment_policy(pool_uuid, node_id, payload)
                    job_id = response.json().get('job_id')
                    job_status = client.monitor_job(job_id)
                    if job_status['success']:
                        result_entry['result'] = 'Success'
                        logger.info(f"CREATE success for {policy_name} on {node_name}")
                    else:
                        result_entry['result'] = 'Fail'
                        result_entry['error'] = job_status.get('error', 'Unknown error')
                        logger.error(f"CREATE fail for {policy_name} on {node_name}: {result_entry['error']}")
                except Exception as e:
                    result_entry['result'] = 'Fail'
                    result_entry['error'] = str(e)
                    logger.error(f"CREATE error for {policy_name} on {node_name}: {str(e)}")
            elif action == 'UPDATE':
                try:
                    # Get destination ID from check_results
                    dest_id = node_result.get('existing_id')
                    update_payload = payload.copy()
                    update_payload['data']['id'] = dest_id
                    response = client.update_enrichment_policy(pool_uuid, node_id, dest_id, update_payload)
                    job_id = response.json().get('job_id')
                    job_status = client.monitor_job(job_id)
                    if job_status['success']:
                        result_entry['result'] = 'Success'
                        logger.info(f"UPDATE success for {policy_name} on {node_name}")
                    else:
                        result_entry['result'] = 'Fail'
                        result_entry['error'] = job_status.get('error', 'Unknown error')
                        logger.error(f"UPDATE fail for {policy_name} on {node_name}: {result_entry['error']}")
                except Exception as e:
                    result_entry['result'] = 'Fail'
                    result_entry['error'] = str(e)
                    logger.error(f"UPDATE error for {policy_name} on {node_name}: {str(e)}")

            results.append(result_entry)

    return results

def import_enrichment_policies_for_nodes(
    client,
    pool_uuid: str,
    nodes: Any,
    xlsx_path: str,
    dry_run: bool = False,
    targets: List[str] = None
) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Imports enrichment policies for specified nodes from an XLSX file.

    Coordinates the workflow: loads data, builds payloads, checks existing policies and sources
    per node, executes actions (CREATE, UPDATE, NOOP, SKIP), and returns results.

    Args:
        client: DirectorClient instance for API calls.
        pool_uuid (str): UUID of the pool.
        nodes (List[Dict]): List of node dictionaries with 'id' and 'name'.
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
        df_policy = pd.read_excel(xlsx_path, sheet_name="EnrichmentPolicy")
        df_rules = pd.read_excel(xlsx_path, sheet_name="EnrichmentRules")
        df_criteria = pd.read_excel(xlsx_path, sheet_name="EnrichmentCriteria")
        logger.debug(f"Loaded sheets: EnrichmentPolicy ({len(df_policy)} rows), "
                     f"Rules ({len(df_rules)} rows), Criteria ({len(df_criteria)} rows)")
    except Exception as e:
        logger.error(f"Failed to load XLSX data: {str(e)}")
        return [], True

    # Build payloads and get ES list
    payloads, es_per_policy = build_enrichment_payloads(df_policy, df_rules, df_criteria)
    
    # Debug the number of nodes being processed
    node_list = [node for node in nodes]
    logger.debug(f"Processing {len(nodes)} nodes: {node_list}")

    # Process per node, then per policy
    for target_type in targets:
        for node in nodes.get(target_type, []):
            node_id = node.id
            node_name = node.name
            siem = node_name  # Assuming siem is same as node_name

            # Check existing policies and sources
            check_results = check_existing_per_node(client, pool_uuid, node, payloads, es_per_policy)

        for policy_id, payload in payloads.items():
            policy_name = payload['data']['name']
            specs_count = len(payload['data']['specifications'])
            node_result = check_results.get(policy_id, {}).get(node_name, {})
            action = node_result.get('action', 'NONE')

            result_entry = {
                'siem': siem,
                'node': node_name,
                'name': policy_name,
                'specs_count': specs_count,
                'action': action,
                'result': 'N/A',
                'error': node_result.get('error', '')
            }

            if action in ['SKIP', 'NOOP']:
                result_entry['result'] = 'Skipped' if action == 'SKIP' else 'Noop'
                logger.info(f"{action} for {policy_name} on {node_name}")
            elif action in ['CREATE', 'UPDATE'] and not dry_run:
                try:
                    if action == 'CREATE':
                        response = client.create_enrichment_policy(pool_uuid, node_id, payload)
                        job_id = response.json().get('job_id')
                    elif action == 'UPDATE':
                        dest_id = node_result.get('existing_id')
                        update_payload = payload.copy()
                        update_payload['data']['id'] = dest_id
                        response = client.update_enrichment_policy(pool_uuid, node_id, dest_id, update_payload)
                        job_id = response.json().get('job_id')

                    job_status = client.monitor_job(job_id)
                    if job_status.get('success'):
                        result_entry['result'] = 'Success'
                        logger.info(f"{action} success for {policy_name} on {node_name}")
                    else:
                        result_entry['result'] = 'Fail'
                        result_entry['error'] = job_status.get('error', 'Unknown error')
                        logger.error(f"{action} fail for {policy_name} on {node_name}: {result_entry['error']}")
                        any_error = True
                except Exception as e:
                    result_entry['result'] = 'Fail'
                    result_entry['error'] = str(e)
                    logger.error(f"{action} error for {policy_name} on {node_name}: {str(e)}")
                    any_error = True
            elif dry_run:
                result_entry['result'] = 'Dry-run'
                logger.info(f"Dry run: {action} for {policy_name} on {node_name}")

            rows.append(result_entry)

    # Log summary
    actions_summary = {r['action']: sum(1 for res in rows if res['action'] == r['action']) for r in rows}
    logger.info(f"Import summary: {actions_summary}")

    return rows, any_error