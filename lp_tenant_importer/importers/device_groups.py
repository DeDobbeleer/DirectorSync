import logging
import pandas as pd
from typing import Dict, List, Any, Tuple
import json
import numpy as np

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)

def build_device_group_payloads(df_group: pd.DataFrame) -> Tuple[Dict[str, Dict], Dict[str, List[str]]]:
    """
    Builds the device group payloads from the provided DataFrame.

    Extracts fixed fields from the DeviceGroups sheet and constructs payloads
    for each group, ignoring device_ids. Converts np.bool_ to bool and NaN to empty strings.

    Parameters:
    df_group (pd.DataFrame): DataFrame from "DeviceGroups" sheet.

    Returns:
    Tuple[Dict[str, Dict], Dict[str, List[str]]]: A dictionary of payloads keyed by group_id,
    and a dictionary of empty lists (no ES equivalent for DeviceGroups).
    """
    payloads = {}
    es_per_group = {}  # Placeholder, no ES for DeviceGroups

    # Group DataFrame by group_id (each row is a unique group)
    grouped_group = df_group.groupby('group_id')

    for group_id, group in grouped_group:
        # Extract fixed fields (assume consistent across group)
        group_name = group['name'].iloc[0]
        description = str(group['description'].iloc[0]) if pd.notna(group['description'].iloc[0]) else ""
        tags = str(group['tags'].iloc[0]) if pd.notna(group['tags'].iloc[0]) else ""
        active = bool(group['active'].iloc[0]) if pd.notna(group['active'].iloc[0]) else False

        # Construct payload
        payload = {
            "data": {
                "id": group_id,
                "name": group_name,
                "description": description,
                "tags": tags,
                "active": active
            }
        }

        # Log for debugging
        logger.debug(f"Built payload for group_id {group_id}: {payload}")

        payloads[group_id] = payload
        es_per_group[group_id] = []  # No ES, just an empty list to match structure

    return payloads, es_per_group

def check_existing_per_node(
    client,
    pool_uuid: str,
    node: Node,
    payloads: Dict[str, Dict],
    es_per_group: Dict[str, List[str]]
) -> Dict[str, Dict]:
    """
    Checks existing DeviceGroups per node.

    For each node, fetches the list of existing DeviceGroups, matches by case-sensitive
    name, and determines the action (NOOP, SKIP, CREATE, UPDATE) based on name and description only.

    Parameters:
    client: DirectorClient instance for API calls.
    pool_uuid (str): UUID of the pool.
    node (Node): Node object with 'id' and 'name'.
    payloads (Dict[str, Dict]): Dictionary of payloads keyed by group_id.
    es_per_group (Dict[str, List[str]]): Dictionary of empty lists (no ES).

    Returns:
    Dict[str, Dict]: Dictionary of results per group_id, with node-specific actions.
    """
    results = {group_id: {} for group_id in payloads.keys()}

    node_id = node.id
    node_name = node.name

    # Fetch existing DeviceGroups list for this node
    try:
        dg_url = f"/configapi/{pool_uuid}/{node_id}/DeviceGroups"
        dg_response = client.get(dg_url)
        dg_response.raise_for_status()
        dg_data = dg_response.json()
        existing_dgs = {}
        if isinstance(dg_data, list):
            existing_dgs = {item.get('name', ''): item for item in dg_data}
        else:
            existing_dgs = {dg['name']: dg for dg in dg_data.get('data', [])}
        logger.debug(f"Fetched DeviceGroups list for node {node_name}: {existing_dgs.keys()}")
    except Exception as e:
        logger.error(f"Failed to fetch DeviceGroups list for node {node_name}: {str(e)}")
        return results

    for group_id, payload in payloads.items():
        group_name = payload['data']['name']
        description = payload['data']['description']

        # Extract existing data for comparison (only name and description)
        if group_name in existing_dgs:
            existing_dg = existing_dgs[group_name]
            existing_data = {
                'name': existing_dg.get('name', ''),
                'description': existing_dg.get('description', '')
            }
            new_data = {
                'name': group_name,
                'description': description
            }
            if json.dumps(existing_data, sort_keys=True) == json.dumps(new_data, sort_keys=True):
                results[group_id][node_name] = {'action': 'NOOP'}
                logger.info(f"NOOP for {group_name} on {node_name}")
            else:
                results[group_id][node_name] = {
                    'action': 'UPDATE',
                    'existing_id': existing_dg.get('id')
                }
                logger.info(f"UPDATE needed for {group_name} on {node_name}")
        else:
            if group_name and isinstance(payload['data']['active'], bool):
                results[group_id][node_name] = {'action': 'CREATE'}
                logger.info(f"CREATE needed for {group_name} on {node_name}")
            else:
                results[group_id][node_name] = {
                    'action': 'SKIP',
                    'error': 'Missing name or invalid active status'
                }
                logger.warning(f"Skipping {group_name} on {node_name} due to {results[group_id][node_name]['error']}")

    return results

def execute_actions_per_node(
    client,
    pool_uuid: str,
    nodes: List[Node],
    payloads: Dict[str, Dict],
    check_results: Dict[str, Dict]
) -> List[Dict]:
    """
    Executes the actions (CREATE, UPDATE) for each device group per node.

    Loops over nodes first, then over device groups, using the payloads and check_results.
    Monitors jobs and collects results in a list of dictionaries conforming to the
    structure in other importers (siem, node, name, result, action, error).

    Parameters:
    client: DirectorClient instance for API calls.
    pool_uuid (str): UUID of the pool.
    nodes (List[Node]): List of node objects with 'id' and 'name'.
    payloads (Dict[str, Dict]): Dictionary of payloads keyed by group_id.
    check_results (Dict[str, Dict]): Results from check_existing_per_node, keyed by group_id.

    Returns:
    List[Dict]: List of result dictionaries for the output table.
    """
    results = []

    for node in nodes:
        node_id = node.id
        node_name = node.name
        siem = node_name  # Assuming siem is same as node_name, adjust if needed

        for group_id, payload in payloads.items():
            group_name = payload['data']['name']
            node_result = check_results.get(group_id, {}).get(node_name, {})
            action = node_result.get('action', 'NONE')

            result_entry = {
                'siem': siem,
                'node': node_name,
                'name': group_name,
                'result': 'N/A',
                'action': action,
                'error': node_result.get('error', '')
            }

            if action == 'SKIP' or action == 'NOOP':
                result_entry['result'] = 'Skipped' if action == 'SKIP' else 'Noop'
                logger.info(f"{action} for {group_name} on {node_name}")
            elif action == 'CREATE':
                try:
                    response = client.create_device_group(pool_uuid, node_id, payload)
                    if response.get('status') == 'Success':
                        result_entry['result'] = 'Success'
                        logger.info(f"CREATE success for {group_name} on {node_name}")
                    else:
                        result_entry['result'] = 'Fail'
                        result_entry['error'] = response.get('error', 'Unknown error')
                        logger.error(f"CREATE fail for {group_name} on {node_name}: {result_entry['error']}")
                except Exception as e:
                    result_entry['result'] = 'Fail'
                    result_entry['error'] = str(e)
                    logger.error(f"CREATE error for {group_name} on {node_name} - payload: {payload}: {str(e)}")
            elif action == 'UPDATE':
                try:
                    dest_id = node_result.get('existing_id')
                    update_payload = payload.copy()
                    update_payload['data']['id'] = dest_id
                    response = client.update_device_group(pool_uuid, node_id, dest_id, update_payload)
                    if response.get('status') == 'Success':
                        result_entry['result'] = 'Success'
                        logger.info(f"UPDATE success for {group_name} on {node_name}")
                    else:
                        result_entry['result'] = 'Fail'
                        result_entry['error'] = response.get('error', 'Unknown error')
                        logger.error(f"UPDATE fail for {group_name} on {node_name}: {result_entry['error']}")
                except Exception as e:
                    result_entry['result'] = 'Fail'
                    result_entry['error'] = str(e)
                    logger.error(f"UPDATE error for {group_name} on {node_name} - payload: {update_payload}: {str(e)}")

            results.append(result_entry)

    return results

def import_device_groups_for_nodes(
    client,
    pool_uuid: str,
    nodes: Any,
    xlsx_path: str,
    dry_run: bool = False,
    targets: List[str] = None
) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Imports device groups for specified nodes from an XLSX file.

    Coordinates the workflow: loads data, builds payloads, checks existing device groups
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
        Results include: siem, node, name, result, action, error.

    Raises:
        Exception: If XLSX loading or API calls fail.
    """
    rows = []
    any_error = False

    # Load Excel sheet with error handling
    try:
        df_group = pd.read_excel(xlsx_path, sheet_name="DeviceGroups")
        logger.debug(f"Loaded sheet: DeviceGroups ({len(df_group)} rows)")
    except Exception as e:
        logger.error(f"Failed to load XLSX data: {str(e)}")
        return [], True

    # Build payloads and get empty ES list (no equivalent for DeviceGroups)
    payloads, es_per_group = build_device_group_payloads(df_group)

    # Process per node, then per device group
    for target_type in targets:
        for node in nodes.get(target_type, []):
            node_id = node.id
            node_name = node.name
            siem = node_name  # Assuming siem is same as node_name

            # Check existing device groups
            check_results = check_existing_per_node(client, pool_uuid, node, payloads, es_per_group)

            for group_id, payload in payloads.items():
                group_name = payload['data']['name']
                if isinstance(payload['data']['description'], float) and np.isnan(payload['data']['description']):
                    payload['data']['description'] = ''
                if isinstance(payload['data']['tags'], float) and np.isnan(payload['data']['tags']):
                    payload['data']['tags'] = ''
                if isinstance(payload['data']['active'], np.bool_):
                    payload['data']['active'] = bool(payload['data']['active'])
                node_result = check_results.get(group_id, {}).get(node_name, {})
                action = node_result.get('action', 'NONE')

                result_entry = {
                    'siem': siem,
                    'node': node_name,
                    'name': group_name,
                    'result': 'N/A',
                    'action': action,
                    'error': node_result.get('error', '')
                }

                if action in ['SKIP', 'NOOP']:
                    result_entry['result'] = 'Skipped' if action == 'SKIP' else 'Noop'
                    logger.info(f"{action} for {group_name} on {node_name}")
                elif action in ['CREATE', 'UPDATE'] and not dry_run:
                    try:
                        if action == 'CREATE':
                            response = client.create_device_group(pool_uuid, node_id, payload)
                        elif action == 'UPDATE':
                            dest_id = node_result.get('existing_id')
                            update_payload = payload.copy()
                            update_payload['data']['id'] = dest_id
                            response = client.update_device_group(pool_uuid, node_id, dest_id, update_payload)
                        if response.get('status') == 'Success':
                            result_entry['result'] = 'Success'
                            logger.info(f"{action} success for {group_name} on {node_name}")
                        else:
                            result_entry['result'] = 'Fail'
                            result_entry['error'] = response.get('error', 'Unknown error')
                            logger.error(f"{action} fail for {group_name} on {node_name}: {result_entry['error']}")
                            any_error = True
                    except Exception as e:
                        result_entry['result'] = 'Fail'
                        result_entry['error'] = str(e)
                        logger.error(f"{action} error for {group_name} on {node_name} - payload: {payload}: {str(e)}")
                        any_error = True
                elif dry_run:
                    result_entry['result'] = 'Dry-run'
                    logger.info(f"Dry run: {action} for {group_name} on {node_name}")

                rows.append(result_entry)

    # Log summary
    actions_summary = {r['action']: sum(1 for res in rows if res['action'] == r['action']) for r in rows}
    logger.info(f"Import summary: {actions_summary}")
    logger.debug(f"result data: {rows}")

    return rows, any_error