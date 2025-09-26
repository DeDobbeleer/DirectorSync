import logging
import pandas as pd
from typing import Dict, List, Any, Tuple
import json
import numpy as np

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)

def build_device_payloads(df_device: pd.DataFrame) -> Dict[str, Dict]:
    """
    Builds the device payloads from the provided DataFrame.

    Extracts fixed fields from the Device sheet and constructs payloads
    for each device, using only specified fields. Handles NaN as defaults (e.g., timezone="UTC",
    mandatory fields set to "Major" if invalid). Stores device group names for mapping.

    Parameters:
    df_device (pd.DataFrame): DataFrame from "Device" sheet.

    Returns:
    Dict[str, Dict]: A dictionary of payloads keyed by device_id.
    """
    payloads = {}

    valid_levels = ["Minimal", "Minor", "Major", "Critical"]

    # Process devices
    for index, row in df_device.iterrows():
        device_id = row['device_id']
        name = str(row['name']) if pd.notna(row['name']) else ""
        ip_str = row['ip']
        ip = [str(ip_str)] if pd.notna(ip_str) and ip_str else []
        timezone = str(row['timezone']) if pd.notna(row['timezone']) else "UTC"
        availability = str(row['availability']) if pd.notna(row['availability']) and str(row['availability']) in valid_levels else "Major"
        confidentiality = str(row['confidentiality']) if pd.notna(row['confidentiality']) and str(row['confidentiality']) in valid_levels else "Major"
        integrity = str(row['integrity']) if pd.notna(row['integrity']) and str(row['integrity']) in valid_levels else "Major"
        device_groups_str = str(row['device_groups']) if pd.notna(row['device_groups']) else ""

        # Temp store names for mapping
        names = [n.strip() for n in device_groups_str.split('|') if n.strip()]

        payload = {
            "data": {
                "name": name,
                "ip": ip,
                "timezone": timezone,
                "devicegroup": [],  # To be mapped per node
                "distributed_collector": [],  # Forced empty as per client request
                "availability": availability,
                "confidentiality": confidentiality,
                "integrity": integrity,
                "logpolicy": [],  # Forced empty as per client request
                "_device_groups_names": names  # Temporary for mapping
            }
        }

        logger.debug(f"Built base payload for device_id {device_id}: {payload}")

        payloads[device_id] = payload

    return payloads

def check_existing_per_node(
    client: DirectorClient,
    pool_uuid: str,
    node: Node,
    payloads: Dict[str, Dict]
) -> Dict[str, Dict]:
    """
    Checks existing Devices per node.

    For each node, fetches DeviceGroups for mapping, then lists existing Devices, matches by name or ip,
    and determines the action (NOOP, SKIP, CREATE, UPDATE) based on specified fields only.
    Skips if any devicegroup name missing or mandatory fields invalid. Maps devicegroup IDs
    before comparison and normalizes forced empty arrays.

    Parameters:
    client: DirectorClient instance for API calls.
    pool_uuid (str): UUID of the pool.
    node (Node): Node object with 'id' and 'name'.
    payloads (Dict[str, Dict]): Dictionary of payloads keyed by device_id.

    Returns:
    Dict[str, Dict]: Dictionary of results per device_id, with node-specific actions and mapped data.
    """
    results = {device_id: {} for device_id in payloads.keys()}

    node_id = node.id
    node_name = node.name

    # Fetch DeviceGroups for mapping
    try:
        groups = client.get_device_groups(pool_uuid, node_id)
        group_map = {g.get('name', '').lower(): g.get('id') for g in groups}  # Case-insensitive match
        logger.debug(f"Fetched DeviceGroups for node {node_name}: {list(group_map.keys())}")
    except Exception as e:
        logger.error(f"Failed to fetch DeviceGroups for node {node_name}: {str(e)}")
        return results

    # Fetch existing Devices
    try:
        devices = client.get_devices(pool_uuid, node_id)
        existing_by_key = {}
        for d in devices:
            key = (d.get('name', '').lower(), tuple(sorted(d.get('ip', []))))
            existing_by_key[key] = d
        logger.debug(f"Fetched Devices list for node {node_name}: {len(devices)} devices")
    except Exception as e:
        logger.error(f"Failed to fetch Devices list for node {node_name}: {str(e)}")
        return results

    valid_levels = ["Minimal", "Minor", "Major", "Critical"]

    for device_id, payload in payloads.items():
        base_data = payload['data']
        names = base_data.pop('_device_groups_names', [])  # Remove temp field

        # Map devicegroup (case-insensitive)
        ids = [group_map.get(n.lower()) for n in names]
        logger.debug(f"Mapping device_groups for {device_id}: names={names}, ids={ids}")
        if any(id is None for id in ids):
            missing = [n for n, id_ in zip(names, ids) if id_ is None]
            results[device_id][node_name] = {
                'action': 'SKIP',
                'error': f"Missing devicegroup(s): {', '.join(missing)}"
            }
            logger.warning(f"SKIP for device_id {device_id} on {node_name} due to missing groups: {missing}")
            continue

        mapped_data = base_data.copy()
        mapped_data['devicegroup'] = sorted(ids)  # Sort for consistent comparison

        # Validate mandatory fields
        if not mapped_data['name'] or not mapped_data['ip'] or mapped_data['availability'] not in valid_levels or mapped_data['confidentiality'] not in valid_levels or mapped_data['integrity'] not in valid_levels:
            results[device_id][node_name] = {
                'action': 'SKIP',
                'error': 'Missing mandatory fields or invalid values'
            }
            logger.warning(f"Skipping {mapped_data['name']} on {node_name} due to {results[device_id][node_name]['error']}")
            continue

        # Match existing by name and sorted ip (case-insensitive)
        key = (mapped_data['name'].lower(), tuple(sorted(mapped_data['ip'])))
        existing = existing_by_key.get(key)

        action = 'SKIP'
        error_msg = None
        existing_id = None

        if existing:
            # Compare specified fields (normalize forced empty arrays)
            existing_spec = {
                'name': existing.get('name', '').lower(),
                'ip': sorted(existing.get('ip', [])),
                'timezone': existing.get('timezone', ''),
                'devicegroup': sorted(existing.get('devicegroup', [])),
                'distributed_collector': [],
                'availability': existing.get('availability', ''),
                'confidentiality': existing.get('confidentiality', ''),
                'integrity': existing.get('integrity', ''),
                'logpolicy': []
            }
            new_spec = {
                'name': mapped_data['name'].lower(),
                'ip': sorted(mapped_data['ip']),
                'timezone': mapped_data['timezone'],
                'devicegroup': sorted(mapped_data['devicegroup']),
                'distributed_collector': sorted(mapped_data['distributed_collector']),
                'availability': mapped_data['availability'],
                'confidentiality': mapped_data['confidentiality'],
                'integrity': mapped_data['integrity'],
                'logpolicy': sorted(mapped_data['logpolicy'])
            }
            logger.debug(f"Existing spec for {mapped_data['name']}: {existing_spec}")
            logger.debug(f"New spec for {mapped_data['name']}: {new_spec}")
            if json.dumps(existing_spec, sort_keys=True) == json.dumps(new_spec, sort_keys=True):
                action = 'NOOP'
                logger.info(f"NOOP for {mapped_data['name']} on {node_name}")
            else:
                action = 'UPDATE'
                existing_id = existing.get('id')
                logger.info(f"UPDATE needed for {mapped_data['name']} on {node_name}")
        else:
            action = 'CREATE'
            logger.info(f"CREATE needed for {mapped_data['name']} on {node_name}")

        results[device_id][node_name] = {
            'action': action,
            'existing_id': existing_id,
            'devicegroup_ids': ids,
            'error': error_msg
        }

    return results

def import_devices_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List[Node]],
    xlsx_path: str,
    dry_run: bool = False,
    targets: List[str] = None
) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Imports devices for specified nodes from an XLSX file.

    Coordinates the workflow: loads data, builds payloads, checks existing devices
    per node, executes actions (CREATE, UPDATE, NOOP, SKIP), and returns results.

    Args:
        client: DirectorClient instance for API calls.
        pool_uuid (str): UUID of the pool.
        nodes (Dict[str, List[Node]]): Dictionary of nodes by role.
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
        df_device = pd.read_excel(xlsx_path, sheet_name="Device")
        logger.debug(f"Loaded sheet: Device ({len(df_device)} rows)")
    except Exception as e:
        logger.error(f"Failed to load XLSX data: {str(e)}")
        return [], True

    # Build payloads
    payloads = build_device_payloads(df_device)

    # Process per target type and node
    for target_type in targets or ["backends", "all_in_one"]:
        for node in nodes.get(target_type, []):
            node_id = node.id
            node_name = node.name
            siem = node_name

            # Check existing devices (includes mapping and validation)
            check_results = check_existing_per_node(client, pool_uuid, node, payloads)

            for device_id, payload in payloads.items():
                base_data = payload['data']
                name = base_data['name']
                node_result = check_results.get(device_id, {}).get(node_name, {})
                action = node_result.get('action', 'NONE')
                devicegroup_ids = node_result.get('devicegroup_ids', [])
                existing_id = node_result.get('existing_id')

                result_entry = {
                    'siem': siem,
                    'node': node_name,
                    'name': name,
                    'result': 'N/A',
                    'action': action,
                    'error': node_result.get('error', '-')
                }

                if action in ['SKIP', 'NOOP']:
                    result_entry['result'] = 'Skipped' if action == 'SKIP' else 'Noop'
                    logger.info(f"{action} for {name} on {node_name}")
                elif action in ['CREATE', 'UPDATE'] and not dry_run:
                    # Build full payload with mapped groups
                    exec_payload = payload.copy()
                    exec_payload['data']['devicegroup'] = devicegroup_ids
                    if action == 'UPDATE':
                        exec_payload['data']['id'] = existing_id

                    try:
                        if action == 'CREATE':
                            response = client.create_device(pool_uuid, node_id, exec_payload)
                        else:
                            response = client.update_device(pool_uuid, node_id, existing_id, exec_payload)
                        if response.get('status') == 'Success':
                            result_entry['result'] = 'Success'
                            logger.info(f"{action} success for {name} on {node_name}")
                        else:
                            result_entry['result'] = 'Fail'
                            result_entry['error'] = response.get('error', 'Unknown error')
                            logger.error(f"{action} fail for {name} on {node_name}: {result_entry['error']}")
                            any_error = True
                    except Exception as e:
                        result_entry['result'] = 'Fail'
                        result_entry['error'] = str(e)
                        logger.error(f"{action} error for {name} on {node_name}: {str(e)}")
                        any_error = True
                elif dry_run:
                    result_entry['result'] = 'Dry-run'
                    logger.info(f"Dry run: {action} for {name} on {node_name}")

                rows.append(result_entry)

    # Log summary
    actions_summary = {r['action']: sum(1 for res in rows if res['action'] == r['action']) for r in rows}
    logger.info(f"Devices import summary: {actions_summary}")

    return rows, any_error