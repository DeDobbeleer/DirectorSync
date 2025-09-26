import logging
import requests
import pandas as pd
from typing import Dict, List, Any, Tuple
import json
import numpy as np

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)

def build_syslog_collector_payloads(df: pd.DataFrame, client: DirectorClient, pool_uuid: str, node_id: str) -> Dict[str, Dict]:
    """
    Builds the Syslog Collector payloads from the DeviceFetcher DataFrame.

    Fetches existing device_ids from the API, matches them with XLSX rows based on device_name,
    and constructs payloads including the API device_id.

    Args:
        df (pd.DataFrame): DataFrame from "DeviceFetcher" sheet.
        client (DirectorClient): API client instance.
        pool_uuid (str): UUID of the pool.
        node_id (str): ID of the current node.

    Returns:
        Dict[str, Dict]: Dictionary of payloads keyed by device_id (or row index if None).
    """
    payloads = {}
    df_filtered = df[df['app'] == "SyslogCollector"].copy()

    # Fetch existing devices to get device_ids
    try:
        devices = client.get_devices(pool_uuid, node_id)
        device_map = {d.get('device_name', str(i)): d.get('device_id') for i, d in enumerate(devices)}
        logger.debug(f"Device map from API: {device_map}")
    except Exception as e:
        logger.error(f"Failed to fetch devices for node {node_id}: {str(e)}")
        return payloads

    for index, row in df_filtered.iterrows():
        device_id = row.get('device_id') if pd.notna(row['device_id']) else None
        key = device_id if device_id else str(index)
        device_name = row.get('device_name', '')  # Assuming device_name is the matching field

        # Split list fields, handle NaN as empty lists
        hostname = row['hostname'].split('|') if pd.notna(row['hostname']) else []
        hostname = [h.strip() for h in hostname if h.strip()]
        proxy_ip = row['proxy_ip'].split('|') if pd.notna(row['proxy_ip']) else []
        proxy_ip = [ip.strip() for ip in proxy_ip if ip.strip()]

        # Validate and build payload based on proxy_condition
        proxy_condition = row['proxy_condition']
        if proxy_condition not in ["use_as_proxy", "uses_proxy", None]:
            logger.warning(f"Invalid proxy_condition {proxy_condition} for {device_name}, skipping payload")
            continue

        payload = {"data": {}}
        payload["data"]["proxy_condition"] = proxy_condition

        if proxy_condition in ["use_as_proxy", None]:
            if pd.isna(row['processpolicy']):
                logger.warning(f"Missing processpolicy for {device_name} with proxy_condition {proxy_condition}")
                continue
            payload["data"]["processpolicy"] = row['processpolicy']
            if pd.isna(row['proxy_ip']):
                if proxy_condition == "None":
                    payload["data"]["proxy_ip"] = []
                else:
                    continue
            else:
                logger.warning(f"Unexpected proxy_ip for {device_name} with proxy_condition {proxy_condition}")
                continue
        elif proxy_condition == "uses_proxy":
            if pd.isna(row['processpolicy']) or not proxy_ip:
                logger.warning(f"Missing processpolicy or proxy_ip for {device_name} with proxy_condition uses_proxy")
                continue
            payload["data"]["processpolicy"] = row['processpolicy']
            payload["data"]["proxy_ip"] = proxy_ip

        # Mandatory fields for use_as_proxy and None, optional for uses_proxy
        if proxy_condition in ["use_as_proxy", None]:
            if pd.isna(row['charset']) or pd.isna(row['parser']):
                logger.warning(f"Missing charset or parser for {device_name} with proxy_condition {proxy_condition}")
                continue
            payload["data"]["charset"] = row['charset']
            payload["data"]["parser"] = row['parser']
        elif proxy_condition == "uses_proxy" and (pd.notna(row['charset']) or pd.notna(row['parser'])):
            payload["data"]["charset"] = row['charset'] if pd.notna(row['charset']) else "utf_8"
            payload["data"]["parser"] = row['parser'] if pd.notna(row['parser']) else "SyslogParser"

        # Add device_id from API
        api_device_id = device_map.get(device_name)
        if not api_device_id:
            logger.warning(f"No matching device_id found for {device_name} in API, skipping payload")
            continue
        payload["data"]["device_id"] = api_device_id

        # Optional fields
        if hostname:
            payload["data"]["hostname"] = hostname

        logger.debug(f"Built payload for {device_name}: {payload}")
        payloads[key] = payload

    return payloads

def check_existing_per_node(client: DirectorClient, pool_uuid: str, node: Node, payloads: Dict[str, Dict], df: pd.DataFrame) -> Dict[str, Dict]:
    """
    Checks existing Syslog Collectors per node.

    Fetches devices via get_devices to validate existence and cross-check proxy_ip for uses_proxy
    against ips from the XLSX sheet. Determines actions (NOOP, SKIP, CREATE, UPDATE) based on matching fields.

    Args:
        client (DirectorClient): API client instance.
        pool_uuid (str): UUID of the pool.
        node (Node): Node object with id and name.
        payloads (Dict[str, Dict]): Dictionary of payloads keyed by device_id or index.
        df (pd.DataFrame): Original DataFrame from "DeviceFetcher" for IP extraction.

    Returns:
        Dict[str, Dict]: Dictionary of results per device_id, with node-specific actions.
    """
    results = {device_id: {} for device_id in payloads.keys()}
    node_id = node.id
    node_name = node.name
    siem = node_name  # Assuming siem is node_name

    # Fetch existing devices for existence check
    try:
        devices = client.get_devices(pool_uuid, node_id)
        existing_devices = {d.get('device_id', str(i)): d for i, d in enumerate(devices)}
        logger.debug(f"Fetched devices for node {node_name}: {list(existing_devices.keys())}")
    except Exception as e:
        logger.error(f"Failed to fetch devices for node {node_name}: {str(e)}")
        return results

    # Extract all ips from the DataFrame for internal cross-check
    all_ips = set()
    for _, row in df.iterrows():
        ips = row.get('ips', '').split('|') if pd.notna(row.get('ips')) else []
        all_ips.update(ip.strip() for ip in ips if ip.strip())
    logger.debug(f"Extracted all IPs from XLSX for cross-check: {all_ips}")

    for device_id, payload in payloads.items():
        device_name = f"Device_{device_id}"  # Placeholder, adjust if device_name is in payload
        proxy_condition = payload["data"]["proxy_condition"]
        result = {"action": "NONE"}

        # Validate mandatory fields
        if proxy_condition == "use_as_proxy":
            if any(pd.isna(payload["data"].get(field)) for field in ["charset", "parser"]):
                result = {"action": "SKIP", "error": "Missing charset or parser"}
                logger.warning(f"Skipping {device_name} on {node_name}: {result['error']}")
                results[device_id][node_name] = result
                continue
            if pd.notna(payload["data"].get("processpolicy")) and payload["data"].get("processpolicy") != "":
                result = {"action": "SKIP", "error": "Unexpected processpolicy for use_as_proxy"}
                logger.warning(f"Skipping {device_name} on {node_name}: {result['error']}")
                results[device_id][node_name] = result
                continue
            if pd.notna(payload["data"].get("proxy_ip")) and payload["data"].get("proxy_ip"):
                result = {"action": "SKIP", "error": "Unexpected proxy_ip for use_as_proxy"}
                logger.warning(f"Skipping {device_name} on {node_name}: {result['error']}")
                results[device_id][node_name] = result
                continue
        elif proxy_condition == "uses_proxy":
            processpolicy = payload["data"].get("processpolicy")
            proxy_ip = payload["data"].get("proxy_ip", [])
            if pd.isna(processpolicy) or not processpolicy or not proxy_ip:
                result = {"action": "SKIP", "error": "Missing processpolicy or proxy_ip"}
                logger.warning(f"Skipping {device_name} on {node_name}: {result['error']}")
                results[device_id][node_name] = result
                continue
            # Internal cross-check of proxy_ip against all ips in XLSX
            # proxy_ips = set(proxy_ip)
            # if not proxy_ips.issubset(all_ips):
            #     result = {"action": "SKIP", "error": f"Invalid proxy_ip {proxy_ips - all_ips}"}
            #     logger.warning(f"Skipping {device_name} on {node_name}: {result['error']}")
            #     results[device_id][node_name] = result
            #     continue
        elif proxy_condition is None:
            if any(pd.isna(payload["data"].get(field)) or (field == "processpolicy" and not payload["data"].get(field)) for field in ["processpolicy", "charset", "parser"]):
                result = {"action": "SKIP", "error": "Missing processpolicy, charset, or parser"}
                logger.warning(f"Skipping {device_name} on {node_name}: {result['error']}")
                results[device_id][node_name] = result
                continue
            if pd.notna(payload["data"].get("proxy_ip")) and payload["data"].get("proxy_ip"):
                result = {"action": "SKIP", "error": "Unexpected proxy_ip for None"}
                logger.warning(f"Skipping {device_name} on {node_name}: {result['error']}")
                results[device_id][node_name] = result
                continue

        # Check existence and compare
        existing = existing_devices.get(device_id, {})
        if existing:
            existing_data = existing.get("data", {})
            new_data = payload["data"]
            if _compare_syslog_collector(existing_data, new_data):
                result = {"action": "NOOP"}
                logger.info(f"NOOP for {device_name} on {node_name}")
            else:
                result = {"action": "UPDATE", "existing_id": existing.get("id")}
                logger.info(f"UPDATE needed for {device_name} on {node_name}")
        else:
            result = {"action": "CREATE"}
            logger.info(f"CREATE needed for {device_name} on {node_name}")

        results[device_id][node_name] = result

    return results

def _compare_syslog_collector(existing: Dict, new: Dict) -> bool:
    """
    Compares two Syslog Collector configurations for equality.

    Performs a case-sensitive comparison of proxy_condition, processpolicy, proxy_ip,
    hostname, charset, and parser.

    Args:
        existing (Dict): Existing collector data.
        new (Dict): New collector data.

    Returns:
        bool: True if configurations are identical, False otherwise.
    """
    fields_to_compare = ["proxy_condition", "processpolicy", "proxy_ip", "hostname", "charset", "parser"]
    for field in fields_to_compare:
        if existing.get(field) != new.get(field):
            return False
    return True

def execute_actions_per_node(client: DirectorClient, pool_uuid: str, nodes: List[Node], payloads: Dict[str, Dict], check_results: Dict[str, Dict]) -> List[Dict]:
    """
    Executes the actions (CREATE, UPDATE) for each Syslog Collector per node.

    Loops over nodes, then over payloads, using check_results to determine actions.
    Monitors jobs and collects results in a list of dictionaries (siem, node, name, result, action, error).

    Args:
        client (DirectorClient): API client instance.
        pool_uuid (str): UUID of the pool.
        nodes (List[Node]): List of node objects with id and name.
        payloads (Dict[str, Dict]): Dictionary of payloads keyed by device_id or index.
        check_results (Dict[str, Dict]): Results from check_existing_per_node.

    Returns:
        List[Dict]: List of result dictionaries for the output table.
    """
    results = []

    for node in nodes:
        node_id = node.id
        node_name = node.name
        siem = node_name  # Assuming siem is node_name

        for device_id, payload in payloads.items():
            device_name = f"Device_{device_id}"  # Placeholder, adjust if device_name is available
            node_result = check_results.get(device_id, {}).get(node_name, {})
            action = node_result.get("action", "NONE")

            result_entry = {
                "siem": siem,
                "node": node_name,
                "name": device_name,
                "result": "N/A",
                "action": action,
                "error": node_result.get("error", "")
            }

            if action in ["SKIP", "NOOP"]:
                result_entry["result"] = "Skipped" if action == "SKIP" else "Noop"
                logger.info(f"{action} for {device_name} on {node_name}")
            elif action in ["CREATE", "UPDATE"] and not "dry_run":
                try:
                    if action == "CREATE":
                        response = client.create_syslog_collector(pool_uuid, node_id, payload)
                    elif action == "UPDATE":
                        existing_id = node_result.get("existing_id")
                        update_payload = payload.copy()
                        update_payload["data"]["id"] = existing_id
                        response = client.update_syslog_collector(pool_uuid, node_id, existing_id, update_payload)

                    if response.get("status") == "Success":
                        monitorapi = response.get("message")
                        if monitorapi and monitorapi.startswith("/monitorapi/"):
                            job_status = client.monitor_job(monitorapi)
                            if job_status.get("success"):
                                result_entry["result"] = "Success"
                                logger.info(f"{action} success for {device_name} on {node_name}")
                            else:
                                result_entry["result"] = "Fail"
                                result_entry["error"] = job_status.get("error", "Unknown error")
                                logger.error(f"{action} fail for {device_name} on {node_name}: {result_entry['error']}")
                                any_error = True
                        else:
                            result_entry["result"] = "Success"
                            logger.info(f"{action} success for {device_name} on {node_name} (no monitoring)")
                    else:
                        result_entry["result"] = "Fail"
                        result_entry["error"] = response.get("error", "Unknown error")
                        logger.error(f"{action} fail for {device_name} on {node_name}: {result_entry['error']}")
                        any_error = True
                except Exception as e:
                    result_entry["result"] = "Fail"
                    result_entry["error"] = str(e)
                    logger.error(f"{action} error for {device_name} on {node_name}: {str(e)}")
                    any_error = True
            elif "dry_run":
                result_entry["result"] = "Dry-run"
                logger.info(f"Dry run: {action} for {device_name} on {node_name}")

            results.append(result_entry)

    return results

def import_syslog_collectors_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List[Node]],
    xlsx_path: str,
    dry_run: bool = False,
    targets: List[str] = None
) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Imports Syslog Collectors for specified nodes from an XLSX file.

    Coordinates the workflow: loads data, builds payloads, checks existing collectors
    per node, executes actions (CREATE, UPDATE, NOOP, SKIP), and returns results.

    Args:
        client (DirectorClient): API client instance.
        pool_uuid (str): UUID of the pool.
        nodes (Dict[str, List[Node]]): Dictionary of node lists by role (e.g., backends).
        xlsx_path (str): Path to the configuration XLSX file.
        dry_run (bool): If True, simulate without API calls.
        targets (List[str]): List of target node roles (e.g., ['backends', 'all_in_one']).

    Returns:
        Tuple[List[Dict[str, Any]], bool]: Tuple of (list of results, error indicator).
        Results include: siem, node, name, action, result, error.

    Raises:
        Exception: If XLSX loading or API calls fail.
    """
    rows = []
    any_error = False

    # Load Excel sheet with error handling
    try:
        df = pd.read_excel(xlsx_path, sheet_name="DeviceFetcher")
        logger.debug(f"Loaded DeviceFetcher sheet: {len(df)} rows")
    except Exception as e:
        logger.error(f"Failed to load XLSX data: {str(e)}")
        return [], True

    # Build payloads
    payloads = build_syslog_collector_payloads(df)

    # Process per node, then per collector
    for target_type in targets or ["backends", "all_in_one"]:
        for node in nodes.get(target_type, []):
            node_id = node.id
            node_name = node.name
            siem = node_name  # Assuming siem is node_name

            # Check existing collectors with the DataFrame
            check_results = check_existing_per_node(client, pool_uuid, node, payloads, df)

            for device_id, payload in payloads.items():
                device_name = f"Device_{device_id}"  # Placeholder, adjust if device_name is available
                node_result = check_results.get(device_id, {}).get(node_name, {})
                action = node_result.get("action", "NONE")

                result_entry = {
                    "siem": siem,
                    "node": node_name,
                    "name": device_name,
                    "action": action,
                    "result": "N/A",
                    "error": node_result.get("error", "")
                }

                if action in ["SKIP", "NOOP"]:
                    result_entry["result"] = "Skipped" if action == "SKIP" else "Noop"
                    logger.info(f"{action} for {device_name} on {node_name}")
                elif action in ["CREATE", "UPDATE"] and not dry_run:
                    try:
                        if action == "CREATE":
                            response = client.create_syslog_collector(pool_uuid, node_id, payload)
                        elif action == "UPDATE":
                            existing_id = node_result.get("existing_id")
                            update_payload = payload.copy()
                            update_payload["data"]["id"] = existing_id
                            response = client.update_syslog_collector(pool_uuid, node_id, existing_id, update_payload)

                        if response.get("status") == "Success":
                            monitorapi = response.get("message")
                            if monitorapi and monitorapi.startswith("/monitorapi/"):
                                job_status = client.monitor_job(monitorapi)
                                if job_status.get("success"):
                                    result_entry["result"] = "Success"
                                    logger.info(f"{action} success for {device_name} on {node_name}")
                                else:
                                    result_entry["result"] = "Fail"
                                    result_entry["error"] = job_status.get("error", "Unknown error")
                                    logger.error(f"{action} fail for {device_name} on {node_name}: {result_entry['error']}")
                                    any_error = True
                            else:
                                result_entry["result"] = "Success"
                                logger.info(f"{action} success for {device_name} on {node_name} (no monitoring)")
                        else:
                            result_entry["result"] = "Fail"
                            result_entry["error"] = response.get("error", "Unknown error")
                            logger.error(f"{action} fail for {device_name} on {node_name}: {result_entry['error']}")
                            any_error = True
                    except requests.RequestException as e:
                        logger.error("Failed to create syslog collectot policy: %s", str(e.response.text))
                    except Exception as e:
                        result_entry["result"] = "Fail"
                        result_entry["error"] = str(e)
                        logger.error(f"{action} error for {device_name} on {node_name}: {str(e)}")
                        any_error = True
                elif dry_run:
                    result_entry["result"] = "Dry-run"
                    logger.info(f"Dry run: {action} for {device_name} on {node_name}")

                rows.append(result_entry)

    # Log summary
    actions_summary = {r["action"]: sum(1 for res in rows if res["action"] == r["action"]) for r in rows}
    logger.info(f"Import summary: {actions_summary}")

    return rows, any_error