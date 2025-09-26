import logging
import pandas as pd
from typing import Dict, List, Any, Tuple
import json
import numpy as np

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)

def build_syslog_collector_payloads(df: pd.DataFrame) -> Dict[str, Dict]:
    """
    Builds the Syslog Collector payloads from the DeviceFetcher DataFrame.

    Filters rows where app="SyslogCollector", constructs payloads based on proxy_condition,
    and handles list fields (hostname, proxy_ip) by splitting on "|". Excludes non-listed
    fields except charset and parser.

    Args:
        df (pd.DataFrame): DataFrame from "DeviceFetcher" sheet.

    Returns:
        Dict[str, Dict]: Dictionary of payloads keyed by device_id (or row index if None).
    """
    payloads = {}
    df_filtered = df[df['app'] == "SyslogCollector"].copy()

    for index, row in df_filtered.iterrows():
        device_id = row.get('device_id') if pd.notna(row['device_id']) else None
        key = device_id if device_id else str(index)
        
        # Split list fields, handle NaN as empty lists
        hostname = row['hostname'].split('|') if pd.notna(row['hostname']) else []
        hostname = [h.strip() for h in hostname if h.strip()]
        proxy_ip = row['proxy_ip'].split('|') if pd.notna(row['proxy_ip']) else []
        proxy_ip = [ip.strip() for ip in proxy_ip if ip.strip()]

        # Validate and build payload based on proxy_condition
        proxy_condition = row['proxy_condition']
        if proxy_condition not in ["use_as_proxy", "uses_proxy", None]:
            logger.warning(f"Invalid proxy_condition {proxy_condition} for {row['device_name']}, skipping payload")
            continue

        payload = {"data": {}}
        payload["data"]["proxy_condition"] = proxy_condition

        if proxy_condition in ["use_as_proxy", None]:
            if pd.isna(row['processpolicy']):
                logger.warning(f"Missing processpolicy for {row['device_name']} with proxy_condition {proxy_condition}")
                continue
            payload["data"]["processpolicy"] = row['processpolicy']
            if pd.isna(row['proxy_ip']):
                if proxy_condition == "None":
                    payload["data"]["proxy_ip"] = []
                else:
                    continue
            else:
                logger.warning(f"Unexpected proxy_ip for {row['device_name']} with proxy_condition {proxy_condition}")
                continue
        elif proxy_condition == "uses_proxy":
            if pd.isna(row['processpolicy']) or not proxy_ip:
                logger.warning(f"Missing processpolicy or proxy_ip for {row['device_name']} with proxy_condition uses_proxy")
                continue
            payload["data"]["processpolicy"] = row['processpolicy']
            payload["data"]["proxy_ip"] = proxy_ip

        # Mandatory fields for use_as_proxy and None, optional for uses_proxy
        if proxy_condition in ["use_as_proxy", None]:
            if pd.isna(row['charset']) or pd.isna(row['parser']):
                logger.warning(f"Missing charset or parser for {row['device_name']} with proxy_condition {proxy_condition}")
                continue
            payload["data"]["charset"] = row['charset']
            payload["data"]["parser"] = row['parser']
        elif proxy_condition == "uses_proxy" and (pd.notna(row['charset']) or pd.notna(row['parser'])):
            payload["data"]["charset"] = row['charset'] if pd.notna(row['charset']) else "utf_8"
            payload["data"]["parser"] = row['parser'] if pd.notna(row['parser']) else "SyslogParser"

        # Optional fields
        if hostname:
            payload["data"]["hostname"] = hostname

        logger.debug(f"Built payload for {row['device_name']}: {payload}")
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
            proxy_ips = set(proxy_ip)
            if not proxy_ips.issubset(all_ips):
                result = {"action": "SKIP", "error": f"Invalid proxy_ip {proxy_ips - all_ips}"}
                logger.warning(f"Skipping {device_name} on {node_name}: {result['error']}")
                results[device_id][node_name] = result
                continue
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
    hostname, charset, and parser. Handles lists (e.g., proxy_ip, hostname) by comparing
    sorted sets to account for order independence.

    Args:
        existing (Dict): Existing collector data.
        new (Dict): New collector data.

    Returns:
        bool: True if configurations are identical, False otherwise.
    """
    fields_to_compare = ["proxy_condition", "processpolicy", "charset", "parser"]
    for field in fields_to_compare:
        if existing.get(field) != new.get(field):
            return False

    # Compare lists (proxy_ip, hostname) as sorted sets
    existing_proxy_ip = set(existing.get("proxy_ip", []))
    new_proxy_ip = set(new.get("proxy_ip", []))
    if existing_proxy_ip != new_proxy_ip:
        return False

    existing_hostname = set(existing.get("hostname", []))
    new_hostname = set(new.get("hostname", []))
    if existing_hostname != new_hostname:
        return False

    return True