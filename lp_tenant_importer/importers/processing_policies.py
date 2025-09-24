import logging
import pandas as pd
from typing import Dict, List, Any, Tuple
import json
import requests

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)

def import_processing_policies_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List[Node]],
    xlsx_path: str,
    dry_run: bool,
    targets: List[str],
) -> Tuple[List[Dict[str, Any]], bool]:
    """Import processing policies for the specified nodes.

    Reads the 'ProcessingPolicy', 'EnrichmentPolicy', and 'RoutingPolicy' sheets from the XLSX file,
    maps source IDs to names, fetches target IDs via API for each node, and performs CREATE/UPDATE/NOOP/SKIP actions.
    Excel is the source of truth; SKIP if any dependency is missing. routing_policy never uses 'None' if required.

    Args:
        client: DirectorClient instance for API calls.
        pool_uuid: Tenant pool UUID.
        nodes: Dictionary of node types and Node instances.
        xlsx_path: Path to the XLSX configuration file.
        dry_run: If True, simulate actions without API calls.
        targets: List of target node roles (e.g., ['backends', 'all_in_one']).

    Returns:
        Tuple of (list of result rows, any_error flag).
        Rows include: siem, node, name, norm_policy, enrich_policy, routing_policy, action, result, error.
    """
    rows = []
    any_error = False

    # Load all relevant sheets and handle NaN
    try:
        pp_df = pd.read_excel(xlsx_path, sheet_name="ProcessingPolicy", skiprows=0).fillna("")
        ep_df = pd.read_excel(xlsx_path, sheet_name="EnrichmentPolicy", skiprows=0)
        rp_df = pd.read_excel(xlsx_path, sheet_name="RoutingPolicy", skiprows=0)
        logger.debug("Loaded ProcessingPolicy, EnrichmentPolicy, and RoutingPolicy sheets")
        logger.debug("EnrichmentPolicy columns: %s", list(ep_df.columns))
        logger.debug("RoutingPolicy columns: %s", list(rp_df.columns))
    except Exception as e:
        logger.error("Failed to load sheets: %s", e)
        return [], True

    # Validate column names based on specified structure
    required_ep_columns = ["policy_id", "policy_name"]
    required_rp_columns = ["policy_id", "cleaned_policy_name"]
    if not all(col in ep_df.columns for col in required_ep_columns):
        logger.error("Missing required columns in EnrichmentPolicy sheet: expected %s, found %s",
                     required_ep_columns, list(ep_df.columns))
        return [], True
    if not all(col in rp_df.columns for col in required_rp_columns):
        logger.error("Missing required columns in RoutingPolicy sheet: expected %s, found %s",
                     required_rp_columns, list(rp_df.columns))
        return [], True

    # Build source ID to name mappings
    ep_mapping = dict(zip(ep_df["policy_id"], ep_df["policy_name"]))
    rp_mapping = dict(zip(rp_df["policy_id"], rp_df["cleaned_policy_name"]))

    # Process per node
    for target_type in targets:
        for node in nodes.get(target_type, []):
            logpoint_id = node.id
            logger.debug("Processing policies for node %s (%s)", node.name, logpoint_id)

            # Fetch existing policies for the current node
            existing_policies = {}
            try:
                resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy")
                resp.raise_for_status()
                policies_data = resp.json()
                logger.debug(f"Existing PP on {node.name} PoliciesData : {policies_data}")
                if isinstance(policies_data, list):
                    existing_policies = {p.get("name", "").strip(): p for p in policies_data if p.get("name")}
                    logger.debug("Existing policies for %s: %d", logpoint_id, len(existing_policies))
                else:
                    logger.warning("Unexpected response for policies on %s: %s", logpoint_id, policies_data)
            except Exception as e:
                logger.error("Failed to fetch existing policies for %s: %s", logpoint_id, e)
                any_error = True
                continue

            # Fetch dependencies for the current node
            norm_policies = set()
            enrich_policies = {}
            routing_policies = {}
            try:
                norm_resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy")
                norm_resp.raise_for_status()
                norm_data = norm_resp.json()
                logger.debug("NormalizationPolicy response for %s: %s", logpoint_id, norm_data)
                norm_policies = {p.get("name") for p in norm_data if p.get("name")}
                enrich_resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy")
                enrich_resp.raise_for_status()
                enrich_data = enrich_resp.json()
                logger.debug("EnrichmentPolicy response for %s: %s", logpoint_id, enrich_data)
                enrich_policies = {p.get("policy_name"): p.get("id") for p in enrich_data if p.get("policy_name") and p.get("id")}
                try:
                    routing_resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies")
                    routing_resp.raise_for_status()
                    routing_data = routing_resp.json()
                    logger.debug("RoutingPolicies response for %s: %s", logpoint_id, routing_data)
                    routing_policies = {p.get("policy_name"): p.get("id") for p in routing_data if p.get("policy_name") and p.get("id")}
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 400:
                        logger.error("Failed to fetch RoutingPolicies for %s: 400 Bad Request, skipping dependent policies", logpoint_id)
                    else:
                        raise
            except Exception as e:
                logger.error("Failed to fetch dependencies for %s: %s", logpoint_id, e)
                any_error = True
                continue

            # Process each processing policy row for the current node
            for _, row in pp_df.iterrows():
                original_name = row.get("original_policy_name", "").strip()
                cleaned_policy_name = row.get("cleaned_policy_name", original_name).strip()
                policy_name = cleaned_policy_name or original_name
                if not policy_name:
                    logger.warning("Skipping row with empty policy_name")
                    continue

                # active is kept internally but not sent to API
                active = bool(row.get("active", True))  # Default True, direct bool conversion
                norm_policy = row.get("norm_policy", "").strip()
                enrich_policy_src_id = str(row.get("enrich_policy", "")).strip()
                routing_policy_src_id = str(row.get("routing_policy_id", "")).strip()

                # Validate all dependencies from Excel
                if norm_policy and norm_policy not in norm_policies:
                    row_result = {
                        "siem": logpoint_id,
                        "node": node.name,
                        "name": policy_name,
                        "norm_policy": norm_policy,
                        "enrich_policy": None,
                        "routing_policy": None,
                        "action": "SKIP",
                        "result": "N/A",
                        "error": "Invalid norm_policy: %s not found" % norm_policy
                    }
                    rows.append(row_result)
                    logger.warning("Skipping %s on %s: %s", policy_name, logpoint_id, row_result["error"])
                    continue

                # Map enrich_policy
                enrich_policy_name = ep_mapping.get(enrich_policy_src_id, None) if enrich_policy_src_id else None
                enrich_policy_dest_id = "None" if not enrich_policy_src_id else enrich_policies.get(enrich_policy_name, "None")
                if enrich_policy_src_id and enrich_policy_dest_id == "None":
                    row_result = {
                        "siem": logpoint_id,
                        "node": node.name,
                        "name": policy_name,
                        "norm_policy": norm_policy,
                        "enrich_policy": None,
                        "routing_policy": None,
                        "action": "SKIP",
                        "result": "N/A",
                        "error": "Invalid enrich_policy: %s not found in target" % enrich_policy_name
                    }
                    rows.append(row_result)
                    logger.warning("Skipping %s on %s: %s", policy_name, logpoint_id, row_result["error"])
                    continue

                # Map routing_policy (never None if required)
                if not routing_policy_src_id:
                    row_result = {
                        "siem": logpoint_id,
                        "node": node.name,
                        "name": policy_name,
                        "norm_policy": norm_policy,
                        "enrich_policy": enrich_policy_dest_id,
                        "routing_policy": None,
                        "action": "SKIP",
                        "result": "N/A",
                        "error": "Missing mandatory routing_policy"
                    }
                    rows.append(row_result)
                    logger.warning("Skipping %s on %s: %s", policy_name, logpoint_id, row_result["error"])
                    continue

                routing_policy_name = rp_mapping.get(routing_policy_src_id, None)
                if not routing_policy_name:
                    row_result = {
                        "siem": logpoint_id,
                        "node": node.name,
                        "name": policy_name,
                        "norm_policy": norm_policy,
                        "enrich_policy": enrich_policy_dest_id,
                        "routing_policy": None,
                        "action": "SKIP",
                        "result": "N/A",
                        "error": "Invalid routing_policy source ID: %s not found in mapping" % routing_policy_src_id
                    }
                    rows.append(row_result)
                    logger.warning("Skipping %s on %s: %s", policy_name, logpoint_id, row_result["error"])
                    continue
                routing_policy_dest_id = routing_policies.get(routing_policy_name)
                if not routing_policy_dest_id:
                    row_result = {
                        "siem": logpoint_id,
                        "node": node.name,
                        "name": policy_name,
                        "norm_policy": norm_policy,
                        "enrich_policy": enrich_policy_dest_id,
                        "routing_policy": None,
                        "action": "SKIP",
                        "result": "N/A",
                        "error": "Invalid routing_policy: %s not found in target" % routing_policy_name
                    }
                    rows.append(row_result)
                    logger.warning("Skipping %s on %s: %s", policy_name, logpoint_id, row_result["error"])
                    continue

                # Build payload without active, using destination IDs
                policy_data = {
                    "policy_name": policy_name,
                    "norm_policy": norm_policy,
                    "enrich_policy": enrich_policy_dest_id,
                    "routing_policy": routing_policy_dest_id
                }

                logger.debug("Processing policy %s on %s with payload: %s",
                             policy_name, logpoint_id, json.dumps(policy_data, indent=2))

                # Check existence and decide action
                action, result, error = _process_policy_action(client, pool_uuid, logpoint_id, dry_run, policy_data, existing_policies.get(policy_name))
                row_result = {
                    "siem": logpoint_id,
                    "node": node.name,
                    "name": policy_name,
                    "norm_policy": norm_policy,
                    "enrich_policy": policy_data.get("enrich_policy"),
                    "routing_policy": policy_data.get("routing_policy"),
                    "action": action,
                    "result": result,
                    "error": error or (json.loads(result.get("error", "{}")) if result and result.get("error") else "")
                }
                rows.append(row_result)

                if result == "Fail":
                    any_error = True

    logger.info("Processed %d processing policies across nodes", len(rows))
    return rows, any_error

def _process_policy_action(
    client: DirectorClient,
    pool_uuid: str,
    logpoint_id: str,
    dry_run: bool,
    policy: Dict[str, Any],
    existing_policy: Dict[str, Any] = None
) -> Tuple[str, str, str]:
    """Determine and execute action for a single processing policy.

    Args:
        client: DirectorClient instance.
        pool_uuid: Tenant pool UUID.
        logpoint_id: SIEM identifier.
        dry_run: Simulate mode.
        policy: Policy data with name, norm_policy, enrich_policy, routing_policy.
        existing_policy: Existing policy if found.

    Returns:
        Tuple of (action, result, error).
    """
    if dry_run:
        logger.info("DRY RUN: Would process %s on %s (CREATE/UPDATE/NOOP/SKIP)", policy["policy_name"], logpoint_id)
        return "DRY_RUN", "N/A", ""

    if not existing_policy:
        # CREATE
        logger.info("Creating processing policy %s on %s", policy["policy_name"], logpoint_id)
        try:
            result = client.create_processing_policy(pool_uuid, logpoint_id, policy)
            if result.get("status") == "success":
                return "CREATE", "Success", ""
            else:
                error = result.get("error", json.dumps(result))
                logger.debug(f"Defective payload: {policy}")
                logger.error("CREATE failed for %s on %s: Response error: %s, Full response: %s", policy["policy_name"], logpoint_id, error, result)
                return "CREATE", "Fail", error
        except Exception as e:
            logger.debug(f"Defective payload: {policy}")
            logger.error("Exception during CREATE %s on %s: %s", policy["policy_name"], logpoint_id, str(e))
            return "CREATE", "Fail", str(e)

    # Compare if existing, ignoring active
    existing_norm = existing_policy.get("norm_policy", "")
    existing_enrich = existing_policy.get("enrich_policy", "")
    existing_routing = existing_policy.get("routing_policy", "")

    if (existing_norm == policy["norm_policy"] and
        existing_enrich == policy["enrich_policy"] and
        existing_routing == policy["routing_policy"]):
        logger.info("NOOP: Processing policy %s on %s unchanged", policy["policy_name"], logpoint_id)
        return "NOOP", "N/A", ""
    else:
        # UPDATE
        policy_id = existing_policy.get("id")
        logger.info("Updating processing policy %s (ID: %s) on %s", policy["policy_name"], policy_id, logpoint_id)
        try:
            result = client.update_processing_policy(pool_uuid, logpoint_id, policy_id, policy)
            if result.get("status") == "success":
                return "UPDATE", "Success", ""
            else:
                error = result.get("error", json.dumps(result))
                logger.error("UPDATE failed for %s on %s: Response error: %s, Full response: %s", policy["policy_name"], logpoint_id, error, result)
                return "UPDATE", "Fail", error
        except Exception as e:
            logger.error("Exception during UPDATE %s on %s: %s", policy["policy_name"], logpoint_id, str(e))
            return "UPDATE", "Fail", str(e)