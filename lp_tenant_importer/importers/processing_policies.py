import logging
import pandas as pd
from typing import Dict, List, Any, Tuple
import json

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
    maps source IDs to names, fetches target IDs via API, and performs CREATE/UPDATE/NOOP/SKIP actions.

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

    # Load all relevant sheets
    try:
        pp_df = pd.read_excel(xlsx_path, sheet_name="ProcessingPolicy", skiprows=0)
        ep_df = pd.read_excel(xlsx_path, sheet_name="EnrichmentPolicy", skiprows=0)
        rp_df = pd.read_excel(xlsx_path, sheet_name="RoutingPolicy", skiprows=0)
        logger.debug("Loaded ProcessingPolicy, EnrichmentPolicy, and RoutingPolicy sheets")
        logger.debug("EnrichmentPolicy columns: %s", list(ep_df.columns))
        logger.debug("RoutingPolicy columns: %s", list(rp_df.columns))
    except Exception as e:
        logger.error("Failed to load sheets: %s", e)
        return [], True

    # Detect column names dynamically
    ep_id_col = next((col for col in ['policy_id', 'id'] if col in ep_df.columns), None)
    ep_name_col = next((col for col in ['policy_name', 'name'] if col in ep_df.columns), None)
    rp_id_col = next((col for col in ['policy_id', 'id'] if col in rp_df.columns), None)
    rp_name_col = next((col for col in ['cleaned_policy_name', 'name'] if col in rp_df.columns), None)

    if not ep_id_col or not ep_name_col:
        logger.error("Cannot proceed: no valid ID or name column in EnrichmentPolicy (found columns: %s)", list(ep_df.columns))
        return [], True
    if not rp_id_col or not rp_name_col:
        logger.error("Cannot proceed: no valid ID or name column in RoutingPolicy (found columns: %s)", list(rp_df.columns))
        return [], True

    # Build source ID to name mappings
    ep_mapping = dict(zip(ep_df[ep_id_col], ep_df[ep_name_col]))
    rp_mapping = dict(zip(rp_df[rp_id_col], rp_df[rp_name_col]))

    # Process per node
    for target_type in targets:
        for node in nodes.get(target_type, []):
            logpoint_id = node.id
            logger.debug("Processing policies for node %s (%s)", node.name, logpoint_id)

            # Fetch existing policies
            existing_policies = {}
            try:
                resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy")
                resp.raise_for_status()
                policies_data = resp.json()
                if isinstance(policies_data, list):
                    existing_policies = {p.get("name", "").strip(): p for p in policies_data if p.get("name")}
                    logger.debug("Existing policies: %d", len(existing_policies))
                else:
                    logger.warning("Unexpected response for policies: %s", policies_data)
            except Exception as e:
                logger.error("Failed to fetch existing policies for %s: %s", logpoint_id, e)
                any_error = True
                continue

            # Fetch dependencies for the target node
            norm_policies = set()
            enrich_policies = {}
            routing_policies = {}
            try:
                norm_resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy")
                norm_resp.raise_for_status()
                norm_policies = {p.get("name") for p in norm_resp.json() if p.get("name")}
                enrich_resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy")
                enrich_resp.raise_for_status()
                enrich_policies = {p.get("name"): p.get("id") for p in enrich_resp.json() if p.get("name") and p.get("id")}
                routing_resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/RoutingPolicy")
                routing_resp.raise_for_status()
                routing_policies = {p.get("name"): p.get("id") for p in routing_resp.json() if p.get("name") and p.get("id")}
            except Exception as e:
                logger.error("Failed to fetch dependencies for %s: %s", logpoint_id, e)
                any_error = True
                continue

            # Process each processing policy row
            for _, row in pp_df.iterrows():
                original_name = row.get("original_policy_name", "").strip()
                cleaned_name = row.get("cleaned_policy_name", original_name).strip()
                policy_name = cleaned_name or original_name
                if not policy_name:
                    logger.warning("Skipping row with empty policy_name")
                    continue

                active = bool(row.get("active", True))  # Default True
                norm_policy = row.get("norm_policy", "").strip().replace("nan", "")
                enrich_policy_src_id = row.get("enrich_policy", "").strip().replace("nan", "")
                routing_policy_src_id = row.get("routing_policy", "").strip().replace("nan", "")

                # Map source IDs to names
                enrich_policy_name = ep_mapping.get(enrich_policy_src_id, "None") if enrich_policy_src_id else "None"
                routing_policy_name = rp_mapping.get(routing_policy_src_id, "None") if routing_policy_src_id else "None"

                # Map names to target IDs
                enrich_policy = enrich_policies.get(enrich_policy_name, "None") if enrich_policy_name != "None" else "None"
                routing_policy = routing_policies.get(routing_policy_name, "None") if routing_policy_name != "None" else "None"

                # Validation: Critical fields
                if not norm_policy:
                    row_result = {
                        "siem": logpoint_id,
                        "node": node.name,
                        "name": policy_name,
                        "norm_policy": norm_policy,
                        "enrich_policy": enrich_policy,
                        "routing_policy": routing_policy,
                        "action": "SKIP",
                        "result": "N/A",
                        "error": "Missing norm_policy"
                    }
                    rows.append(row_result)
                    logger.warning("Skipping %s: %s", policy_name, row_result["error"])
                    continue
                if norm_policy not in norm_policies:
                    row_result = {
                        "siem": logpoint_id,
                        "node": node.name,
                        "name": policy_name,
                        "norm_policy": norm_policy,
                        "enrich_policy": enrich_policy,
                        "routing_policy": routing_policy,
                        "action": "SKIP",
                        "result": "N/A",
                        "error": "Invalid norm_policy"
                    }
                    rows.append(row_result)
                    logger.warning("Skipping %s: %s", policy_name, row_result["error"])
                    continue
                if enrich_policy_name and enrich_policy == "None":
                    logger.warning("Invalid enrich_policy mapping for %s: %s", policy_name, enrich_policy_name)
                if routing_policy_name and routing_policy == "None":
                    logger.warning("Invalid routing_policy mapping for %s: %s", policy_name, routing_policy_name)

                policy_data = {
                    "name": policy_name,
                    "active": active,
                    "norm_policy": norm_policy,
                    "enrich_policy": enrich_policy,
                    "routing_policy": routing_policy
                }

                logger.debug("Processing policy %s: active=%s, norm_policy=%s, enrich_policy=%s, routing_policy=%s",
                             policy_name, active, norm_policy, enrich_policy, routing_policy)

                # Check existence and decide action
                action, result, error = _process_policy_action(client, pool_uuid, logpoint_id, dry_run, policy_data, existing_policies.get(policy_name))
                row_result = {
                    "siem": logpoint_id,
                    "node": node.name,
                    "name": policy_name,
                    "norm_policy": norm_policy,
                    "enrich_policy": enrich_policy,
                    "routing_policy": routing_policy,
                    "action": action,
                    "result": result,
                    "error": error
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
        policy: Policy data with name, active, norm_policy, enrich_policy, routing_policy.
        existing_policy: Existing policy if found.

    Returns:
        Tuple of (action, result, error).
    """
    if dry_run:
        logger.info("DRY RUN: Would process %s (CREATE/UPDATE/NOOP/SKIP)", policy["name"])
        return "DRY_RUN", "N/A", ""

    if not existing_policy:
        # CREATE
        logger.info("Creating processing policy %s", policy["name"])
        try:
            api_result = client.create_processing_policy(pool_uuid, logpoint_id, policy)
            if api_result.get("status") == "success":
                return "CREATE", "Success", ""
            else:
                error = api_result.get("error", json.dumps(api_result))
                logger.error("CREATE failed for %s: %s", policy["name"], error)
                return "CREATE", "Fail", error
        except Exception as e:
            logger.error("Exception during CREATE %s: %s", policy["name"], e)
            return "CREATE", "Fail", str(e)

    # Compare if existing
    existing_active = existing_policy.get("active", False)
    existing_norm = existing_policy.get("norm_policy", "")
    existing_enrich = existing_policy.get("enrich_policy", "")
    existing_routing = existing_policy.get("routing_policy", "")

    if (existing_active == policy["active"] and
        existing_norm == policy["norm_policy"] and
        existing_enrich == policy["enrich_policy"] and
        existing_routing == policy["routing_policy"]):
        logger.info("NOOP: Processing policy %s unchanged", policy["name"])
        return "NOOP", "N/A", ""

    # UPDATE
    policy_id = existing_policy.get("id")
    logger.info("Updating processing policy %s (ID: %s)", policy["name"], policy_id)
    try:
        api_result = client.update_processing_policy(pool_uuid, logpoint_id, policy_id, policy)
        if api_result.get("status") == "success":
            return "UPDATE", "Success", ""
        else:
            error = api_result.get("error", json.dumps(api_result))
            logger.error("UPDATE failed for %s: %s", policy["name"], error)
            return "UPDATE", "Fail", error
    except Exception as e:
        logger.error("Exception during UPDATE %s: %s", policy["name"], e)
        return "UPDATE", "Fail", str(e)