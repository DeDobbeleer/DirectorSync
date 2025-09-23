"""Importer for routing policies from Excel to Logpoint Director API."""
import json
import logging
import re
from typing import Dict, List, Tuple, Any

import pandas as pd

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)

# def normalize_repo_name(repo_name: str, tenant: str) -> str:
#     """Normalize repository name by removing tenant and rejoining parts with '_'.

#     Handles mixed separators ('-' or '_') and removes tenant name (case-insensitive).

#     Args:
#         repo_name: Original repository name (e.g., 'Repo-core-system', 'Repo_core_system').
#         tenant: Tenant name to remove (e.g., 'core').

#     Returns:
#         Normalized repository name (e.g., 'Repo_system').
#     """
#     if not repo_name or repo_name.lower() in ('nan', '', 'none'):
#         return ''
#     # Split on both '-' and '_'
#     parts = re.split(r'[-_]', repo_name)
#     tenant_lower = tenant.lower()
#     # Remove tenant (case-insensitive)
#     parts = [part for part in parts if part.lower() != tenant_lower]
#     # Join remaining parts with '_'
#     return '_'.join(parts) if parts else ''


def import_routing_policies_for_nodes(df, nodes, tenant_config, http_client):
    logging.debug("Found columns: %s", list(df.columns))
    logging.debug("Found %d routing policies in XLSX", len(df))
    target_nodes = [n.name for n in nodes['backends']]  # Ex. ['lb-backend01', 'lb-backend02']
    logging.debug("Target nodes for RP: %s", ", ".join(target_nodes))

    for policy_name in df['cleaned_policy_name'].unique():  # Par politique unique
        policy_rows = df[df['cleaned_policy_name'] == policy_name]
        active = bool(policy_rows['active'].iloc[0])
        catch_all = policy_rows['catch_all'].iloc[0]
        routing_criteria = []

        for index, row in policy_rows.iterrows():
            if pd.notna(row['rule_type']) and pd.notna(row['key']) and pd.notna(row['value']) and pd.notna(row['repo']):
                criterion = {
                    "type": row['rule_type'],
                    "key": row['key'],
                    "value": row['value'],
                    "repo": row['repo'],
                    "drop": row['drop'] if pd.notna(row['drop']) else "store"
                }
                routing_criteria.append(criterion)
            else:
                logging.debug("No criteria for this row in policy %s", policy_name)

        logging.debug("Routing criteria for %s: %s", policy_name, routing_criteria)
        data = {"data": {"policy_name": policy_name, "active": active, "catch_all": catch_all, "routing_criteria": routing_criteria}}
        # Applique aux nœuds (votre logique existante ici)
        for node in nodes['backends']:
            # Vérification des dépôts et mise à jour
            existing_repos = http_client.get_existing_repos(tenant_config['pool_uuid'], node.id)
            required_repos = [crit["repo"] for crit in routing_criteria] + [catch_all] if catch_all else []
            missing_repos = [r for r in required_repos if r not in [repo["name"] for repo in existing_repos]]
            if missing_repos:
                logging.warning("Skipping policy %s on %s (%s): missing repos %s", policy_name, node.name, node.id, missing_repos)
                continue
            # Logique de mise à jour (ex. http_client.update_routing_policy)
            logging.info("Policy %s on %s (%s): NOOP -> (N/A)", policy_name, node.name, node.id)

    return  # Ajuste selon ton retour


def import_routing_policies_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List[Node]],
    xlsx_path: str,
    dry_run: bool,
    targets: List[str],
    tenant: str = 'core'
) -> Tuple[List[Dict], bool]:
    """Import or update routing policies for specified nodes.

    Groups rows by cleaned_policy_name to handle multi-line policies with multiple criteria.
    Verifies that all referenced repos (catch_all and routing_criteria.repo) exist after
    normalizing names (removing tenant). Uses NOOP for no changes, SKIP for anomalies.

    Args:
        client: DirectorClient instance for API interactions.
        pool_uuid: Tenant pool UUID.
        nodes: Dictionary of node types and their instances (e.g., backends, all_in_one).
        xlsx_path: Path to the Excel configuration file.
        dry_run: If True, simulate actions without API calls.
        targets: List of target node roles (e.g., ['backends', 'all_in_one']).
        tenant: Tenant name for normalizing repo names (default: 'core').

    Returns:
        Tuple of (list of result dictionaries, flag indicating if any error occurred).

    Raises:
        ValueError: If Excel file is invalid or missing required columns.
    """
    rows = []
    any_error = False

    try:
        # Load RoutingPolicy sheet from Excel
        df = pd.read_excel(xlsx_path, sheet_name="RoutingPolicy", skiprows=0)
        required_columns = [
            "cleaned_policy_name",
            "active",
            "catch_all",
            "rule_type",
            "key",
            "value",
            "repo",
            "drop",
        ]
        if not all(col in df.columns for col in required_columns):
            missing_cols = [col for col in required_columns if col not in df.columns]
            logger.error("Missing required columns in RoutingPolicy sheet: %s", missing_cols)
            raise ValueError(f"Missing required columns: {missing_cols}")

        logger.debug("Found columns: %s", df.columns.tolist())
        logger.debug("Found %d routing policies in XLSX", len(df))
        logger.debug("Target nodes for RP: %s", ", ".join([node.name for node_type in targets for node in nodes.get(node_type, []) if nodes.get(node_type)]))

        # Group by cleaned_policy_name to handle multi-line policies
        grouped = df.groupby('cleaned_policy_name')

        for policy_name, group in grouped:
            # Validate consistency in common fields
            if len(group['active'].unique()) > 1 or len(group['catch_all'].unique()) > 1:
                logger.error("Inconsistent common fields for policy %s", policy_name)
                any_error = True
                continue

            active = str(group['active'].iloc[0]).lower() == "true"
            catch_all = normalize_repo_name(str(group['catch_all'].iloc[0]).strip(), tenant)
            if not catch_all:
                logger.warning("No catch_all for policy %s, skipping", policy_name)
                for node_type in targets:
                    if node_type in nodes and nodes[node_type]:
                        for node in nodes[node_type]:
                            rows.append({
                                "siem": node.id,
                                "node": node.name,
                                "name": policy_name,
                                "result": "NO_DATA",
                                "action": "SKIP",
                                "error": "No catch_all defined",
                            })
                continue

            # Build routing_criteria, handling multi-line policies
            routing_criteria = []
            repos_to_check = set()

          
            for _, crit_row in group.iterrows():
                if str(crit_row['rule_type']).strip().lower() not in ('nan', '', 'none'):
                    crit_repo = normalize_repo_name(str(crit_row['repo']).strip(), tenant)
                    if not crit_repo:
                        logger.warning("No repo for criteria in policy %s, skipping this criterion", policy_name)
                        continue
                    criteria = {
                        "type": str(crit_row['rule_type']).strip(),
                        "key": str(crit_row['key']).strip(),
                        "value": str(crit_row['value']).strip(),
                        "repo": crit_repo,
                        "drop": str(crit_row['drop']).strip(),
                    }
                    routing_criteria.append(criteria)
                    repos_to_check.add(crit_repo)
                else:
                    logger.debug("No criteria for this row in policy %s", policy_name)

            repos_to_check.add(catch_all)
            logger.debug("Normalized repos for %s: %s", policy_name, list(repos_to_check))

            policy = {
                "policy_name": policy_name,
                "active": active,
                "catch_all": catch_all,
                "routing_criteria": routing_criteria,
            }

            # Process for each target role (backends, all_in_one only)
            for node_type in targets:
                if node_type not in nodes or not nodes[node_type]:
                    logger.warning("No nodes available for target role %s", node_type)
                    continue
                for node in nodes[node_type]:
                    siem_id = node.id
                    node_name = node.name

                    try:
                        # Verify all referenced repos exist
                        repos_to_check_list = list(repos_to_check)
                        missing_repos = client.check_repos(pool_uuid, siem_id, repos_to_check_list)
                        if missing_repos:
                            logger.warning(
                                "Skipping policy %s on %s (%s): missing repos %s",
                                policy_name,
                                node_name,
                                siem_id,
                                missing_repos,
                            )
                            rows.append(
                                {
                                    "siem": siem_id,
                                    "node": node_name,
                                    "name": policy_name,
                                    "result": "MISSING_REPO",
                                    "action": "SKIP",
                                    "error": f"Missing repos: {missing_repos}",
                                    "job_status": None,
                                }
                            )
                            continue

                        # Check if policy exists
                        existing_policies = client.get_existing_routing_policies(pool_uuid, siem_id)
                        existing_policy = next(
                            (p for p in existing_policies if p["policy_name"] == policy["policy_name"]),
                            None,
                        )
                        action = "NOOP"
                        result = "(N/A)"
                        error = None
                        job_status = None

                        if existing_policy:
                            # Check if update is needed
                            if _needs_update(existing_policy, policy):
                                action = "UPDATE"
                                if not dry_run:
                                    response = client.update_routing_policy(
                                        pool_uuid, siem_id, existing_policy["id"], policy
                                    )
                                    if "monitorapi" in response:
                                        job_status = client.monitor_job(response["monitorapi"])
                                        logger.debug("Monitor job response for %s: %s", policy_name, job_status)
                                        if job_status.get("success"):
                                            result = "Success"
                                        else:
                                            result = "Fail"
                                            error = job_status.get("error", "Unknown error")
                                            any_error = True
                                            job_status = json.dumps(job_status) if job_status else None
                                    else:
                                        result = "Success" if response.get("status") == "Success" else "Fail"
                                        error = "Invalid response from API" if result == "Fail" else None
                                        any_error = result == "Fail"
                            else:
                                action = "NOOP"
                                result = "(N/A)"
                        else:
                            # Create new policy
                            action = "CREATE"
                            if not dry_run:
                                response = client.create_routing_policy(pool_uuid, siem_id, policy)
                                if response.get("status") == "noop":
                                    result = "(N/A)"
                                    action = "NOOP"
                                elif "monitorapi" in response:
                                    job_status = client.monitor_job(response["monitorapi"])
                                    logger.debug("Monitor job response for %s: %s", policy_name, job_status)
                                    if job_status.get("success"):
                                        result = "Success"
                                    else:
                                        result = "Fail"
                                        error = job_status.get("error", "Unknown error")
                                        any_error = True
                                        job_status = json.dumps(job_status) if job_status else None
                                else:
                                    result = "Success" if response.get("status") == "Success" else "Fail"
                                    error = "Invalid response from API" if result == "Fail" else None
                                    any_error = result == "Fail"

                        rows.append(
                            {
                                "siem": siem_id,
                                "node": node_name,
                                "name": policy_name,
                                "result": result,
                                "action": action,
                                "error": error,
                                "job_status": job_status,
                            }
                        )
                        logger.info(
                            "Policy %s on %s (%s): %s -> %s",
                            policy_name,
                            node_name,
                            siem_id,
                            action,
                            result,
                        )
                    except Exception as e:
                        logger.error(
                            "Failed to process policy %s on %s (%s): %s",
                            policy_name,
                            node_name,
                            siem_id,
                            str(e),
                        )
                        rows.append(
                            {
                                "siem": siem_id,
                                "node": node_name,
                                "name": policy_name,
                                "result": "Fail",
                                "action": "NONE",
                                "error": str(e),
                                "job_status": None,
                            }
                        )
                        any_error = True

        if not rows:
            logger.warning("No routing policies processed for %s", xlsx_path)
            rows.append(
                {
                    "siem": "",
                    "node": "",
                    "name": "N/A",
                    "result": "SKIPPED",
                    "action": "SKIP",
                    "error": "No policies processed",
                    "job_status": None,
                }
            )

    except ValueError as ve:
        logger.error("Invalid Excel file: %s", str(ve))
        raise
    except Exception as e:
        logger.error("Error importing routing policies: %s", str(e))
        raise

    return rows, any_error


def _needs_update(existing: Dict[str, Any], new: Dict[str, Any]) -> bool:
    """Check if an existing policy needs updating by comparing key fields.

    Args:
        existing: Existing policy data from API.
        new: New policy data from Excel.

    Returns:
        True if any field differs, False otherwise.
    """
    fields_to_compare = ["policy_name", "active", "catch_all"]
    for field in fields_to_compare:
        if existing.get(field) != new.get(field):
            return True

    # Compare routing_criteria
    existing_criteria = existing.get("routing_criteria", [])
    new_criteria = new.get("routing_criteria", [])
    if len(existing_criteria) != len(new_criteria):
        return True
    for existing_crit, new_crit in zip(existing_criteria, new_criteria):
        if existing_crit != new_crit:
            return True

    return False