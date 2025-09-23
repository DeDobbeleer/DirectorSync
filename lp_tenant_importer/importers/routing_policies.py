"""Importer for routing policies from Excel to Logpoint Director API."""
import logging
import re
from typing import Dict, List, Tuple

import pandas as pd

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)

def normalize_repo_name(repo_name: str, tenant: str) -> str:
    """Normalize repository name by removing tenant and rejoining parts with '-'.

    Handles mixed separators ('-' or '_') and removes tenant name (case-insensitive).

    Args:
        repo_name: Original repository name (e.g., 'Repo-core-system', 'Repo_core_system').
        tenant: Tenant name to remove (e.g., 'core').

    Returns:
        Normalized repository name (e.g., 'Repo-system').
    """
    if not repo_name or repo_name.lower() in ('nan', '', 'none'):
        return ''
    # Split on both '-' and '_'
    parts = re.split(r'[-_]', repo_name)
    tenant_lower = tenant.lower()
    # Remove tenant (case-insensitive)
    parts = [part for part in parts if part.lower() != tenant_lower]
    # Join remaining parts with '-'
    return '-'.join(parts) if parts else ''

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

    Verifies that all referenced repos (catch_all and routing_criteria.repo) exist after
    normalizing names (removing tenant). Skips policies if any repo is missing to avoid DB inconsistencies.

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

        for index, row in df.iterrows():
            # Build policy dictionary with normalized repo names
            policy = {
                "policy_name": str(row["cleaned_policy_name"]).strip(),
                "active": str(row["active"]).lower() == "true",
                "catch_all": normalize_repo_name(str(row["catch_all"]).strip(), tenant),
                "routing_criteria": [
                    {
                        "type": str(row["rule_type"]).strip(),
                        "key": str(row["key"]).strip(),
                        "value": str(row["value"]).strip(),
                        "repo": normalize_repo_name(str(row["repo"]).strip(), tenant),
                        "drop": str(row["drop"]).strip(),  # "store" or "drop"
                    }
                ],
            }
            if not policy["policy_name"]:
                logger.warning("Skipping row %d with empty policy_name", index + 2)
                rows.append(
                    {
                        "siem": "",
                        "node": "",
                        "name": "N/A",
                        "result": "Fail",
                        "action": "NONE",
                        "error": "Empty policy_name",
                    }
                )
                any_error = True
                continue

            logger.debug("Processing policy: %s", policy["policy_name"])

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
                        repos_to_check = [
                            policy["catch_all"],
                            policy["routing_criteria"][0]["repo"],
                            *[criteria["repo"] for criteria in policy["routing_criteria"]]
                        ]
                        repos_to_check = [r for r in repos_to_check if r]  # Remove empty or invalid repos
                        if not repos_to_check:
                            logger.warning(
                                "Skipping policy %s on %s (%s): no valid repos to check",
                                policy["policy_name"],
                                node_name,
                                siem_id,
                            )
                            rows.append(
                                {
                                    "siem": siem_id,
                                    "node": node_name,
                                    "name": policy["policy_name"],
                                    "result": "MISSING_REPO",
                                    "action": "SKIP",
                                    "error": "No valid repos provided",
                                }
                            )
                            continue

                        missing_repos = client.check_repos(pool_uuid, siem_id, repos_to_check)
                        if missing_repos:
                            logger.warning(
                                "Skipping policy %s on %s (%s): missing repos %s",
                                policy["policy_name"],
                                node_name,
                                siem_id,
                                missing_repos,
                            )
                            rows.append(
                                {
                                    "siem": siem_id,
                                    "node": node_name,
                                    "name": policy["policy_name"],
                                    "result": "MISSING_REPO",
                                    "action": "SKIP",
                                    "error": f"Missing repos: {missing_repos}",
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
                        result = "N/A"
                        error = None

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
                                        if job_status.get("success"):
                                            result = "Success"
                                        else:
                                            result = "Fail"
                                            error = job_status.get("error", "Unknown error")
                                            any_error = True
                                    else:
                                        result = "Fail"
                                        error = "Invalid response from API"
                                        any_error = True
                            else:
                                action = "SKIP"
                                result = "Success"
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
                                    if job_status.get("success"):
                                        result = "Success"
                                    else:
                                        result = "Fail"
                                        error = job_status.get("error", "Unknown error")
                                        any_error = True
                                else:
                                    result = "Fail"
                                    error = "Invalid response from API"
                                    any_error = True

                        rows.append(
                            {
                                "siem": siem_id,
                                "node": node_name,
                                "name": policy["policy_name"],
                                "result": result,
                                "action": action,
                                "error": error,
                            }
                        )
                        logger.info(
                            "Policy %s on %s (%s): %s -> %s",
                            policy["policy_name"],
                            node_name,
                            siem_id,
                            action,
                            result,
                        )
                    except Exception as e:
                        logger.error(
                            "Failed to process policy %s on %s (%s): %s",
                            policy["policy_name"],
                            node_name,
                            siem_id,
                            str(e),
                        )
                        rows.append(
                            {
                                "siem": siem_id,
                                "node": node_name,
                                "name": policy["policy_name"],
                                "result": "Fail",
                                "action": "NONE",
                                "error": str(e),
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
                    "action": "NO_DATA",
                    "error": "No policies processed",
                }
            )

    except ValueError as ve:
        logger.error("Invalid Excel file: %s", str(ve))
        raise
    except Exception as e:
        logger.error("Error importing routing policies: %s", str(e))
        raise

    return rows, any_error


def _needs_update(existing: Dict[str, any], new: Dict[str, any]) -> bool:
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