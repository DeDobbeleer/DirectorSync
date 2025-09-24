import logging
import pandas as pd
from typing import Dict, List, Any, Tuple
import json

from core.http import DirectorClient
from core.nodes import Node

logger = logging.getLogger(__name__)

def import_normalization_policies_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List[Node]],
    xlsx_path: str,
    dry_run: bool,
    targets: List[str],
) -> Tuple[List[Dict[str, Any]], bool]:
    """Import normalization policies for the specified nodes.

    Reads the 'NormalizationPolicy' sheet from the XLSX file, processes each policy,
    verifies availability of normalization packages and compiled normalizers via API,
    and performs CREATE/UPDATE/NOOP/SKIP actions based on existence and differences.

    Args:
        client: DirectorClient instance for API calls.
        pool_uuid: Tenant pool UUID.
        nodes: Dictionary of node types and Node instances.
        xlsx_path: Path to the XLSX configuration file.
        dry_run: If True, simulate actions without API calls.
        targets: List of target node roles (e.g., ['backends', 'all_in_one']).

    Returns:
        Tuple of (list of result rows, any_error flag).
        Rows include: siem, node, name, packages_count, compiled_count, action, result, error.
    """
    rows = []
    any_error = False

    # Read and process XLSX sheet
    try:
        df = pd.read_excel(xlsx_path, sheet_name="NormalizationPolicy", skiprows=0)
        logger.debug("Loaded NormalizationPolicy sheet with %d rows", len(df))
    except Exception as e:
        logger.error("Failed to load NormalizationPolicy sheet: %s", e)
        return [], True

    # Fetch available packages and compiled normalizers once per node
    for target_type in targets:
        for node in nodes.get(target_type, []):
            logpoint_id = node.id
            logger.debug("Fetching available packages/normalizers for node %s (%s)", node.name, logpoint_id)

            available_packages = {}  # name -> id mapping
            available_compiled = set()  # set of names

            try:
                packages_resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/NormalizationPackage")
                packages_resp.raise_for_status()
                packages_data = packages_resp.json()
                if isinstance(packages_data, list):
                    available_packages = {pkg.get("name", "").strip(): pkg.get("id", "") for pkg in packages_data if pkg.get("id") and pkg.get("name")}
                    logger.debug("Available packages: %d", len(available_packages))
                else:
                    logger.warning("Unexpected response for packages: %s", packages_data)
            except Exception as e:
                logger.error("Failed to fetch available packages for %s: %s", logpoint_id, e)
                any_error = True
                continue

            try:
                compiled_resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/NormalizationPackage/CompiledNormalizers")
                compiled_resp.raise_for_status()
                compiled_data = compiled_resp.json()
                if isinstance(compiled_data, list):
                    available_compiled = {c.get("name", "").strip() for c in compiled_data if c.get("name")}
                    logger.debug("Available compiled normalizers: %d", len(available_compiled))
                else:
                    logger.warning("Unexpected response for compiled normalizers: %s", compiled_data)
            except Exception as e:
                logger.error("Failed to fetch available compiled normalizers for %s: %s", logpoint_id, e)
                any_error = True
                continue

            # Process each policy row
            for _, row in df.iterrows():
                policy_name = row.get("policy_name", "").strip()
                if not policy_name:
                    logger.warning("Skipping row with empty policy_name")
                    continue

                # Parse multi-values, handle 'nan' as empty
                norm_packages_str = str(row.get("normalization_packages", "")).strip().replace("nan", "").strip()
                compiled_str = str(row.get("compiled_normalizer", "")).strip().replace("nan", "").strip()
                norm_packages = [p.strip() for p in norm_packages_str.split("|") if p.strip()] if norm_packages_str else []
                compiled_normalizers = [c.strip() for c in compiled_str.split("|") if c.strip()] if compiled_str else []

                packages_count = len(norm_packages)
                compiled_count = len(compiled_normalizers)

                # Validation: At least one field non-empty
                if packages_count == 0 and compiled_count == 0:
                    row_result = {
                        "siem": logpoint_id,
                        "node": node.name,
                        "name": policy_name,
                        "packages_count": packages_count,
                        "compiled_count": compiled_count,
                        "action": "SKIP",
                        "result": "N/A",
                        "error": "Both fields empty"
                    }
                    rows.append(row_result)
                    logger.warning("Skipping %s: Both fields empty", policy_name)
                    continue

                # Verify availability
                missing_packages = [p for p in norm_packages if p not in available_packages]
                missing_compiled = [c for c in compiled_normalizers if c not in available_compiled]
                if missing_packages or missing_compiled:
                    error_msg = f"Missing packages: {', '.join(missing_packages)}; Missing compiled: {', '.join(missing_compiled)}"
                    row_result = {
                        "siem": logpoint_id,
                        "node": node.name,
                        "name": policy_name,
                        "packages_count": packages_count,
                        "compiled_count": compiled_count,
                        "action": "SKIP",
                        "result": "N/A",
                        "error": error_msg
                    }
                    rows.append(row_result)
                    logger.warning("Skipping %s: %s", policy_name, error_msg)
                    continue

                # Map names to IDs for packages
                package_ids = [available_packages[p] for p in norm_packages]

                policy_data = {
                    "name": policy_name,
                    "normalization_packages": package_ids,
                    "compiled_normalizer": compiled_normalizers
                }

                logger.debug("Processing policy %s: packages=%s (IDs=%s), compiled=%s", policy_name, norm_packages, package_ids, compiled_normalizers)

                # Check existence and decide action
                action, result, error = _process_policy_action(client, pool_uuid, logpoint_id, dry_run, policy_data)
                row_result = {
                    "siem": logpoint_id,
                    "node": node.name,
                    "name": policy_name,
                    "packages_count": packages_count,
                    "compiled_count": compiled_count,
                    "action": action,
                    "result": result,
                    "error": error
                }
                rows.append(row_result)

                if result == "Fail":
                    any_error = True

    logger.info("Processed %d normalization policies across nodes", len(rows))
    return rows, any_error

def _process_policy_action(
    client: DirectorClient,
    pool_uuid: str,
    logpoint_id: str,
    dry_run: bool,
    policy: Dict[str, Any]
) -> Tuple[str, str, str]:
    """Determine and execute action for a single policy.

    Args:
        client: DirectorClient instance.
        pool_uuid: Tenant pool UUID.
        logpoint_id: SIEM identifier.
        dry_run: Simulate mode.
        policy: Policy data with name, normalization_packages (IDs), compiled_normalizer (names).

    Returns:
        Tuple of (action, result, error).
    """
    if dry_run:
        logger.info("DRY RUN: Would process %s (CREATE/UPDATE/NOOP/SKIP)", policy["name"])
        return "DRY_RUN", "N/A", ""

    # Fetch existing policies
    try:
        resp = client.get(f"configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy")
        resp.raise_for_status()
        existing_policies = resp.json()
        if not isinstance(existing_policies, list):
            existing_policies = []
        logger.debug("Fetched existing normalization policies: %s", [p.get("name") for p in existing_policies])
    except Exception as e:
        logger.error("Failed to fetch existing policies: %s", e)
        return "SKIP", "N/A", "Failed to fetch existing policies"

    # Find existing by name
    existing = next((p for p in existing_policies if p.get("name") == policy["name"]), None)
    if not existing:
        # CREATE
        logger.info("Creating normalization policy %s", policy["name"])
        try:
            api_result = client.create_normalization_policy(pool_uuid, logpoint_id, policy)
            if api_result.get("status") == "success":
                return "CREATE", "Success", ""
            else:
                error = api_result.get("error", json.dumps(api_result))
                logger.error("CREATE failed for %s: %s", policy["name"], error)
                return "CREATE", "Fail", error
        except Exception as e:
            logger.error("Exception during CREATE %s: %s", policy["name"], e)
            return "CREATE", "Fail", str(e)

    # Existing: Compare
    existing_packages = set(existing.get("normalization_packages", []))  # list of IDs
    existing_compiled = existing.get("compiled_normalizer", [])
    if isinstance(existing_compiled, str):
        existing_compiled = set([c.strip() for c in existing_compiled.split(",") if c.strip()])
    else:  # Assume list
        existing_compiled = set(str(c).strip() for c in existing_compiled if c)

    current_packages = set(policy["normalization_packages"])
    current_compiled = set(policy["compiled_normalizer"])

    logger.debug("Comparing: existing_packages=%s, current_packages=%s, existing_compiled=%s, current_compiled=%s",
                 existing_packages, current_packages, existing_compiled, current_compiled)

    if existing_packages == current_packages and existing_compiled == current_compiled:
        logger.info("NOOP: Normalization policy %s unchanged", policy["name"])
        return "NOOP", "N/A", ""

    # UPDATE
    policy_id = existing.get("id")
    logger.info("Updating normalization policy %s (ID: %s)", policy["name"], policy_id)
    try:
        api_result = client.update_normalization_policy(pool_uuid, logpoint_id, policy_id, policy)
        if api_result.get("status") == "success":
            return "UPDATE", "Success", ""
        else:
            error = api_result.get("error", json.dumps(api_result))
            logger.error("UPDATE failed for %s: %s", policy["name"], error)
            return "UPDATE", "Fail", error
    except Exception as e:
        logger.error("Exception during UPDATE %s: %s", policy["name"], e)
        return "UPDATE", "Fail", str(e)