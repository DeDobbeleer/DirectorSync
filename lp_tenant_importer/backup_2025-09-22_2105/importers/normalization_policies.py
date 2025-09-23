import logging
import pandas as pd
from typing import List, Dict, Any, Tuple
from pathlib import Path
from core.http import DirectorClient

logger = logging.getLogger(__name__)

def import_normalization_policies_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List],
    xlsx_path: str,
    dry_run: bool,
    targets: List[str],
) -> Tuple[List[Dict], bool]:
    """Import normalization policies from XLSX to specified SIEM nodes.

    Args:
        client: DirectorClient instance for API calls.
        pool_uuid: Tenant pool UUID.
        nodes: Dictionary of SIEM nodes by role (backends, all_in_one).
        xlsx_path: Path to XLSX file.
        dry_run: If True, simulate without API calls.
        targets: List of target roles (e.g., ['backends', 'all_in_one']).

    Returns:
        Tuple of (results list, any_error boolean).

    Raises:
        FileNotFoundError: If XLSX file is missing.
        ValueError: If XLSX parsing fails or sheet is invalid.
    """
    results = []
    any_error = False

    # Validate XLSX file
    xlsx_path = Path(xlsx_path)
    if not xlsx_path.exists():
        logger.error("XLSX file not found: %s", xlsx_path)
        raise FileNotFoundError(f"XLSX file not found: {xlsx_path}")

    # Check if any target nodes are available
    available_nodes = any(nodes.get(target, []) for target in targets)
    if not available_nodes:
        logger.warning("No nodes available for targets: %s", targets)
        results.append({
            "siem": "none",
            "node": "none",
            "name": "N/A",
            "result": "SKIPPED",
            "action": "NO_NODES",
            "error": f"No nodes for targets: {targets}",
        })
        return results, False

    try:
        # Read NormalizationPolicy sheet
        logger.debug("Reading NormalizationPolicy sheet from %s", xlsx_path)
        df = pd.read_excel(xlsx_path, sheet_name="NormalizationPolicy", skiprows=0)
        # Drop header row if it contains 'row1'
        if 'row1' in df.iloc[0].astype(str).str.lower().values:
            df = df.iloc[1:].reset_index(drop=True)
        if df.empty:
            logger.warning("NormalizationPolicy sheet is empty in %s", xlsx_path)
            results.append({
                "siem": "none",
                "node": "none",
                "name": "N/A",
                "result": "SKIPPED",
                "action": "EMPTY_SHEET",
            })
            return results, False

        logger.debug("Found %d normalization policies in XLSX", len(df))
        # Convert to list of dicts, clean data
        policies = df.to_dict("records")
        for policy in policies:
            cleaned_policy = {
                "name": str(policy.get("policy_name", "")).strip(),
                "normalization_packages": [
                    pkg.strip() for pkg in str(policy.get("normalization_packages", "")).split("|")
                ] if policy.get("normalization_packages") else [],
                "compiled_normalizer": [
                    norm.strip() for norm in str(policy.get("compiled_normalizer", "")).split("|")
                ] if policy.get("compiled_normalizer") else [],
            }
            if not cleaned_policy["name"]:
                logger.warning("Skipping policy with empty name: %s", policy)
                continue

            logger.debug("Processing normalization policy: %s", cleaned_policy["name"])
            # Process for each target role
            for target in targets:
                if target not in nodes or not nodes[target]:
                    logger.warning("No nodes for target role %s", target)
                    continue
                for node in nodes.get(target, []):
                    siem_id = node["id"]
                    node_name = node["name"]
                    result = {
                        "siem": siem_id,
                        "node": node_name,
                        "name": cleaned_policy["name"],
                        "result": "PENDING",
                        "action": "NONE",
                    }

                    if dry_run:
                        result["result"] = "SKIPPED"
                        result["action"] = "DRY_RUN"
                        logger.info(
                            "Dry-run: Would import normalization policy %s to %s (%s)",
                            cleaned_policy["name"],
                            node_name,
                            siem_id,
                        )
                    else:
                        try:
                            # Check if policy exists
                            endpoint = client.build_endpoint(pool_uuid, siem_id, "normalization-policies")
                            existing_policies = client.get(endpoint).get("policies", [])
                            existing = next(
                                (p for p in existing_policies if p["name"] == cleaned_policy["name"]), None
                            )

                            if existing:
                                # Update existing policy
                                client.put(endpoint + f"/{existing['id']}", cleaned_policy)
                                result["action"] = "UPDATED"
                                logger.info(
                                    "Updated normalization policy %s on %s (%s)",
                                    cleaned_policy["name"],
                                    node_name,
                                    siem_id,
                                )
                            else:
                                # Create new policy
                                client.post(endpoint, cleaned_policy)
                                result["action"] = "CREATED"
                                logger.info(
                                    "Created normalization policy %s on %s (%s)",
                                    cleaned_policy["name"],
                                    node_name,
                                    siem_id,
                                )

                            result["result"] = "SUCCESS"
                        except Exception as e:
                            result["result"] = "FAILED"
                            result["error"] = str(e)
                            any_error = True
                            logger.error(
                                "Failed to import normalization policy %s to %s (%s): %s",
                                cleaned_policy["name"],
                                node_name,
                                siem_id,
                                e,
                            )

                    results.append(result)

        if not results:
            logger.warning("No normalization policies processed for %s", xlsx_path)
            results.append({
                "siem": "none",
                "node": "none",
                "name": "N/A",
                "result": "SKIPPED",
                "action": "NO_DATA",
            })

    except Exception as e:
        logger.error("Failed to parse NormalizationPolicy sheet in %s: %s", xlsx_path, e)
        raise ValueError(f"Failed to parse NormalizationPolicy sheet: {e}")

    return results, any_error