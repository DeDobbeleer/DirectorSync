import logging
import pandas as pd
from typing import List, Dict, Any, Tuple
from pathlib import Path
from core.http import DirectorClient

logger = logging.getLogger(__name__)

def import_enrichment_policies_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List],
    xlsx_path: str,
    dry_run: bool,
    targets: List[str],
) -> Tuple[List[Dict], bool]:
    """Import enrichment policies from XLSX to specified SIEM nodes.

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

    xlsx_path = Path(xlsx_path)
    if not xlsx_path.exists():
        logger.error("XLSX file not found: %s", xlsx_path)
        raise FileNotFoundError(f"XLSX file not found: {xlsx_path}")

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
        logger.debug("Reading EnrichmentPolicy sheet from %s", xlsx_path)
        df = pd.read_excel(xlsx_path, sheet_name="EnrichmentPolicy", skiprows=0)
        if 'row1' in df.iloc[0].astype(str).str.lower().values:
            df = df.iloc[1:].reset_index(drop=True)
        if df.empty:
            logger.warning("EnrichmentPolicy sheet is empty in %s", xlsx_path)
            results.append({
                "siem": "none",
                "node": "none",
                "name": "N/A",
                "result": "SKIPPED",
                "action": "EMPTY_SHEET",
            })
            return results, False

        logger.debug("Found %d enrichment policies in XLSX", len(df))
        policies = df.to_dict("records")
        for policy in policies:
            cleaned_policy = {
                "name": str(policy.get("policy_name", "")).strip(),
                "active": str(policy.get("active", "true")).lower() == "true",
                "description": str(policy.get("description", "")).strip() or None,
                "tags": [tag.strip() for tag in str(policy.get("tags", "")).split("|") if tag.strip()],
                "source": str(policy.get("source", "")).strip() or None,
                "policy_id": str(policy.get("policy_id", "")).strip() or None,
            }
            if not cleaned_policy["name"]:
                logger.warning("Skipping policy with empty name: %s", policy)
                continue

            logger.debug("Processing enrichment policy: %s", cleaned_policy["name"])
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
                        logger.info("Dry-run: Would import enrichment policy %s to %s (%s)", cleaned_policy["name"], node_name, siem_id)
                    else:
                        try:
                            # Placeholder for API checks (to be extended with get_existing_policies)
                            existing_policies = client.get_existing_policies(pool_uuid, siem_id)  # Hypothetical method
                            existing = next((p for p in existing_policies if p["name"] == cleaned_policy["name"]), None)

                            if existing and _compare_policies(existing, cleaned_policy):
                                result["result"] = "SKIPPED"
                                result["action"] = "NOOP"
                                logger.info("No changes needed for policy %s on %s (%s)", cleaned_policy["name"], node_name, siem_id)
                            else:
                                if not existing:
                                    response = client.post(f"/api/v1/enrichment-policies", json=cleaned_policy)  # Hypothetical
                                    status = client.monitor_job(response.json().get("monitorapi"))
                                    if status.get("success"):
                                        result["action"] = "CREATED"
                                        result["result"] = "SUCCESS"
                                        logger.info("Created policy %s on %s (%s)", cleaned_policy["name"], node_name, siem_id)
                                    else:
                                        result["action"] = "FAILED"
                                        result["result"] = "FAILED"
                                        result["error"] = status.get("error", "Unknown error")
                                        any_error = True
                                        logger.error("Failed to create policy %s on %s (%s): %s", cleaned_policy["name"], node_name, siem_id, result["error"])
                                else:
                                    response = client.put(f"/api/v1/enrichment-policies/{existing['id']}", json=cleaned_policy)  # Hypothetical
                                    status = client.monitor_job(response.json().get("monitorapi"))
                                    if status.get("success"):
                                        result["action"] = "UPDATED"
                                        result["result"] = "SUCCESS"
                                        logger.info("Updated policy %s on %s (%s)", cleaned_policy["name"], node_name, siem_id)
                                    else:
                                        result["action"] = "FAILED"
                                        result["result"] = "FAILED"
                                        result["error"] = status.get("error", "Unknown error")
                                        any_error = True
                                        logger.error("Failed to update policy %s on %s (%s): %s", cleaned_policy["name"], node_name, siem_id, result["error"])
                        except Exception as e:
                            result["result"] = "FAILED"
                            result["error"] = str(e)
                            any_error = True
                            logger.error("Failed to process policy %s on %s (%s): %s", cleaned_policy["name"], node_name, siem_id, e)

                    results.append(result)

        if not results:
            logger.warning("No enrichment policies processed for %s", xlsx_path)
            results.append({
                "siem": "none",
                "node": "none",
                "name": "N/A",
                "result": "SKIPPED",
                "action": "NO_DATA",
            })



    except Exception as e:
        logger.error("Failed to parse EnrichmentPolicy sheet in %s: %s", xlsx_path, e)
        raise ValueError(f"Failed to parse EnrichmentPolicy sheet: {e}")

    return results, any_error

def _compare_policies(existing: Dict, new: Dict) -> bool:
    if existing["name"] != new["name"] or existing["active"] != new["active"]:
        return False
    existing_tags = set(existing.get("tags", []))
    new_tags = set(new.get("tags", []))
    return (existing.get("description") == new.get("description") and
            existing.get("source") == new.get("source") and
            existing_tags == new_tags)