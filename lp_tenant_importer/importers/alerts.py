import logging
import pandas as pd
from typing import List, Dict, Any, Tuple
from pathlib import Path
from core.http import DirectorClient
import json

logger = logging.getLogger(__name__)

def import_alerts_for_nodes(
    client: DirectorClient,
    pool_uuid: str,
    nodes: Dict[str, List],
    xlsx_path: str,
    dry_run: bool,
    targets: List[str],
) -> Tuple[List[Dict], bool]:
    """Import alerts from XLSX to specified SIEM nodes (typically search_heads).

    Args:
        client: DirectorClient instance for API calls.
        pool_uuid: Tenant pool UUID.
        nodes: Dictionary of SIEM nodes by role (search_heads).
        xlsx_path: Path to XLSX file.
        dry_run: If True, simulate without API calls.
        targets: List of target roles (e.g., ['search_heads']).

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
        # Read Alert sheet
        logger.debug("Reading Alert sheet from %s", xlsx_path)
        df = pd.read_excel(xlsx_path, sheet_name="Alert", skiprows=0)
        # Drop header row if it contains 'row1'
        if 'row1' in df.iloc[0].astype(str).str.lower().values:
            df = df.iloc[1:].reset_index(drop=True)
        if df.empty:
            logger.warning("Alert sheet is empty in %s", xlsx_path)
            results.append({
                "siem": "none",
                "node": "none",
                "name": "N/A",
                "result": "SKIPPED",
                "action": "EMPTY_SHEET",
            })
            return results, False

        logger.debug("Found %d alerts in XLSX", len(df))
        # Convert to list of dicts, clean data
        alerts = df.to_dict("records")
        for alert in alerts:
            # Handle JSON string in settings.notify
            notify = alert.get("settings.notify", "[]")
            try:
                notify = json.loads(notify) if isinstance(notify, str) else notify
            except json.JSONDecodeError:
                logger.warning("Invalid JSON in settings.notify for alert %s: %s", alert.get("name", "N/A"), notify)
                notify = []

            cleaned_alert = {
                "name": str(alert.get("name", "")).strip(),
                "active": str(alert.get("settings.active", "true")).lower() == "true",
                "description": str(alert.get("settings.description", "")).strip() or None,
                "time_range_seconds": int(float(alert.get("settings.time_range_seconds", 0))),
                "query": str(alert.get("settings.extra_config.query", "")).strip() or None,
                "repos": [
                    repo.strip() for repo in str(alert.get("settings.repos", "")).split("|")
                ] if alert.get("settings.repos") else [],
                "condition": {
                    "condition_option": str(alert.get("settings.condition.condition_option", "")).strip() or None,
                    "condition_value": str(alert.get("settings.condition.condition_value", "")).strip() or None,
                },
                "notify": notify,
                "risk": str(alert.get("settings.risk", "")).strip() or None,
                "visible_to": str(alert.get("settings.visible_to", "[]")).strip() or [],
            }
            if not cleaned_alert["name"]:
                logger.warning("Skipping alert with empty name: %s", alert)
                continue

            logger.debug("Processing alert: %s", cleaned_alert["name"])
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
                        "name": cleaned_alert["name"],
                        "result": "PENDING",
                        "action": "NONE",
                    }

                    if dry_run:
                        result["result"] = "SKIPPED"
                        result["action"] = "DRY_RUN"
                        logger.info(
                            "Dry-run: Would import alert %s to %s (%s)",
                            cleaned_alert["name"],
                            node_name,
                            siem_id,
                        )
                    else:
                        try:
                            # Check if alert exists
                            endpoint = client.build_endpoint(pool_uuid, siem_id, "alerts")
                            existing_alerts = client.get(endpoint).get("alerts", [])
                            existing = next(
                                (a for a in existing_alerts if a["name"] == cleaned_alert["name"]), None
                            )

                            if existing:
                                # Update existing alert
                                client.put(endpoint + f"/{existing['id']}", cleaned_alert)
                                result["action"] = "UPDATED"
                                logger.info(
                                    "Updated alert %s on %s (%s)",
                                    cleaned_alert["name"],
                                    node_name,
                                    siem_id,
                                )
                            else:
                                # Create new alert
                                client.post(endpoint, cleaned_alert)
                                result["action"] = "CREATED"
                                logger.info(
                                    "Created alert %s on %s (%s)",
                                    cleaned_alert["name"],
                                    node_name,
                                    siem_id,
                                )

                            result["result"] = "SUCCESS"
                        except Exception as e:
                            result["result"] = "FAILED"
                            result["error"] = str(e)
                            any_error = True
                            logger.error(
                                "Failed to import alert %s to %s (%s): %s",
                                cleaned_alert["name"],
                                node_name,
                                siem_id,
                                e,
                            )

                    results.append(result)

        if not results:
            logger.warning("No alerts processed for %s", xlsx_path)
            results.append({
                "siem": "none",
                "node": "none",
                "name": "N/A",
                "result": "SKIPPED",
                "action": "NO_DATA",
            })

    except Exception as e:
        logger.error("Failed to parse Alert sheet in %s: %s", xlsx_path, e)
        raise ValueError(f"Failed to parse Alert sheet: {e}")

    return results, any_error