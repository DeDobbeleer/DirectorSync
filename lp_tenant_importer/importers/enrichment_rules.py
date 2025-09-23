import pandas as pd
import time
from core.http import make_api_request
from logging_utils import logger

def import_enrichment_rules(config_file, dry_run=False, nonzero_on_skip=False, pool_uuid=None, logpoint_identifier=None):
    logger.info("Starting import of EnrichmentRules")
    df = pd.read_excel(config_file, sheet_name="EnrichmentRules", skiprows=0)
    results = []

    for _, row in df.iterrows():
        policy_name = row["policy_name"]
        spec_index = row["spec_index"]
        rule_data = {
            "source": row["source"],
            "category": row["category"],
            "source_key": row["source_key"],
            "prefix": row["prefix"],
            "operation": row["operation"],
            "type": row["type"],
            "event_key": row["event_key"],
        }
        endpoint = f"/configapi/v1/{pool_uuid}/{logpoint_identifier}/enrichment-policies/{policy_name}/rules/{spec_index}"
        action = "NOOP"

        # Vérifier si la règle existe
        existing_rule = make_api_request("GET", endpoint)
        if existing_rule:
            # Comparer les champs pour décider UPDATE ou SKIP
            if any(existing_rule.get(k) != v for k, v in rule_data.items()):
                action = "UPDATE"
                if not dry_run:
                    response = make_api_request("PUT", endpoint, payload=rule_data)
                    if response.get("success"):
                        request_id = response.get("message", "").split("/")[-1]
                        status = poll_request_status(pool_uuid, logpoint_identifier, request_id)
                        if not status.get("success"):
                            logger.error(f"Failed to update rule {policy_name}/{spec_index}: {status.get('errors')}")
                            action = "FAILED"
            else:
                action = "SKIP"
        else:
            action = "CREATE"
            if not dry_run:
                response = make_api_request("POST", f"/configapi/v1/{pool_uuid}/{logpoint_identifier}/enrichment-policies/{policy_name}/rules", payload=rule_data)
                if response.get("success"):
                    request_id = response.get("message", "").split("/")[-1]
                    status = poll_request_status(pool_uuid, logpoint_identifier, request_id)
                    if not status.get("success"):
                        logger.error(f"Failed to create rule {policy_name}/{spec_index}: {status.get('errors')}")
                        action = "FAILED"

        results.append({"policy_name": policy_name, "spec_index": spec_index, "action": action})
        logger.info(f"EnrichmentRule {policy_name}/{spec_index}: {action}")

    # Gérer --nonzero-on-skip
    if nonzero_on_skip and any(r["action"] == "SKIP" for r in results):
        logger.warning("Non-zero exit due to skipped rules")
        exit(2)

    return results

def poll_request_status(pool_uuid, logpoint_identifier, request_id, max_attempts=10, interval=5):
    """Poll le statut d'une requête asynchrone."""
    endpoint = f"/monitorapi/{pool_uuid}/{logpoint_identifier}/orders/{request_id}"
    for _ in range(max_attempts):
        response = make_api_request("GET", endpoint)
        if response.get("response", {}).get("success") is not None:
            return response["response"]
        time.sleep(interval)
    logger.error(f"Timeout polling request {request_id}")
    return {"success": False, "errors": ["Timeout"]}