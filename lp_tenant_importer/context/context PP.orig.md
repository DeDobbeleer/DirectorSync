### Documentation d'Ingénierie pour Processing Policies (PP)

With your "GO" at **07:58 AM CEST on Wednesday, September 24, 2025**, I will now provide the complete engineering documentation for `processing_policies.py` in English, adhering to PEP 8, self-documented code, comprehensive logging, and utilization of common modules. We have approximately **6 hours and 2 minutes** until 14:00 CEST to finalize, targeting completion by **09:15 AM CEST** as per the updated plan. The implementation will reflect the mapping logic for `enrich_policy` and `routing_policy` IDs based on the source IDs in `core_config.xlsx` and the destination IDs fetched via API.

---

#### Implementation Plan
1. **Analysis and Validation (20 minutes)**:
   - Load "ProcessingPolicy", "EnrichmentPolicy", and "RoutingPolicy" sheets with `pandas`.
   - Parse `original_policy_name`, `cleaned_policy_name`, `active`, `norm_policy`, `enrich_policy` (source ID), `routing_policy` (source ID).
   - Validate: SKIP if `policy_name` is empty or `norm_policy` is missing.

2. **API Fetch and Mapping (20 minutes)**:
   - Fetch existing policies via `GET /ProcessingPolicy`.
   - Dump `GET /NormalizationPolicy`, `GET /EnrichmentPolicy`, and `GET /RoutingPolicy` for the target node.
   - Map `enrich_policy` and `routing_policy` source IDs to names via XLSX, then to target IDs via API.

3. **Action Logic (20 minutes)**:
   - NOOP: Policy exists and matches (including mapped IDs).
   - SKIP: Invalid or missing critical dependencies.
   - CREATE: Non-existent, valid → POST with mapped IDs, monitor job.
   - UPDATE: Differs, valid → PUT with mapped IDs, monitor job.
   - Async handling with `monitor_job` (30 attempts, 2s interval).

4. **Integration and Testing (15 minutes)**:
   - Integrate with `main.py`.
   - Test in `test_all.py`: 9 policies, mapping cases.

5. **Documentation (5 minutes)**:
   - Update `PROJECT_STATE.md`.

**Estimated Time**: 80 minutes. Start: 08:00 AM CEST, End: 09:20 AM CEST.

---

#### Code Implementation (`importers/processing_policies.py`)
```python
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
    except Exception as e:
        logger.error("Failed to load sheets: %s", e)
        return [], True

    # Build source ID to name mappings
    ep_mapping = dict(zip(ep_df["id"], ep_df["name"]))
    rp_mapping = dict(zip(rp_df["id"], rp_df["name"]))

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
                enrich_policy_name = ep_mapping.get(enrich_policy_src_id, "") if enrich_policy_src_id else "None"
                routing_policy_name = rp_mapping.get(routing_policy_src_id, "") if routing_policy_src_id else "None"

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
```

#### Updates to `core/http.py` (Methods for PP)
Add these methods to the `DirectorClient` class:
```python
    def get_existing_processing_policies(self, pool_uuid: str, logpoint_id: str) -> List[Dict]:
        """Fetch existing processing policies from the SIEM."""
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy"
        try:
            response = self.session.get(url, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            logger.debug("Raw response from %s: %s", url, response.text)
            data = response.json()
            policies = data if isinstance(data, list) else data.get("data", [])
            logger.debug("Fetched %d existing processing policies", len(policies))
            return policies
        except requests.RequestException as e:
            logger.error("Failed to fetch existing processing policies: %s", str(e))
            return []

    def create_processing_policy(self, pool_uuid: str, logpoint_id: str, policy: Dict) -> Dict:
        """Create a new processing policy (async)."""
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy"
        payload = {
            "data": {
                "name": policy["name"],
                "active": policy.get("active", True),
                "norm_policy": policy.get("norm_policy", ""),
                "enrich_policy": policy.get("enrich_policy", "None"),
                "routing_policy": policy.get("routing_policy", "None")
            }
        }
        logger.debug("Create request body for %s: %s", url, json.dumps(payload, indent=2))
        try:
            response = self.session.post(url, json=payload, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            result = response.json()
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
                monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
                logger.info("Monitoring job for create %s at %s", policy["name"], monitorapi)
                job_status = self.monitor_job(monitorapi)
                if job_status.get("success"):
                    logger.info("Processing policy %s created successfully", policy["name"])
                    return {"status": "success"}
                else:
                    error = json.dumps(job_status, indent=2)
                    logger.error("Create job failed for %s: %s", policy["name"], error)
                    return {"status": "failed", "error": error}
            return {"status": "failed", "error": json.dumps(result, indent=2)}
        except requests.RequestException as e:
            logger.error("Failed to create processing policy %s: %s", policy["name"], str(e))
            return {"status": "failed", "error": str(e)}

    def update_processing_policy(self, pool_uuid: str, logpoint_id: str, policy_id: str, policy: Dict) -> Dict:
        """Update an existing processing policy (async)."""
        url = f"{self.base_url}/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{policy_id}"
        payload = {
            "data": {
                "active": policy.get("active", True),
                "norm_policy": policy.get("norm_policy", ""),
                "enrich_policy": policy.get("enrich_policy", "None"),
                "routing_policy": policy.get("routing_policy", "None")
            }
        }
        logger.debug("Update request body for %s: %s", url, json.dumps(payload, indent=2))
        try:
            response = self.session.put(url, json=payload, verify=self.verify, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
            result = response.json()
            if result.get("status") == "Success" and "message" in result and result["message"].startswith("monitorapi/"):
                monitorapi = '/' + result["message"] if not result["message"].startswith('/') else result["message"]
                logger.info("Monitoring job for update %s at %s", policy_id, monitorapi)
                job_status = self.monitor_job(monitorapi)
                if job_status.get("success"):
                    logger.info("Processing policy %s updated successfully", policy_id)
                    return {"status": "success"}
                else:
                    error = json.dumps(job_status, indent=2)
                    logger.error("Update job failed for %s: %s", policy_id, error)
                    return {"status": "failed", "error": error}
            return {"status": "failed", "error": json.dumps(result, indent=2)}
        except requests.RequestException as e:
            logger.error("Failed to update processing policy %s: %s", policy_id, str(e))
            return {"status": "failed", "error": str(e)}
```

#### Specifications
##### **Dependencies and Constraints**
- **Dependencies**: PP relies on NP (`norm_policy`), EP (`enrich_policy`), and RP (`routing_policy`). Validation via API; SKIP if `norm_policy` invalid, warnings for others.
- **XLSX Fields** (based on `core_config.xlsx`):
  - `original_policy_name`: Original name.
  - `cleaned_policy_name`: Cleaned name (priority if present).
  - `active`: Boolean (1/0 or True/False), default True.
  - `norm_policy`: Normalization policy name, mandatory.
  - `enrich_policy`: Enrichment policy source ID, optional.
  - `routing_policy`: Routing policy source ID, mandatory.
  - Validation: SKIP if `norm_policy` missing; map IDs.
- **API Endpoints** (per documentation):
  - `GET /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`: List existing policies.
  - `POST /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`: Create.
  - `PUT /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`: Update.
  - Dependencies via `/NormalizationPolicy`, `/EnrichmentPolicy`, `/RoutingPolicy`.
- **Action Logic**:
  | Action | Conditions | Result | Possible Errors |
  |--------|------------|--------|-----------------|
  | NOOP   | Exists and matches | N/A | - |
  | SKIP   | Missing `norm_policy` | N/A | "Missing norm_policy" |
  | CREATE | Non-existent, valid | Success/Fail | API error, timeout |
  | UPDATE | Exists, differs, valid | Success/Fail | API error, timeout |

- **Payload API**: `norm_policy` (name), `enrich_policy`/`routing_policy` (IDs or "None").
- **Monitoring**: Poll `monitor_job` (30x, 2s).
- **Logging**: DEBUG, INFO, WARNING, ERROR.
- **Dry Run**: Simulate without API calls.

##### **Examples**
- **CREATE Payload**: `{"data": {"name": "default_processing_policy", "active": true, "norm_policy": "_logpoint", "enrich_policy": "57591a2cd8aaa41bfef54888", "routing_policy": "586cc3edd8aaa406f6fdc8e3"}}`.
- **Log**: "Creating processing policy default_processing_policy".

---

#### Next Steps
- **Status**: PP implemented with mapping logic. Target completion: 09:20 AM CEST.
- **Action**: Run tests or proceed to DeviceGroups/Device with "GO".
- **Time**: 08:05 AM CEST. On track!

Say "GO" to proceed! 😎