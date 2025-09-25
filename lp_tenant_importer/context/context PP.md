# Context and Engineering Documentation for Processing Policies (PP)

## Documentation for Processing Policies

With your "GO" at **07:58 AM CEST on Wednesday, September 24, 2025**, I will now provide the complete engineering documentation for `processing_policies.py` in English, adhering to PEP 8, self-documented code, comprehensive logging, and utilization of common modules. We have approximately **6 hours and 2 minutes** until 14:00 CEST to finalize, targeting completion by **09:15 AM CEST** as per the updated plan. The implementation will reflect the mapping logic for `enrich_policy` and `routing_policy` IDs based on the source IDs in `core_config.xlsx` and the destination IDs fetched via API.

### Updated Findings (from Logs dated September 25, 2025)
- API requires `"policy_name"` and `"id"` in UPDATE payloads; absence causes 400 Bad Request.
- Successful UPDATE for `pp_rsa` after including `"policy_name"`.
- NOOP detects unchanged policies (e.g., `pp_windows`).
- 400 persists if IDs (e.g., `routing_policy`) invalid or not linked to node.
- Explicit validation added: Raise ValueError if required fields missing.
- "enrich_policy": "None" valid, but "Threat_Intelligence" often missing, leading to SKIP.

### Implementation Plan (Updated)
1. **Analysis and Validation (20 min)**:
   - Load "ProcessingPolicy", "EnrichmentPolicy", and "RoutingPolicy" with `pandas`.
   - Parse `original_policy_name`, `cleaned_policy_name`, `active`, `norm_policy` (name), `enrich_policy` (source ID), `routing_policy` (source ID).
   - Validate: SKIP if `policy_name` empty or `norm_policy` missing. Explicit check for required fields.

2. **API Fetch and Mapping (20 min)**:
   - Fetch existing via `GET /ProcessingPolicy`.
   - Dump `GET /NormalizationPolicy` (names), `GET /EnrichmentPolicy` (IDs), `GET /RoutingPolicy` (IDs) for target node.
   - Map `enrich_policy` and `routing_policy`: source ID → name via XLSX, then name → target ID via API.
   - New: Handle "None" for `enrich_policy` as empty string if API rejects "None".

3. **Action Logic (20 min)**:
   - NOOP: Identical (including mapped IDs).
   - SKIP: Invalid or missing dependencies (e.g., norm_policy not found).
   - CREATE: Non-existent → POST with mapped IDs, monitor job (30 attempts).
   - UPDATE: Differs → PUT with mapped IDs, monitor job.
   - Async handling updated to 30 attempts with exponential backoff.

4. **Integration and Tests (15 min)**:
   - Integrate in `main.py`.
   - Tests: Mapping validation, SKIP on missing ID, successful UPDATE for `pp_rsa`.

5. **Documentation (5 min)**:
   - Update `PROJECT_STATE.md`.

**Estimated Time**: 80 min. Start: 08:00 AM CEST, End: 09:20 AM CEST (September 25, 2025).

### Updated Algorithm in `processing_policies.py`
The algorithm has been finalized based on your implementation:
- Load sheets and build mappings.
- Per node: Fetch existing PP, NP, EP, RP.
- Validate dependencies (SKIP if missing).
- Map source IDs to target IDs.
- Determine action:
  - SKIP: Dependencies invalid.
  - CREATE: Not existing, valid dependencies.
  - UPDATE: Existing but differs (norm/enrich/routing).
  - NOOP: Existing and identical.
- Explicit validation: Raise if `"policy_name"` or `"id"` missing in UPDATE.

## API Endpoints (Based on Logpoint Director v2.7.0 Documentation)
#### Endpoint `POST /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`
- **Description**: Creates a processing policy (async).
- **Method**: POST
- **URL**: `https://api-server-host-name/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`
- **Headers**: Authorization: Bearer {token}, Content-Type: application/json.
- **Required Payload**:
  ```json
  {
    "data": {
      "name": "string",             // Policy name (required)
      "norm_policy": "string",      // Normalization policy ID or name (required)
      "enrich_policy": "string",    // Enrichment policy ID or "None" (optional)
      "routing_policy": "string"    // Routing policy ID (required)
    }
  }
  ```
- **Success Response**:
  ```json
  {
    "status": "Success",
    "message": "/monitorapi/{pool_uuid}/{logpoint_id}/orders/{request_id}"
  }
  ```
- **Failure Response**:
  ```json
  {
    "status": "Failed",
    "error": "string" // e.g., "Invalid norm_policy"
  }
  ```

#### Endpoint `PUT /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`
- **Description**: Edits a policy (async).
- **Method**: PUT
- **URL**: `https://api-server-host-name/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`
- **Headers**: Same as POST.
- **Required Payload**:
  ```json
  {
    "data": {
      "id": "string",               // Policy ID (required)
      "policy_name": "string",      // Policy name (required)
      "norm_policy": "string",      // Normalization policy ID or name (required)
      "enrich_policy": "string",    // Enrichment policy ID or "None" (optional)
      "routing_policy": "string"    // Routing policy ID (required)
    }
  }
  ```
  - `id`: Required in URL and payload.
  - Other fields: Same as POST.
- **Success Response**: Same as POST.
- **Failure Response**: Same as POST.

#### Dependencies and Validation
- **Mapping**:
  - Load "EnrichmentPolicy": source ID → EP name.
  - Load "RoutingPolicy": source ID → RP name.
  - Per target node: Dump `GET /EnrichmentPolicy` and `GET /RoutingPolicy`, map name → target ID.
- **Verification**:
  - `norm_policy`: Required, valid name via `/NormalizationPolicy`.
  - `enrich_policy`: Optional, valid target ID if present.
  - `routing_policy`: Required, valid target ID.
  - SKIP if `norm_policy` invalid; warning for others.
  - Explicit validation: Raise if `"policy_name"` or `"id"` missing in UPDATE.

## Next Steps
- **Status**: Updated with new findings (e.g., 400 resolution via "policy_name"), finalized algorithm from .py.
- **Action**: Test or finalize with "GO".
- **Time**: 08:45 AM CEST (September 25, 2025). On track!