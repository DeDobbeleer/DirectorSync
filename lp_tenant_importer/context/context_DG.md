## Comprehensive Plan, Engineering, and Specifications Document for DeviceGroups in lp_tenant_importer Project

#### Date and Version
- **Date**: September 26, 2025, 00:55 CEST
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document focuses on the DeviceGroups importer and serves as the sole reference for its implementation.

#### Overview
The **DeviceGroups** importer is a Python-based module within the `lp_tenant_importer` project, designed to synchronize device group configurations from the "DeviceGroups" sheet in Excel (XLSX) files with the LogPoint Director API (version 2.7.0). It handles creation, editing, listing, fetching, and deletion of device groups across multiple tenants (e.g., 'core'). The importer supports dry-run simulations, async job monitoring, and comprehensive logging. It excludes `device_ids` as per user specification, focusing on `name`, `description`, `active`, and `tags` (though `tags` is not supported in the API and may be ignored or mapped if needed). No dependencies with other entities are enforced, allowing independent import.

#### Project Structure (Relevant to DeviceGroups)
The structure is modular, with DeviceGroups integrated as follows:
```
lp_tenant_importer/
├── main.py                    # CLI entry point, adds subcommand `import-device-groups`
├── config_loader.py           # Loads .env and YAML for pool_uuid, nodes
├── core/
│   ├── http.py               # API client with methods for DeviceGroups (e.g., create_device_group, update_device_group)
│   └── nodes.py              # Node management (backends, all_in_one)
├── importers/
│   ├── device_groups.py      # DeviceGroups import logic
├── logging_utils.py           # Logging setup
├── samples/
│   ├── core_config.xlsx      # Contains "DeviceGroups" sheet
├── tenants.full.example.yaml  # Tenant config with targets
```

#### General Modules (Relevant Updates)
##### main.py
- **Purpose** : CLI entry point, adds subcommand `import-device-groups` with arguments `--dry-run`, `--xlsx`, `--tenants`.
- **Functionality** : Initializes `DirectorClient`, loads config and nodes, delegates to `importers.device_groups.import_device_groups_for_nodes`.
- **Key Logic** :
  1. Parse arguments.
  2. Load tenant config.
  3. Call importer.
  4. Display results in table/JSON, exit with status (0 success, 1 error, 2 skip).

##### http.py
- **Purpose** : HTTP client for API interactions.
- **New Methods for DeviceGroups** :
  - `get_device_groups(pool_uuid, logpoint_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/DeviceGroups
  - `get_device_group(pool_uuid, logpoint_id, id)`: GET /configapi/{pool_uuid}/{logpoint_id}/DeviceGroups/{id}
  - `create_device_group(pool_uuid, logpoint_id, payload)`: POST /configapi/{pool_uuid}/{logpoint_id}/DeviceGroups
  - `update_device_group(pool_uuid, logpoint_id, id, payload)`: PUT /configapi/{pool_uuid}/{logpoint_id}/DeviceGroups/{id}
  - `delete_device_group(pool_uuid, logpoint_id, id)`: DELETE /configapi/{pool_uuid}/{logpoint_id}/DeviceGroups/{id}
- **Key Logic** : Handle requests with auth, retries (3 attempts, 2s delay), monitor async jobs via `monitor_job` (poll until `success: true/false`, max 30 attempts, 2s interval).

##### logging_utils.py
- **Purpose** : Logging configuration.
- **Functionality** : Levels (DEBUG/INFO/WARNING/ERROR), JSON output optional, verbose HTTP debugging.

##### nodes.py
- **Purpose** : Manages SIEM nodes by role (backends, all_in_one for DeviceGroups targets).

#### Importers
##### device_groups.py
- **Specifications** : Manages device groups (e.g., `windows`, `RSA`) with fields `name`, `description`, `active`, `tags` (excludes `device_ids`). No dependencies enforced.
- **API Endpoints** (from LogPoint Director API v2.7.0, Chapter 8) :
  - GET `/configapi/{pool_uuid}/{logpoint_id}/DeviceGroups`: Lists all groups.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/DeviceGroups/{id}`: Fetches a group.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/DeviceGroups`: Creates a group.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/DeviceGroups/{id}`: Updates a group.
  - DELETE `/configapi/{pool_uuid}/{logpoint_id}/DeviceGroups/{id}`: Deletes a group (Trash).
- **Payload Structure** :
  - **CREATE** :
    ```json
    {
      "data": {
        "name": "windows",
        "description": "windows",
        "active": true,
        "tags": ""
      }
    }
    ```
  - **UPDATE** :
    ```json
    {
      "data": {
        "name": "windows",
        "description": "updated description",
        "active": true,
        "tags": ""
      }
    }
    ```
  - **Response** : {"status": "Success", "message": "/monitorapi/{pool_uuid}/{logpoint_id}/orders/{request_id}"} for async operations. Monitor via GET to the message URL.
- **XLS Structure** : `group_id, name, description, active, device_ids (ignored), tags`.
- **Data Formatting and Import Logic** :
  1. Load "DeviceGroups" sheet with `pandas.read_excel`.
  2. Ignore `device_ids`.
  3. For each row, build payload with `name`, `description`, `active`, `tags` (handle NaN as empty string).
  4. Fetch existing groups via GET `/DeviceGroups` per node.
  5. Compare: NOOP if identical (name, description, active, tags), UPDATE if different (use `group_id`), CREATE if new.
  6. Execute POST/PUT, monitor job, log outcome.
- **Prerequisite Checks via API** :
  - No dependencies; basic validation for mandatory fields (`name`, `active`).
- **Status Handling and Payloads** :
  - **NOOP**: Identical configuration.
    - Payload: N/A.
    - Log: `INFO: No changes needed for windows on lb-backend01`.
  - **SKIP**: Invalid data (e.g., missing name).
    - Payload: N/A.
    - Log: `WARNING: Skipping windows on lb-backend01 due to missing name`.
  - **CREATE**: New group.
    - Payload: As above.
    - Log: `INFO: Created windows on lb-backend01`.
  - **UPDATE**: Changed fields (e.g., description).
    - Payload: Updated fields.
    - Log: `INFO: Updated RSA on lb-backend01`.
- **Error Logs** :
  - `ERROR: Failed to create windows on lb-backend01: 400`.
  - `WARNING: Skipping due to invalid active status`.
- **Algorithm** :
  1. Read "DeviceGroups" into DataFrame.
  2. For each node in targets:
     - Fetch existing groups via GET `/DeviceGroups`.
     - For each row in DataFrame:
       - Build payload (ignore device_ids, handle NaN).
       - Validate mandatory fields.
       - Check if exists by name or group_id.
       - If existing and identical: NOOP.
       - If existing and different: UPDATE with group_id.
       - If new and valid: CREATE.
       - Monitor job with `monitor_job`, log result.

#### Import Algorithm (Detailed)
1. **Initialization** :
   - Load config (pool_uuid, nodes) from YAML/.env.
   - Initialize `DirectorClient`.
2. **Data Loading** :
   - Read "DeviceGroups" into DataFrame.
   - Drop or ignore `device_ids`.
   - Handle NaN: description/tags → "", active → skip if not bool.
3. **Prerequisite Checks** :
   - No dependencies; validate fields (name not empty, active bool).
4. **Data Comparison** :
   - Serialize payload (JSON dumps).
   - Compare with existing (name, description, active, tags).
5. **Action Execution** :
   - If dry_run, log simulation.
   - Else, POST/PUT payload, monitor job.
6. **Result Logging** :
   - Log action/result/error.
   - Return results for CLI display.
7. **Cleanup** :
   - Exit with status based on errors/skips.

#### Next Steps
- **Testing** : Execute `test_all.py` for DeviceGroups, validate logs.
- **Deployment** : Integrate into GitHub, generate binary.
- **Future Work** : Add tags if supported in future API versions; implement Device if needed.

This document provides a complete blueprint for the DeviceGroups importer, covering all engineering details, specifications, and algorithms without requiring external sources.