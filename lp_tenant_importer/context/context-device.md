## Comprehensive Plan, Engineering, and Specifications Document for Devices in lp_tenant_importer Project

#### Date and Version
- **Date**: September 26, 2025, 09:30 CEST (updated post-discussion and alignment on fields, mappings, and skips)
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document focuses on the Devices importer (including DeviceFetcher sub-module) and serves as the sole reference for its implementation. Updated with field limitations, devicegroup mapping via GET, skip if group missing, distributed_collector/logpolicy as empty arrays, timezone default "UTC".

#### Overview
The **Devices** importer is a Python-based module within the `lp_tenant_importer` project, designed to synchronize device configurations from the "Device" sheet and fetcher configurations from the "DeviceFetcher" sheet in Excel (XLSX) files with the LogPoint Director API (version 2.7.0). It handles creation, update, and listing of devices across multiple tenants (e.g., 'core'), with sub-logic for fetchers (limited to SyslogCollector). The importer supports dry-run simulations, async job monitoring, and comprehensive logging. It focuses on specified fields (availability, confidentiality, devicegroup, distributed_collector, integrity, ip, logpolicy, name, timezone), with devicegroup mapped from names in XLSX via API, and skip if group missing. No dependencies with other entities enforced, but DeviceGroups must be imported first for mapping. Tests to confirm 13 devices and ~13 fetchers, with NOOP on specified fields only.

#### Project Structure (Relevant to Devices)
The structure is modular, with Devices integrated as follows:
```
lp_tenant_importer/
├── main.py                    # CLI entry point, adds subcommand `import-devices`
├── config_loader.py           # Loads .env and YAML for pool_uuid, nodes
├── core/
│   ├── http.py               # API client with methods for Devices and plugins (e.g., create_device, get_device_plugins)
│   └── nodes.py              # Node management (backends, all_in_one for Devices targets)
├── importers/
│   ├── devices.py            # Devices import logic, including DeviceFetcher sub-module
├── logging_utils.py           # Logging setup
├── samples/
│   ├── core_config.xlsx      # Contains "Device" and "DeviceFetcher" sheets
├── tenants.full.example.yaml  # Tenant config with targets
```

#### General Modules (Relevant Updates)
##### main.py
- **Purpose**: CLI entry point, adds subcommand `import-devices` with arguments `--dry-run`, `--xlsx`, `--tenants`.
- **Functionality**: Initializes `DirectorClient`, loads config and nodes, delegates to `importers.devices.import_devices_for_nodes`. Forces 'error' column in output table via `print_table`.
- **Key Logic**:
  1. Parse arguments.
  2. Load tenant config.
  3. Call importer.
  4. Display results in table/JSON (with 'error' always included), exit with status (0 success, 1 error, 2 skip).

##### http.py
- **Purpose**: HTTP client for API interactions.
- **New Methods for Devices**:
  - `get_devices(pool_uuid, logpoint_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/Devices
  - `get_device(pool_uuid, logpoint_id, id)`: GET /configapi/{pool_uuid}/{logpoint_id}/Devices/{id}
  - `create_device(pool_uuid, logpoint_id, payload)`: POST /configapi/{pool_uuid}/{logpoint_id}/Devices
  - `update_device(pool_uuid, logpoint_id, id, payload)`: PUT /configapi/{pool_uuid}/{logpoint_id}/Devices/{id}
  - `get_device_plugins(pool_uuid, logpoint_id, device_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/Devices/{device_id}/plugins
  - `create_plugin(pool_uuid, logpoint_id, device_id, payload)`: POST /configapi/{pool_uuid}/{logpoint_id}/Devices/{device_id}/plugins
  - `update_plugin(pool_uuid, logpoint_id, device_id, uuid, payload)`: PUT /configapi/{pool_uuid}/{logpoint_id}/Devices/{device_id}/plugins/{uuid}
- **Key Logic**: Handle requests with auth, retries (3 attempts, 2s delay), monitor async jobs via `monitor_job` (poll until `success: true/false`, max 30 attempts, 2s interval). Fetch DeviceGroups for mapping.

##### logging_utils.py
- **Purpose**: Logging configuration.
- **Functionality**: Levels (DEBUG/INFO/WARNING/ERROR), JSON output optional, verbose HTTP debugging. Logs for group missing skips and NaN handling.

##### nodes.py
- **Purpose**: Manages SIEM nodes by role (backends, all_in_one for Devices targets).

#### Importers
##### devices.py
- **Specifications**: Manages devices (e.g., `core-ojs`) with specified fields, and fetchers (SyslogCollector) with XLS fields. Skips device if devicegroup missing. NOOP comparison on specified fields only.
- **API Endpoints** (from LogPoint Director API v2.7.0, pages 74-77):
  - GET `/configapi/{pool_uuid}/{logpoint_id}/Devices`: Lists all devices.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/Devices/{id}`: Fetches a device.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/Devices`: Creates a device.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/Devices/{id}`: Updates a device.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/DeviceGroups`: Lists groups for mapping.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/Devices/{device_id}/plugins`: Lists plugins.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/Devices/{device_id}/plugins`: Creates plugin.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/Devices/{device_id}/plugins/{uuid}`: Updates plugin.
- **Payload Structure**:
  - **CREATE (Device)**:
    ```json
    {
      "data": {
        "name": "core-ojs",
        "ip": ["10.93.8.26"],
        "timezone": "UTC",
        "devicegroup": ["mapped_id_for_windows"],
        "distributed_collector": [],
        "availability": "Major",
        "confidentiality": "Major",
        "integrity": "Major",
        "logpolicy": []
      }
    }
    ```
  - **UPDATE (Device)**:
    ```json
    {
      "data": {
        "id": "64fb908b5aaee58760df275e",
        "name": "core-ojs",
        "ip": ["10.93.8.26"],
        "timezone": "UTC",
        "devicegroup": ["mapped_id_for_windows"],
        "distributed_collector": [],
        "availability": "Major",
        "confidentiality": "Major",
        "integrity": "Major",
        "logpolicy": []
      }
    }
    ```
  - **CREATE (Fetcher/Plugin)**:
    ```json
    {
      "data": {
        "sid": "syslog|device-core-ojs",
        "parser": "SyslogParser",
        "processpolicy": "64f9ded28e8df427ea06b3de",
        "charset": "utf_8",
        "uuid": "new_uuid",
        "distributed_collector": "64f9287e8e8df427ea06b3d1"
      }
    }
    ```
- **XLS Structure**:
  - `Device`: `device_id, name, description, type, tags, ip, fqdn, active, timezone, has_hostname, device_groups, distributed_collector, confidentiality, integrity, availability` (limited to specified fields).
  - `DeviceFetcher`: `device_id, device_name, app, sid, parser, processpolicy, charset, uuid, path, excludes, hasLCP, client_id, api_key, uri, fetch_interval, LOGGEDINUSER, proxy, authorization_url, client_secret, events_url, distributed_collector, tenant_id, workspace_id, endpoint, resource, user_query, generated, requestType, ips, proxy_condition, CSRFToken`.
- **Data Formatting and Import Logic**:
  1. Load "Device" and "DeviceFetcher" sheets with `pandas.read_excel`.
  2. Fetch groups via GET `/DeviceGroups`, map names to IDs.
  3. For each device row, build payload with specified fields (handle NaN as defaults, timezone "UTC", arrays empty).
  4. Skip if any devicegroup missing (WARNING log).
  5. Fetch existing devices via GET `/Devices`, match by name/ip.
  6. Compare specified fields for NOOP.
  7. Execute POST/PUT for device, then for associated fetchers (match by sid).
- **Prerequisite Checks via API**:
  - Fetch DeviceGroups for mapping; skip if group missing.
  - Validate mandatory fields (name, ip, availability, confidentiality, integrity).
- **Status Handling and Payloads**:
  - **NOOP**: Identical specified fields.
    - Payload: N/A.
    - Log: `INFO: No changes needed for core-ojs on lb-backend01`.
  - **SKIP**: Missing group or invalid data.
    - Payload: N/A.
    - Log: `WARNING: Skipping core-ojs on lb-backend01 due to missing devicegroup 'windows'`.
  - **CREATE**: New device with valid groups.
    - Payload: As above.
    - Log: `INFO: Created core-ojs on lb-backend01`.
  - **UPDATE**: Changed fields.
    - Payload: Updated fields.
    - Log: `INFO: Updated core-ojs on lb-backend01`.
- **Error Logs**:
  - `ERROR: Failed to create core-ojs on lb-backend01: 400`.
  - `WARNING: Skipping due to missing ip`.
- **Algorithm**:
  1. Read "Device" and "DeviceFetcher" into DataFrames.
  2. For each node in targets:
     - Fetch groups, create name-to-ID map.
     - For each device row:
       - Map device_groups to IDs; skip if any missing.
       - Build payload (empty arrays for distributed_collector/logpolicy).
       - Check existing by name/ip.
       - If existing and fields identical: NOOP.
       - If existing and different: UPDATE with id.
       - If new and valid: CREATE.
       - Monitor job, log result.
     - For each fetcher (grouped by device_id):
       - Build payload, check existing by sid.
       - CREATE/UPDATE plugin, monitor job.

#### Import Algorithm (Detailed)
1. **Initialization**:
   - Load config (pool_uuid, nodes) from YAML/.env.
   - Initialize `DirectorClient`.
2. **Data Loading**:
   - Read sheets into DataFrames.
   - Handle NaN: ip/timezone defaults, convert types.
3. **Prerequisite Checks**:
   - Fetch groups for mapping; validate all names exist.
4. **Data Comparison**:
   - Serialize specified fields (JSON dumps).
   - Compare with existing.
5. **Action Execution**:
   - If dry_run, log simulation.
   - Else, POST/PUT payload, monitor job.
6. **Result Logging**:
   - Log action/result/error.
   - Return results for CLI display.
7. **Cleanup**:
   - Exit with status based on errors/skips.

#### Next Steps
- **Testing**: Execute `test_all.py` for Devices, validate logs. Test with 13 devices and fetchers.
- **Deployment**: Push to GitHub, generate Windows binary with `auto-py-to-exe`.
- **Future Work**: Implement `alerts.py` using API doc pages 7-42; add fetcher type support beyond SyslogCollector.

This document provides a complete blueprint for the Devices importer, covering all engineering details, specifications, and algorithms without requiring external sources.