## Comprehensive Plan, Engineering, and Specifications Document for Fetchers in lp_tenant_importer Project

#### Date and Version
- **Date**: September 26, 2025, 12:00 CEST (updated post-API doc extraction and analysis)
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document focuses on the Fetchers importer (specifically Syslog Collectors) and serves as the sole reference for its implementation. Updated with API details from LogPoint Director API v2.7.0: conditional mandatory fields, list support for hostname/proxy_ip, no dependencies enforced beyond optional device_id and processpolicy validation. Tests to be conducted: Expected ~15 rows filtered to SyslogCollector, with NOOP on matching fields, SKIP for hors scope/invalid, and CREATE/UPDATE for changes.

#### Overview
The **Fetchers** importer is a Python-based module within the `lp_tenant_importer` project, designed to synchronize fetcher configurations (focusing on Syslog Collectors) from the "DeviceFetcher" sheet in Excel (XLSX) files with the LogPoint Director API (version 2.7.0). It handles creation, editing, and deletion of Syslog Collectors across multiple tenants (e.g., 'core'), filtering for `app="SyslogCollector"` and skipping others as "hors scope". The importer supports dry-run simulations, async job monitoring, and comprehensive logging. It handles types based on `proxy_condition` (`use_as_proxy`, `uses_proxy`, `None`), with conditional validations (e.g., no processpolicy for `use_as_proxy`), cross-check of proxy_ip via Devices List, and excludes non-essential fields like sid, uuid, fetch_interval. No strict dependencies with other entities are enforced, but validates optional device_id and processpolicy. Tests pending: Validate filtering, 3 types, and ~10 NOOP/3 UPDATE/2 SKIP actions.

#### Project Structure (Relevant to Fetchers)
The structure is modular, with Fetchers integrated as follows:
```
lp_tenant_importer/
├── main.py                    # CLI entry point, adds subcommand `import-syslog-collectors`
├── config_loader.py           # Loads .env and YAML for pool_uuid, nodes
├── core/
│   ├── http.py               # API client with methods for SyslogCollector (e.g., create_syslog_collector, update_syslog_collector)
│   └── nodes.py              # Node management (backends, all_in_one)
├── importers/
│   ├── syslog_collectors.py  # Syslog Collectors import logic (filtered from DeviceFetcher)
├── logging_utils.py           # Logging setup
├── samples/
│   ├── core_config.xlsx      # Contains "DeviceFetcher" sheet
├── tenants.full.example.yaml  # Tenant config with targets
```

#### General Modules (Relevant Updates)
##### main.py
- **Purpose** : CLI entry point, adds subcommand `import-syslog-collectors` with arguments `--dry-run`, `--xlsx`, `--tenants`.
- **Functionality** : Initializes `DirectorClient`, loads config and nodes, delegates to `importers.syslog_collectors.import_syslog_collectors_for_nodes`. Forces 'error' column in output table via `print_table`.
- **Key Logic** :
  1. Parse arguments.
  2. Load tenant config.
  3. Call importer.
  4. Display results in table/JSON (with 'error' always included), exit with status (0 success, 1 error, 2 skip).

##### http.py
- **Purpose** : HTTP client for API interactions.
- **New Methods for Syslog Collectors** :
  - `get_devices(pool_uuid, logpoint_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/Device (for cross-check and existence)
  - `create_syslog_collector(pool_uuid, logpoint_id, payload)`: POST /configapi/{pool_uuid}/{logpoint_id}/SyslogCollector
  - `update_syslog_collector(pool_uuid, logpoint_id, id, payload)`: PUT /configapi/{pool_uuid}/{logpoint_id}/SyslogCollector/{id}
  - `delete_syslog_collector(pool_uuid, logpoint_id, id)`: DELETE /configapi/{pool_uuid}/{logpoint_id}/SyslogCollector/{id}
- **Key Logic** : Handle requests with auth, retries (3 attempts, 2s delay), monitor async jobs via `monitor_job` (poll /monitorapi/{pool_uuid}/{logpoint_id}/orders/{request_id} until `success: true/false`, max 30 attempts, 2s interval). Tests pending for monitoring CREATE/UPDATE.

##### logging_utils.py
- **Purpose** : Logging configuration.
- **Functionality** : Levels (DEBUG/INFO/WARNING/ERROR), JSON output optional, verbose HTTP debugging. Updated logs for tracing SKIP (hors scope/invalid proxy_condition).

##### nodes.py
- **Purpose** : Manages SIEM nodes by role (backends, all_in_one for Fetchers targets).

#### Importers
##### syslog_collectors.py
- **Specifications** : Manages Syslog Collectors (filtered from `app="SyslogCollector"`) with fields `device_id` (optional), `hostname` (list), `processpolicy` (conditional), `proxy_condition` (mandatory), `proxy_ip` (list, conditional), `charset` (conditional), `parser` (conditional). Skips non-SyslogCollector as "hors scope". Validates types, cross-checks proxy_ip against use_as_proxy IPs via Devices List. Tests pending: 15 rows, filter to ~10, with NOOP comparison on key fields.
- **API Endpoints** (from LogPoint Director API v2.7.0, SyslogCollector section) :
  - GET `/configapi/{pool_uuid}/{logpoint_id}/Device`: Lists devices for cross-check/existence (no direct GET for SyslogCollector list).
  - POST `/configapi/{pool_uuid}/{logpoint_id}/SyslogCollector`: Creates a collector.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/SyslogCollector/{id}`: Updates a collector.
  - DELETE `/configapi/{pool_uuid}/{logpoint_id}/SyslogCollector/{id}`: Deletes a collector (Trash).
- **Payload Structure** :
  - **CREATE** :
    ```json
    {
      "data": {
        "device_id": "64fb908b5aaee58760df275e",
        "hostname": ["core-ojs", "core-ojs.local.ld", "10.93.8.26"],
        "processpolicy": "64f9ded28e8df427ea06b3de",
        "proxy_condition": "uses_proxy",
        "proxy_ip": ["10.10.25.1", "10.10.25.2"],
        "charset": "utf_8",
        "parser": "SyslogParser"
      }
    }
    ```
  - **UPDATE** :
    ```json
    {
      "data": {
        "hostname": ["updated-hostname"],
        "processpolicy": "updated-id",
        "proxy_condition": "uses_proxy",
        "proxy_ip": ["1.1.1.1"],
        "charset": "utf_8",
        "parser": "SyslogParser"
      }
    }
    ```
  - **Response** : {"status": "Success", "message": "/monitorapi/{pool_uuid}/{logpoint_id}/orders/{request_id}"} for async operations. Monitor via GET to the message URL. Tests pending for 'Syslog Collector information updated'.
- **XLS Structure** : `device_id, device_name, app, sid, parser, processpolicy, charset, uuid, path, excludes, hasLCP, client_id, api_key, uri, fetch_interval, LOGGEDINUSER, proxy, authorization_url, client_secret, events_url, distributed_collector, tenant_id, workspace_id, endpoint, resource, user_query, generated, requestType, ips, proxy_condition, CSRFToken, proxy_ip, hostname`.
- **Data Formatting and Import Logic** :
  1. Load "DeviceFetcher" sheet with `pandas.read_excel`.
  2. Filter for `app="SyslogCollector"`, SKIP others as "hors scope".
  3. For each row, build payload with `device_id` (optional), `hostname` (list from split "|"), `processpolicy` (conditional), `proxy_condition` (mandatory), `proxy_ip` (list from split "|", conditional), `charset` (conditional), `parser` (conditional); exclude others.
  4. Fetch devices via GET `/Device` per node for existence/cross-check.
  5. Compare key fields (proxy_condition, processpolicy, proxy_ip, hostname, charset, parser) for NOOP (serialized JSON).
  6. Execute POST/PUT, monitor job, log outcome.
- **Prerequisite Checks via API** :
  - Validate device_id (optional) via GET `/Device/{device_id}`.
  - Validate processpolicy (conditional) via GET `/ProcessingPolicy/{processpolicy}`.
  - Cross-check proxy_ip for "uses_proxy": Match against IPs from use_as_proxy via GET `/Device`.
- **Status Handling and Payloads** :
  - **NOOP**: Identical key fields.
    - Payload: N/A.
    - Log: `INFO: No changes needed for core-ojs on lb-backend01`.
  - **SKIP**: Invalid (e.g., missing mandatory, hors scope).
    - Payload: N/A.
    - Log: `WARNING: Skipping core-ojs on lb-backend01 due to invalid proxy_condition` or `hors scope`.
  - **CREATE**: New collector.
    - Payload: As above.
    - Log: `INFO: Created core-ojs on lb-backend01`.
  - **UPDATE**: Changed fields.
    - Payload: Updated fields.
    - Log: `INFO: Updated core-vs2-p001esarsam on lb-backend01`.
- **Error Logs** :
  - `ERROR: Failed to create core-ojs on lb-backend01: 400`.
  - `WARNING: Skipping due to missing processpolicy`.
- **Algorithm** :
  1. Read "DeviceFetcher" into DataFrame.
  2. Filter for app="SyslogCollector".
  3. For each node in targets:
     - Fetch devices via GET `/Device`.
     - For each filtered row:
       - Split lists (hostname, proxy_ip by "|").
       - Validate mandatory/conditional fields based on proxy_condition.
       - Cross-check proxy_ip for "uses_proxy".
       - Check if exists by device_id or matching fields.
       - If existing and identical: NOOP.
       - If existing and different: UPDATE with id.
       - If new and valid: CREATE.
       - Monitor job with `monitor_job`, log result.

#### Import Algorithm (Detailed)
1. **Initialization** :
   - Load config (pool_uuid, nodes) from YAML/.env.
   - Initialize `DirectorClient`.
2. **Data Loading** :
   - Read "DeviceFetcher" into DataFrame.
   - Filter app="SyslogCollector", SKIP others.
   - Handle NaN: strings → "", lists → [].
3. **Prerequisite Checks** :
   - Validate fields per proxy_condition.
   - Cross-check proxy_ip via GET `/Device`.
4. **Data Comparison** :
   - Serialize key fields (JSON dumps).
   - Compare with existing from GET `/Device`.
5. **Action Execution** :
   - If dry_run, log simulation.
   - Else, POST/PUT payload, monitor job.
6. **Result Logging** :
   - Log action/result/error.
   - Return results for CLI display.
7. **Cleanup** :
   - Exit with status based on errors/skips.

#### Next Steps
- **Testing** : Execute `test_all.py` for Syslog Collectors, validate logs. Pending tests for filtering, types, cross-check.
- **Deployment** : Push to GitHub, generate Windows binary with `auto-py-to-exe`.
- **Future Work** : Implement other fetchers if needed; add full GET for SyslogCollector if available in doc.

This document provides a complete blueprint for the Fetchers importer, covering all engineering details, specifications, and algorithms without requiring external sources. Updated with API extraction: conditional fields, list support, async monitoring.