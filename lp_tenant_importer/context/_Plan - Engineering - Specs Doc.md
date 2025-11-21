### Comprehensive Plan, Engineering, and Specifications Document for lp_tenant_importer Project

#### Date and Version
- **Date**: September 25, 2025, 03:11 PM CEST
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document serves as the sole reference for implementation.

#### Project Overview
The **lp_tenant_importer** project is a Python-based automation tool designed to synchronize configuration data for LogPoint Director tenants. It processes Excel (XLSX) files and YAML configurations, interfacing with the LogPoint Director API (version 2.7.0) to manage entities including Repositories (Repos), Routing Policies (RP), Normalization Policies (NP), Processing Policies (PP), Enrichment Policies (EP), Devices, Device Groups, and Alerts. The tool supports multiple tenants (e.g., 'core', 'esait', 'tia'), dry-run simulations, async job monitoring, and comprehensive logging, ensuring robustness and scalability for production environments.

#### Project Structure
The project follows a modular directory structure to separate concerns and facilitate maintenance:
```
lp_tenant_importer/
├── all_test_repos.py          # Script for testing repository imports
├── api-documentation.pdf      # API documentation (470 pages, v2.7.0)
├── config_loader.py           # Module to load .env and tenant YAML configurations
├── context/                   # Contextual documentation files
│   ├── context-grok 01.md
│   ├── context-grok.md
│   └── Context RP.md
├── core/                      # Core utility modules
│   ├── http.py               # HTTP client for API interactions
│   ├── http copy.py          # Backup of HTTP module
│   └── nodes.py              # Node (SIEM) management
├── importers/                 # Entity-specific import modules
│   ├── alerts.py             # Alert import logic
│   ├── enrichment_policies.py # Enrichment policy import logic
│   ├── enrichment_rules.py   # Enrichment rules (if separate, TBD)
│   ├── normalization_policies.py # Normalization policy import
│   ├── processing_policies.py # Processing policy import
│   ├── repos.py              # Repository import logic
│   └── routing_policies.py   # Routing policy import logic
├── logging_utils.py           # Logging configuration and utilities
├── main.py                    # Main CLI entry point and orchestrator
├── requirements.txt           # List of Python dependencies (e.g., pandas, requests)
├── samples/                   # Sample configuration files
│   ├── core_config.xlsx      # Main configuration file with all sheets
│   ├── esait_config.xlsx     # Tenant-specific configuration
│   ├── tenants.full.example.yaml # Full tenant configuration example
│   └── tenants.sample.yaml   # Minimal tenant configuration sample
├── test_all.py                # Comprehensive test suite for all importers
├── test_config.py             # Configuration test file
├── test_http.py               # HTTP test module
└── test_log/                  # Directory for log output files
    ├── create.log
    ├── log1.txt
    ├── Noop.log
    └── Update.log
```

#### General Modules

##### main.py
- **Purpose**: Acts as the command-line interface (CLI) entry point, coordinating subcommands for importing various entity types.
- **Functionality**: 
  - Uses `argparse` to define subcommands (e.g., `import-repos`, `import-routing-policies`, `import-enrichment-policies`) with arguments like `--dry-run`, `--xlsx`, and `--tenants`.
  - Initializes the `DirectorClient`, loads configuration and nodes, and delegates to importer functions.
- **Dependencies**: `core.http.DirectorClient`, `core.config_loader.load_config`, `core.nodes.load_nodes`, `importers.*`.
- **Key Logic**:
  1. Parse command-line arguments.
  2. Load tenant configuration from YAML and environment variables.
  3. Initialize node list and API client.
  4. Call the appropriate importer based on the subcommand.
  5. Display results and exit with status code (0 for success, 1 for error, 2 for skip with `--nonzero-on-skip`).
- **Implementation Notes**: Ensure subcommand handlers return results for logging and exit code determination.

##### config_loader.py
- **Purpose**: Handles loading and validation of configuration data from `.env` and tenant YAML files.
- **Functionality**:
  - Reads `LP_DIRECTOR_URL`, `LP_TOKEN`, and other settings from `.env.example`.
  - Parses `tenants.full.example.yaml` to extract `pool_uuid`, `siems` (e.g., `backends`, `search_heads`, `all_in_one`), and target mappings.
  - Validates file paths and merges default with tenant-specific configurations.
- **Dependencies**: `os`, `yaml`.
- **Key Logic**:
  1. Load `.env` variables using `os.environ` or a library like `python-dotenv`.
  2. Read YAML file and validate required fields (e.g., `pool_uuid`).
  3. Return a dictionary with configuration data, including node targets.
- **Implementation Notes**: Add error handling for missing files or invalid YAML.

##### http.py
- **Purpose**: Provides a centralized HTTP client for interacting with the LogPoint Director API.
- **Functionality**:
  - Implements `make_api_request` for generic GET/POST/PUT calls with authentication.
  - Includes `monitor_job` for async job tracking with retries.
  - Offers entity-specific methods (e.g., `get_enrichment_sources`, `create_enrichment_policy`) for EP.
- **Dependencies**: `requests`, `logging`, `time` (for retries).
- **Key Logic**:
  1. Initialize with `base_url` and `token` from config.
  2. Handle API requests with retries (e.g., 3 attempts, 2s delay).
  3. Monitor jobs with `monitor_job`, polling until `success: true` or timeout (30 attempts).
- **Implementation Notes**: Ensure `make_api_request` includes headers (`Authorization: Bearer {token}`, `Content-Type: application/json`).

##### logging_utils.py
- **Purpose**: Configures logging behavior across the application.
- **Functionality**:
  - Sets up logging levels (`DEBUG`, `INFO`, `WARNING`, `ERROR`) based on `LP_LOG_LEVEL`.
  - Supports JSON output if `LP_LOG_JSON` is true.
  - Enables verbose HTTP debugging (`LP_HTTP_DEBUG`) and full body logging (`LP_LOG_BODY_FULL`).
- **Dependencies**: `logging`, `json` (for JSON format).
- **Key Logic**:
  1. Configure root logger with file handler (e.g., `artifacts/logs/lp_importer.log`).
  2. Apply level filters and formatters based on environment variables.
- **Implementation Notes**: Ensure log rotation or size limits if logs grow large.

##### nodes.py
- **Purpose**: Manages the collection and validation of SIEM nodes.
- **Functionality**:
  - Retrieves nodes by role (`backends`, `search_heads`, `all_in_one`) from tenant YAML.
  - Handles `all_in_one` as a dual role (backend + search head).
- **Dependencies**: `core.config_loader`.
- **Key Logic**:
  1. Parse `siems` section from tenant config.
  2. Filter nodes by role, ensuring uniqueness.
- **Implementation Notes**: Add validation for node IDs and active status.

#### Importers
Each importer follows a consistent pattern: load XLSX data, validate prerequisites, fetch existing entities, apply actions, and monitor jobs.

##### repos.py
- **Specifications**:
  - Manages storage repositories (e.g., `Repo_system`, `Repo_cloud`) with multi-value fields.
- **API Endpoints**:
  - GET `/configapi/{pool_uuid}/{logpoint_id}/Repos`: Retrieves existing repositories.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/Repos`: Creates a new repository.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/Repos/{id}`: Updates an existing repository.
- **Payload Structure**:
  - CREATE/UPDATE:
    ```json
    {
        "data": {
            "name": "Repo_system",
            "storage_paths": [
                {"path": "/data_hot", "retention_days": 90},
                {"path": "/cold_nfs", "retention_days": 275}
            ],
            "active": true,
            "used_size": "11583.08301 MB"
        }
    }
    ```
- **XLS Structure**: `repo_number, original_repo_name, cleaned_repo_name, storage_paths, retention_days, active, used_size`.
- **Data Formatting and Import Logic**:
  1. Load XLSX sheet "Repo".
  2. Split `storage_paths` and `retention_days` by `|` into lists.
  3. Normalize `cleaned_repo_name` (remove tenant prefix, join with `_`).
  4. Fetch existing repos via GET `/Repos`.
  5. Validate storage paths (non-empty, valid retention).
  6. Compare with existing: NOOP if identical, SKIP if invalid, CREATE/UPDATE otherwise.
  7. Apply action with POST/PUT, monitor with `monitor_job`.
- **Prerequisite Checks via API**:
  - Check storage availability (TBD endpoint, assume GET `/storage`).
- **Status Handling and Payloads**:
  - **NOOP**: Identical config.
    - Payload: N/A (no action).
    - Log: `INFO: No action required for Repo_system on node1`.
  - **SKIP**: Missing storage or invalid data.
    - Payload: N/A.
    - Log: `WARNING: Skipping Repo_cloud due to missing storage path`.
  - **CREATE**: New repository.
    - Payload: As above with new `id`.
    - Log: `INFO: Created Repo_system on node1`.
  - **UPDATE**: Changed config.
    - Payload: Updated `storage_paths` or `retention_days`.
    - Log: `INFO: Updated Repo_system on node1`.
- **Error Logs**:
  - `ERROR: Failed to create Repo_system on node1: 500 Internal Server Error`.
  - `WARNING: Skipping due to invalid retention days`.
- **Algorithm**:
  1. Read "Repo" sheet into DataFrame.
  2. For each row, parse multi-value fields.
  3. Call `get_repos` to fetch current state.
  4. Validate prerequisites (storage paths).
  5. If existing, compare fields; if new, prepare payload.
  6. Execute POST/PUT, monitor job, log result.

##### routing_policies.py
- **Specifications**: Manages routing policies (e.g., `rp_windows`) with multi-line criteria.
- **API Endpoints**:
  - GET `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicy`: Lists policies.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicy/{id}`: Updates a policy.
- **Payload Structure**:
  - CREATE/UPDATE:
    ```json
    {
        "data": {
            "name": "rp_windows",
            "catch_all": "Repo_system",
            "routing_criteria": [
                {"rule_type": "KeyPresentValueMatches", "key": "event_source", "value": "Microsoft-Windows-Sysmon", "repo": "Repo_system", "drop": false}
            ],
            "policy_id": "65ba6dd9fe03d8eb8b99c0bc"
        }
    }
    ```
- **XLS Structure**: `original_policy_name, cleaned_policy_name, active, catch_all, rule_type, key, value, repo, drop, policy_id`.
- **Data Formatting and Import Logic**:
  1. Load "RoutingPolicy" sheet.
  2. Group rows by `cleaned_policy_name` using `groupby`.
  3. Collect `routing_criteria` from each group.
  4. Fetch existing policies via GET `/RoutingPolicy`.
  5. Validate `catch_all` and `repo` against Repos.
  6. Compare with existing: NOOP if identical, SKIP if invalid, CREATE/UPDATE otherwise.
  7. Apply action with POST/PUT, monitor with `monitor_job`.
- **Prerequisite Checks via API**:
  - Call `get_repos` to ensure `catch_all` and `repo` exist.
- **Status Handling and Payloads**:
  - **NOOP**: Identical policy configuration.
    - Payload: N/A.
    - Log: `INFO: Noop for rp_windows on node1`.
  - **SKIP**: Missing repo or no `catch_all`.
    - Payload: N/A.
    - Log: `WARNING: Skipping rp_cisco_amp due to missing Repo_system_expert`.
  - **CREATE**: New policy.
    - Payload: As above with new `policy_id`.
    - Log: `INFO: Created rp_fortinet on node1`.
  - **UPDATE**: Changed criteria.
    - Payload: Updated `routing_criteria`.
    - Log: `INFO: Updated rp_rsa on node1`.
- **Error Logs**:
  - `ERROR: Failed to update rp_windows on node1: 400 Bad Request`.
  - `WARNING: Inconsistent active field for rp_core_windows`.
- **Algorithm**:
  1. Read "RoutingPolicy" into DataFrame.
  2. Group by `cleaned_policy_name`.
  3. For each group, build `routing_criteria` list.
  4. Fetch existing policies.
  5. Check `catch_all` and `repo` prerequisites.
  6. Compare fields and criteria; decide action.
  7. Execute POST/PUT, monitor job, log outcome.

##### normalization_policies.py
- **Specifications**: Manages normalization policies (e.g., `np_windows`) with packages and compiled normalizers.
- **API Endpoints**:
  - GET `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy`: Lists policies.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy/{id}`: Updates a policy.
- **Payload Structure**:
  - CREATE/UPDATE:
    ```json
    {
        "data": {
            "name": "np_windows",
            "norm_packages": "",
            "compiled_normalizer": "WindowsSysmonCompiledNormalizer,LPA_Windows"
        }
    }
    ```
- **XLS Structure**: `policy_name, normalization_packages, compiled_normalizer`.
- **Data Formatting and Import Logic**:
  1. Load "NormalizationPolicy" sheet.
  2. Split `normalization_packages` and `compiled_normalizer` by `|` into comma-separated strings.
  3. Fetch existing policies via GET `/NormalizationPolicy`.
  4. Validate packages and normalizers against API (GET `/NormalizationPackage`).
  5. Compare with existing: NOOP if identical, SKIP if invalid, CREATE/UPDATE otherwise.
  6. Apply action with POST/PUT, monitor with `monitor_job`.
- **Prerequisite Checks via API**:
  - Call `get_normalization_packages` to verify `normalization_packages`.
  - Call `get_compiled_normalizers` to verify `compiled_normalizer`.
- **Status Handling and Payloads**:
  - **NOOP**: Identical configuration.
    - Payload: N/A.
    - Log: `INFO: Noop for np_windows on node1`.
  - **SKIP**: Missing packages or normalizers.
    - Payload: N/A.
    - Log: `WARNING: Skipping np_checkpoint due to missing LP_CheckPoint`.
  - **CREATE**: New policy.
    - Payload: As above with new `id`.
    - Log: `INFO: Created np_sanm on node1`.
  - **UPDATE**: Changed normalizers.
    - Payload: Updated `compiled_normalizer`.
    - Log: `INFO: Updated np_azure on node1`.
- **Error Logs**:
  - `ERROR: Failed to create np_windows on node1: 500`.
  - `WARNING: Skipping due to invalid normalizer`.
- **Algorithm**:
  1. Read "NormalizationPolicy" into DataFrame.
  2. Parse multi-value fields into strings.
  3. Fetch existing policies and available packages/normalizers.
  4. Validate prerequisites.
  5. Compare fields; decide action.
  6. Execute POST/PUT, monitor job, log result.

##### processing_policies.py
- **Specifications**: Manages processing policies (e.g., `pp_windows`) with dependencies on NP, EP, RP.
- **API Endpoints**:
  - GET `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`: Lists policies.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`: Updates a policy.
- **Payload Structure**:
  - CREATE/UPDATE:
    ```json
    {
        "data": {
            "name": "pp_windows",
            "norm_policy": "np_windows",
            "enrich_policy": "None",
            "routing_policy": "rp_windows",
            "id": "64f9ded28e9b8f289b079f715b02651e8"
        }
    }
    ```
- **XLS Structure**: `original_policy_name, cleaned_policy_name, active, norm_policy, enrich_policy, routing_policy_id, policy_id`.
- **Data Formatting and Import Logic**:
  1. Load "ProcessingPolicy" sheet.
  2. Map `norm_policy`, `enrich_policy`, `routing_policy_id` to IDs via API lookups.
  3. Fetch existing policies via GET `/ProcessingPolicy`.
  4. Validate dependencies (NP, EP, RP) against their respective APIs.
  5. Compare with existing: NOOP if identical, SKIP if invalid, CREATE/UPDATE otherwise.
  6. Apply action with POST/PUT, monitor with `monitor_job`.
- **Prerequisite Checks via API**:
  - Call `get_normalization_policies` to validate `norm_policy`.
  - Call `get_enrichment_policies` to validate `enrich_policy`.
  - Call `get_routing_policies` to validate `routing_policy_id`.
- **Status Handling and Payloads**:
  - **NOOP**: Identical configuration.
    - Payload: N/A.
    - Log: `INFO: Noop for pp_windows on node1`.
  - **SKIP**: Invalid dependency (e.g., missing `norm_policy`).
    - Payload: N/A.
    - Log: `WARNING: Skipping pp_cisco_amp due to invalid norm_policy`.
  - **CREATE**: New policy.
    - Payload: As above with new `id`.
    - Log: `INFO: Created pp_rsa on node1`.
  - **UPDATE**: Changed dependency.
    - Payload: Updated `routing_policy`.
    - Log: `INFO: Updated pp_core_rsa on node1`.
- **Error Logs**:
  - `ERROR: Failed to update pp_windows on node1: 400`.
  - `WARNING: Skipping due to missing enrich_policy`.
- **Algorithm**:
  1. Read "ProcessingPolicy" into DataFrame.
  2. Map source IDs to target IDs via API lookups.
  3. Fetch existing policies.
  4. Validate prerequisites.
  5. Compare fields; decide action.
  6. Execute POST/PUT, monitor job, log outcome.

##### enrichment_policies.py
- **Specifications**: Manages enrichment policies (e.g., `Threat_Intelligence`) with multi-spec `rules` and `criteria`.
- **API Endpoints**:
  - GET `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy`: Lists policies.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy/{id}`: Updates a policy.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentSource`: Validates sources.
- **Payload Structure**:
  - **CREATE**:
    ```json
    {
        "data": {
            "name": "Threat_Intelligence",
            "description": "",
            "specifications": [
                {
                    "source": "threat_intelligence",
                    "rules": [
                        {
                            "category": "simple",
                            "source_key": "ip_address",
                            "prefix": false,
                            "operation": "Equals",
                            "type": "ip",
                            "event_key": "source_address"
                        }
                    ],
                    "criteria": [
                        {
                            "type": "KeyPresents",
                            "key": "source_address",
                            "value": "found"
                        },
                        {
                            "type": "KeyPresents",
                            "key": "destination_address",
                            "value": "found"
                        }
                    ]
                }
            ]
        }
    }
    ```
  - **UPDATE**:
    ```json
    {
        "data": {
            "id": "62dcc0c3f1fa2022ab0872e7",
            "name": "Threat_Intelligence",
            "description": "",
            "specifications": [
                {
                    "source": "threat_intelligence",
                    "rules": [...],
                    "criteria": [...]
                }
            ]
        }
    }
    ```
- **XLS Structure**:
  - `EnrichmentPolicy`: `spec_index, policy_name, description, tags, active, source, policy_id`.
  - `EnrichmentRules`: `policy_name, source, spec_index, category, source_key, prefix, operation, type, event_key`.
  - `EnrichmentCriteria`: `policy_name, source, spec_index, type, key, value`.
- **Data Formatting and Import Logic**:
  1. Load "EnrichmentPolicy", "EnrichmentRules", "EnrichmentCriteria" sheets.
  2. Group rows by `policy_name` and `spec_index` using `groupby`.
  3. Build `specifications` list with `rules` and `criteria` per `spec_index`.
  4. Fetch available sources via GET `/EnrichmentSource` per node.
  5. Fetch existing policies via GET `/EnrichmentPolicy`.
  6. Validate `source` against fetched sources.
  7. Compare with existing: NOOP if identical, SKIP if invalid, CREATE/UPDATE otherwise.
  8. Apply action with POST/PUT, monitor with `monitor_job`.
- **Prerequisite Checks via API**:
  - Call `get_enrichment_sources` to validate each `source` per node.
- **Status Handling and Payloads**:
  - **NOOP**: Identical configuration (name, description, specifications).
    - Payload: N/A.
    - Log: `INFO: No changes needed for Threat_Intelligence on node1`.
  - **SKIP**: Missing source or invalid data (e.g., no rules/criteria).
    - Payload: N/A.
    - Log: `WARNING: Skipping GeoIp on node1 due to missing source`.
  - **CREATE**: New policy with valid source.
    - Payload: As above with new `id`.
    - Log: `INFO: Created UEBA_ENRICHMENT_POLICY on node1`.
  - **UPDATE**: Changed specifications.
    - Payload: Updated `specifications`.
    - Log: `INFO: Updated Threat_Intelligence on node1`.
- **Error Logs**:
  - `ERROR: Failed to create Threat_Intelligence on node1: 500`.
  - `WARNING: Skipping due to inconsistent spec_index`.
- **Algorithm**:
  1. Read all three sheets into DataFrames.
  2. Group `EnrichmentRules` and `EnrichmentCriteria` by `policy_name` and `spec_index`.
  3. For each `policy_name` in "EnrichmentPolicy":
     - Build `specifications` list from grouped data.
     - Fetch `available_sources` per node.
     - Validate `source` presence.
     - Fetch `existing_policies`.
     - Compare `description` and `specifications` (serialized for set comparison).
     - If existing and identical: NOOP.
     - If existing and different: UPDATE with `policy_id`.
     - If new and valid: CREATE.
     - Monitor job with `monitor_job`, log result.

##### alerts.py
- **Specifications**: Manages alerts with complex settings.
- **API Endpoints**: (TBD from pages 7-42, e.g., POST `/configapi/{pool_uuid}/{logpoint_id}/AlertRules`).
- **Payload Structure**: (TBD, e.g., `{"data": {"name": "alert1", "settings": {...}}}`).
- **XLS Structure**: `alert_index, name, settings.active, settings.description, ...`.
- **Data Formatting and Import Logic**: (TBD).
- **Prerequisite Checks via API**: (TBD).
- **Status Handling and Payloads**: (TBD).
- **Error Logs**: (TBD).
- **Algorithm**: (TBD).

#### Data Formatting and API Import
- **XLS Processing**: Use `pandas.read_excel` with `skiprows=0` to load sheets. Handle multi-value fields (e.g., `|` split) and group data where applicable (e.g., RP criteria, EP specs).
- **API Integration**: Fetch existing entities with GET, validate prerequisites, construct payloads dynamically, and apply changes with POST/PUT. Use `monitor_job` for async completion.
- **Payload Construction**: Ensure required fields (e.g., `name`, `specifications` for EP) are present, serialize complex structures (e.g., `specifications`) for comparison.

#### Import Algorithm (Detailed)
1. **Initialization**:
   - Load `config_loader.py` to get `pool_uuid`, `nodes`, and `targets` from YAML and `.env`.
   - Initialize `DirectorClient` with `base_url` and `token`.
2. **Data Loading**:
   - Read XLSX sheet(s) into `pandas.DataFrame`.
   - Parse multi-value fields (e.g., split by `|`).
   - Group data by key fields (e.g., `cleaned_policy_name` for RP, `policy_name`/`spec_index` for EP).
3. **Prerequisite Checks**:
   - For each node in `targets`, fetch existing entities via GET (e.g., `/Repos`, `/EnrichmentSource`).
   - Validate dependencies (e.g., repo existence for RP, source availability for EP).
4. **Data Comparison**:
   - Serialize current and existing data (e.g., JSON dumps for sets).
   - Compare fields: if identical, NOOP; if different, prepare for UPDATE; if new, prepare for CREATE.
5. **Action Execution**:
   - If `dry_run`, log simulated action.
   - Otherwise, construct payload and call POST/PUT via `http.py` methods.
   - Monitor job with `monitor_job`, polling until success or failure (max 30 attempts, 2s interval).
6. **Result Logging**:
   - Record `siem`, `node`, `name`, `action`, `result`, `error` in a list.
   - Log at appropriate level (DEBUG for details, INFO for success, WARNING for skips, ERROR for failures).
7. **Cleanup**:
   - Return results and error flag.
   - Exit with status code based on `has_error` and `--nonzero-on-skip`.

#### Next Steps
- **Testing**: Execute `test_all.py` for each importer, validate logs and exit codes.
- **Deployment**: Push to GitHub, generate Windows binary with `auto-py-to-exe`.
- **Future Work**: Implement `alerts.py` using API doc pages 7-42.

This document provides a complete blueprint for implementing the `lp_tenant_importer` tool, covering all engineering details, specifications, and algorithms without requiring external sources.