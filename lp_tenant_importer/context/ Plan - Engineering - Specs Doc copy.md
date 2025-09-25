### Comprehensive Plan, Engineering, and Specifications Document for lp_tenant_importer Project (Updated)

#### Date and Version
- **Date**: September 25, 2025, 03:27 PM CEST
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document is the sole reference for implementation.

#### Project Overview
The **lp_tenant_importer** project is a Python-based automation tool designed to synchronize configuration data for LogPoint Director tenants. It processes Excel (XLSX) files and YAML configurations, interfacing with the LogPoint Director API (version 2.7.0) to manage entities including Repositories (Repos), Routing Policies (RP), Normalization Policies (NP), Processing Policies (PP), Enrichment Policies (EP), Devices, Device Groups, and Alerts. The tool supports multiple tenants (e.g., 'core', 'esait', 'tia'), dry-run simulations, async job monitoring via monitorAPI, and comprehensive logging, ensuring robustness and scalability for production environments.

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
  - Uses `argparse` to define subcommands (e.g., `import-repos`, `import-enrichment-policies`) with arguments like `--dry-run`, `--xlsx`, and `--tenants`.
  - Initializes the `DirectorClient`, loads configuration and nodes, and delegates to importer functions.
  - Displays results and exits with status codes (0 for success, 1 for error, 2 for skip with `--nonzero-on-skip`).
- **Dependencies**: `core.http.DirectorClient`, `core.config_loader.load_config`, `core.nodes.load_nodes`, `importers.*`.
- **Key Logic**:
  1. Parse command-line arguments using `argparse`.
  2. Load tenant configuration from `tenants.sample.yaml` and environment variables from `.env.example`.
  3. Initialize `DirectorClient` with `base_url` and `token`.
  4. Load node list from `nodes.py` based on `targets` (e.g., `backends`, `all_in_one`).
  5. Call the appropriate importer function (e.g., `import_enrichment_policies_for_nodes`).
  6. Process results, log them, and set exit code based on `has_error` and skip conditions.
- **Implementation Notes**: Ensure subcommand handlers return a tuple of (results list, error flag). Add error handling for missing arguments or config files.

##### config_loader.py
- **Purpose**: Handles loading and validation of configuration data from `.env` and tenant YAML files.
- **Functionality**:
  - Reads `LP_DIRECTOR_URL` (e.g., `https://10.160.144.185`), `LP_TOKEN`, and other settings from `.env.example`.
  - Parses `tenants.full.example.yaml` to extract `pool_uuid` (e.g., `a9fa7661c4f84b278b136e94a86b4ea2`), `siems` (e.g., `backends`, `search_heads`), and target mappings.
  - Validates file paths and merges default settings with tenant-specific overrides.
- **Dependencies**: `os`, `yaml`.
- **Key Logic**:
  1. Use `os.getenv` or `python-dotenv` to load `.env` variables, raising `ValueError` if `LP_DIRECTOR_URL` or `LP_TOKEN` is missing.
  2. Open and parse YAML file with `yaml.safe_load`, checking for `tenants` and `pool_uuid`.
  3. Return a dictionary with `base_url`, `token`, `pool_uuid`, and `targets` (e.g., `{'backends': [...], 'all_in_one': [...]}`).
- **Implementation Notes**: Add logging for config load success/failure. Handle file not found with `FileNotFoundError`.

##### http.py
- **Purpose**: Provides a centralized HTTP client for interacting with the LogPoint Director API.
- **Functionality**:
  - Implements `make_api_request` for generic GET/POST/PUT calls with authentication and retries.
  - Includes `monitor_job` for async job tracking with a maximum of 30 attempts and 2-second intervals.
  - Offers entity-specific methods (e.g., `get_enrichment_sources`, `create_enrichment_policy`) with async monitoring.
- **Dependencies**: `requests`, `logging`, `time` (for retries).
- **Key Logic**:
  1. Initialize with `base_url` and `token` from config, setting headers (`Authorization: Bearer {token}`, `Content-Type: application/json`).
  2. `make_api_request`: Send request with 3 retries on `ConnectionError`, logging each attempt.
  3. `monitor_job`: Poll `/monitorapi/{job_path}` until `success: true` or timeout, logging status.
  4. Entity methods: Wrap `make_api_request` with specific URLs and handle async responses.
- **Implementation Notes**: Ensure `monitor_job` returns `True`/`False` based on job success. Add timeout configuration (e.g., 60s total).

##### logging_utils.py
- **Purpose**: Configures logging behavior across the application.
- **Functionality**:
  - Sets up logging levels (`DEBUG`, `INFO`, `WARNING`, `ERROR`) based on `LP_LOG_LEVEL` (default `DEBUG`).
  - Supports JSON output if `LP_LOG_JSON` is `true`, with fields like `timestamp`, `level`, `message`.
  - Enables verbose HTTP debugging (`LP_HTTP_DEBUG`) and full body logging (`LP_LOG_BODY_FULL`) with sanitization for secrets.
- **Dependencies**: `logging`, `json`, `os`.
- **Key Logic**:
  1. Configure root logger with `FileHandler` to `artifacts/logs/lp_importer.log`.
  2. Set level from `LP_LOG_LEVEL`, defaulting to `logging.DEBUG`.
  3. Apply `JSONFormatter` if `LP_LOG_JSON` is `true`, otherwise use plain text.
  4. Add filters for `LP_HTTP_DEBUG` and `LP_LOG_BODY_FULL`.
- **Implementation Notes**: Implement log rotation (e.g., `RotatingFileHandler` with 10MB max size).

##### nodes.py
- **Purpose**: Manages the collection and validation of SIEM nodes.
- **Functionality**:
  - Retrieves nodes by role (`backends`, `search_heads`, `all_in_one`) from `siems` in tenant YAML.
  - Handles `all_in_one` as a dual role, ensuring no duplicate IDs.
- **Dependencies**: `core.config_loader`.
- **Key Logic**:
  1. Access `config['siems']` from loaded config.
  2. Filter nodes by `active` status and role, building lists for each target.
  3. Validate `id` and `name` uniqueness.
- **Implementation Notes**: Raise `ValueError` if duplicate IDs detected.

#### Importers
Each importer follows a consistent pattern: load XLSX data, validate prerequisites, fetch existing entities, apply actions, and monitor jobs.

##### repos.py
- **Specifications**: Manages storage repositories with multi-value `storage_paths` and `retention_days`.
- **API Endpoints**:
  - GET `/configapi/{pool_uuid}/{logpoint_id}/Repos`: Retrieves existing repositories.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/Repos`: Creates a new repository.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/Repos/{id}`: Updates an existing repository.
- **Payload Structure**:
  - **CREATE**:
    ```json
    {
        "data": {
            "name": "Repo_core_system",
            "storage_paths": [
                {"path": "/data_hot", "retention_days": 90},
                {"path": "/cold_nfs", "retention_days": 275}
            ],
            "active": true,
            "used_size": "11583.08301 MB"
        }
    }
    ```
  - **UPDATE**:
    ```json
    {
        "data": {
            "id": "4",
            "name": "Repo_core_system",
            "storage_paths": [
                {"path": "/data_hot", "retention_days": 90}
            ],
            "active": true,
            "used_size": "11583.08301 MB"
        }
    }
    ```
- **XLS Structure**: `repo_number, original_repo_name, cleaned_repo_name, storage_paths, retention_days, active, used_size`.
- **Data Formatting and Import Logic**:
  1. Load "Repo" sheet into a `pandas.DataFrame`.
  2. Split `storage_paths` and `retention_days` by `|` into lists of dictionaries.
  3. Normalize `cleaned_repo_name` by removing tenant prefix and joining with `_`.
  4. Fetch existing repositories via `get_repos` (GET `/Repos`).
  5. Validate each `storage_paths` entry (non-empty path, positive `retention_days`).
  6. Compare with existing: NOOP if all fields match, SKIP if invalid, CREATE/UPDATE otherwise.
  7. Construct payload and call `create_repos` or `update_repos`, monitor with `monitor_job`.
- **Prerequisite Checks via API**:
  - Call `get_storage_status` (hypothetical endpoint) to ensure paths are accessible.
- **Status Handling and Payloads**:
  - **NOOP**: All fields (name, storage_paths, retention_days, active, used_size) match.
    - Payload: N/A.
    - Log: `INFO: No action required for Repo_core_system on node1`.
  - **SKIP**: Missing or invalid `storage_paths` or negative `retention_days`.
    - Payload: N/A.
    - Log: `WARNING: Skipping Repo_core_cloud due to invalid retention_days`.
  - **CREATE**: No matching `name` found, valid data.
    - Payload: As above with new `id`.
    - Log: `INFO: Created Repo_core_system on node1`.
  - **UPDATE**: Existing `id` with differing `storage_paths` or `retention_days`.
    - Payload: As above with updated fields.
    - Log: `INFO: Updated Repo_core_system on node1`.
- **Async Monitoring Process**:
  - After POST/PUT, extract `job_path` from response (e.g., `/monitorapi/{pool_uuid}/{logpoint_id}/orders/{request_id}`).
  - Call `monitor_job(job_path)` with 30 attempts, 2-second intervals.
  - Check `success` field; log `INFO` if `true`, `ERROR` if `false` or timeout.
- **Error Logs**:
  - `ERROR: Failed to create Repo_core_system on node1: 500 Internal Server Error`.
  - `WARNING: Skipping due to missing storage path on node1`.
- **Algorithm**:
  1. Initialize `client` and `nodes` from `main.py`.
  2. Read "Repo" sheet, parse multi-value fields into lists.
  3. For each row, normalize `cleaned_repo_name`.
  4. Fetch existing repos with `get_repos`.
  5. Validate `storage_paths` (non-empty, positive retention).
  6. If existing, compare all fields; if new, validate data.
  7. Construct payload, call `create_repos` or `update_repos`.
  8. Monitor job with `monitor_job`, log result (success/failure).

##### routing_policies.py
- **Specifications**: Manages routing policies with multi-line `routing_criteria`.
- **API Endpoints**:
  - GET `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicy`: Lists policies.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicy/{id}`: Updates a policy.
- **Payload Structure**:
  - **CREATE**:
    ```json
    {
        "data": {
            "name": "rp_core_windows",
            "catch_all": "Repo_core_system",
            "routing_criteria": [
                {
                    "rule_type": "KeyPresentValueMatches",
                    "key": "event_source",
                    "value": "Microsoft-Windows-Sysmon",
                    "repo": "Repo_core_system_verbose",
                    "drop": false
                },
                {
                    "rule_type": "KeyPresentValueMatches",
                    "key": "event_source",
                    "value": "Microsoft-Defender",
                    "repo": "Repo_core_cloud",
                    "drop": true
                }
            ],
            "policy_id": "64f9de0f49a44cde2b327502"
        }
    }
    ```
  - **UPDATE**:
    ```json
    {
        "data": {
            "id": "64f9de0f49a44cde2b327502",
            "name": "rp_core_windows",
            "catch_all": "Repo_core_system",
            "routing_criteria": [
                {
                    "rule_type": "KeyPresentValueMatches",
                    "key": "event_source",
                    "value": "Microsoft-Windows-Sysmon",
                    "repo": "Repo_core_system_verbose",
                    "drop": false
                }
            ],
            "policy_id": "64f9de0f49a44cde2b327502"
        }
    }
    ```
- **XLS Structure**: `original_policy_name, cleaned_policy_name, active, catch_all, rule_type, key, value, repo, drop, policy_id`.
- **Data Formatting and Import Logic**:
  1. Load "RoutingPolicy" sheet into a `pandas.DataFrame`.
  2. Group rows by `cleaned_policy_name` using `groupby`.
  3. For each group, collect `routing_criteria` into a list (rule_type, key, value, repo, drop).
  4. Fetch existing policies via GET `/RoutingPolicy`.
  5. Validate `catch_all` and `repo` against `get_repos`.
  6. Compare with existing: NOOP if identical, SKIP if invalid, CREATE/UPDATE otherwise.
  7. Construct payload and call `create_routing_policy` or `update_routing_policy`, monitor with `monitor_job`.
- **Prerequisite Checks via API**:
  - Call `get_repos` to ensure `catch_all` and `repo` exist.
- **Status Handling and Payloads**:
  - **NOOP**: Matching `name`, `catch_all`, and `routing_criteria`.
    - Payload: N/A.
    - Log: `INFO: No action required for rp_core_windows on node1`.
  - **SKIP**: Missing `catch_all` or `repo`, or inconsistent `active`.
    - Payload: N/A.
    - Log: `WARNING: Skipping rp_core_cisco_amp due to missing Repo_core_system_expert`.
  - **CREATE**: No matching `name` found, valid data.
    - Payload: As above with new `policy_id`.
    - Log: `INFO: Created rp_core_fortinet on node1`.
  - **UPDATE**: Existing `policy_id` with differing `routing_criteria`.
    - Payload: As above with updated criteria.
    - Log: `INFO: Updated rp_core_rsa on node1`.
- **Async Monitoring Process**:
  - Extract `job_path` from POST/PUT response (e.g., `/monitorapi/{pool_uuid}/{logpoint_id}/orders/{request_id}`).
  - Call `monitor_job(job_path)` with 30 attempts, 2s delay per attempt (max 60s).
  - Poll API, check `success` field; log `INFO` if `true`, `ERROR` if `false` or timeout.
- **Error Logs**:
  - `ERROR: Failed to update rp_core_windows on node1: 400 Bad Request`.
  - `WARNING: Skipping due to missing catch_all on node1`.
- **Algorithm**:
  1. Load "RoutingPolicy" sheet.
  2. Group by `cleaned_policy_name`, build `routing_criteria` list.
  3. Fetch existing policies with `get_routing_policies`.
  4. Validate `catch_all` and `repo` via `get_repos`.
  5. Compare `catch_all` and `routing_criteria`; decide action.
  6. Construct payload, call `create_routing_policy` or `update_routing_policy`.
  7. Monitor job with `monitor_job`, log success or failure.

##### normalization_policies.py
- **Specifications**: Manages normalization policies with packages and compiled normalizers.
- **API Endpoints**:
  - GET `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy`: Lists policies.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy/{id}`: Updates a policy.
- **Payload Structure**:
  - **CREATE**:
    ```json
    {
        "data": {
            "name": "np_windows",
            "norm_packages": "",
            "compiled_normalizer": "WindowsSysmonCompiledNormalizer,LPA_Windows"
        }
    }
    ```
  - **UPDATE**:
    ```json
    {
        "data": {
            "id": "np_windows_id",
            "name": "np_windows",
            "norm_packages": "",
            "compiled_normalizer": "WindowsSysmonCompiledNormalizer"
        }
    }
    ```
- **XLS Structure**: `policy_name, normalization_packages, compiled_normalizer`.
- **Data Formatting and Import Logic**:
  1. Load "NormalizationPolicy" sheet into a `pandas.DataFrame`.
  2. Split `normalization_packages` and `compiled_normalizer` by `|` into comma-separated strings.
  3. Fetch existing policies via GET `/NormalizationPolicy`.
  4. Validate packages and normalizers against API (GET `/NormalizationPackage`, GET `/CompiledNormalizer`).
  5. Compare with existing: NOOP if identical, SKIP if invalid, CREATE/UPDATE otherwise.
  6. Construct payload and call `create_normalization_policy` or `update_normalization_policy`, monitor with `monitor_job`.
- **Prerequisite Checks via API**:
  - Call `get_normalization_packages` to verify `normalization_packages`.
  - Call `get_compiled_normalizers` to verify `compiled_normalizer`.
- **Status Handling and Payloads**:
  - **NOOP**: Matching `name`, `norm_packages`, and `compiled_normalizer`.
    - Payload: N/A.
    - Log: `INFO: No action required for np_windows on node1`.
  - **SKIP**: Missing or invalid `normalization_packages` or `compiled_normalizer`.
    - Payload: N/A.
    - Log: `WARNING: Skipping np_checkpoint due to missing LP_CheckPoint`.
  - **CREATE**: No matching `name` found, valid data.
    - Payload: As above with new `id`.
    - Log: `INFO: Created np_sanm on node1`.
  - **UPDATE**: Existing `id` with differing `compiled_normalizer`.
    - Payload: As above with updated fields.
    - Log: `INFO: Updated np_azure on node1`.
- **Async Monitoring Process**:
  - Extract `job_path` from response.
  - Call `monitor_job(job_path)` with 30 attempts, 2s delay (max 60s).
  - Check `success`; log `INFO` if `true`, `ERROR` if `false` or timeout.
- **Error Logs**:
  - `ERROR: Failed to create np_windows on node1: 500`.
  - `WARNING: Skipping due to invalid normalizer on node1`.
- **Algorithm**:
  1. Load "NormalizationPolicy" sheet.
  2. Parse multi-value fields into strings.
  3. Fetch existing policies and available packages/normalizers.
  4. Validate prerequisites via API.
  5. Compare fields; decide action.
  6. Construct payload, call `create_normalization_policy` or `update_normalization_policy`.
  7. Monitor job, log result.

##### processing_policies.py
- **Specifications**: Manages processing policies with dependencies on NP, EP, RP.
- **API Endpoints**:
  - GET `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`: Lists policies.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`: Updates a policy.
- **Payload Structure**:
  - **CREATE**:
    ```json
    {
        "data": {
            "name": "pp_core_windows",
            "norm_policy": "np_windows",
            "enrich_policy": "None",
            "routing_policy": "rp_core_windows",
            "id": "64f9ded28e8df427ea06b3de"
        }
    }
    ```
  - **UPDATE**:
    ```json
    {
        "data": {
            "id": "64f9ded28e8df427ea06b3de",
            "name": "pp_core_windows",
            "norm_policy": "np_windows",
            "enrich_policy": "62dcc0c3f1fa2022ab0872e7",
            "routing_policy": "rp_core_windows"
        }
    }
    ```
- **XLS Structure**: `original_policy_name, cleaned_policy_name, active, norm_policy, enrich_policy, routing_policy_id, policy_id`.
- **Data Formatting and Import Logic**:
  1. Load "ProcessingPolicy" sheet into a `pandas.DataFrame`.
  2. Map `norm_policy`, `enrich_policy`, and `routing_policy_id` to their respective IDs via API lookups.
  3. Fetch existing policies via GET `/ProcessingPolicy`.
  4. Validate dependencies against `get_normalization_policies`, `get_enrichment_policies`, and `get_routing_policies`.
  5. Compare with existing: NOOP if identical, SKIP if invalid, CREATE/UPDATE otherwise.
  6. Construct payload and call `create_processing_policy` or `update_processing_policy`, monitor with `monitor_job`.
- **Prerequisite Checks via API**:
  - Call `get_normalization_policies` to validate `norm_policy`.
  - Call `get_enrichment_policies` to validate `enrich_policy`.
  - Call `get_routing_policies` to validate `routing_policy_id`.
- **Status Handling and Payloads**:
  - **NOOP**: Matching `name`, `norm_policy`, `enrich_policy`, and `routing_policy`.
    - Payload: N/A.
    - Log: `INFO: No action required for pp_core_windows on node1`.
  - **SKIP**: Invalid or missing dependency (e.g., `norm_policy` not found).
    - Payload: N/A.
    - Log: `WARNING: Skipping pp_core_cisco_amp due to invalid norm_policy`.
  - **CREATE**: No matching `name` found, valid data.
    - Payload: As above with new `id`.
    - Log: `INFO: Created pp_core_rsa on node1`.
  - **UPDATE**: Existing `id` with differing `enrich_policy`.
    - Payload: As above with updated fields.
    - Log: `INFO: Updated pp_core_rsa on node1`.
- **Async Monitoring Process**:
  - Extract `job_path` from response.
  - Call `monitor_job(job_path)` with 30 attempts, 2s delay (max 60s).
  - Check `success`; log `INFO` if `true`, `ERROR` if `false` or timeout.
- **Error Logs**:
  - `ERROR: Failed to update pp_core_windows on node1: 400`.
  - `WARNING: Skipping due to missing enrich_policy on node1`.
- **Algorithm**:
  1. Load "ProcessingPolicy" sheet.
  2. Map source names to IDs via API lookups.
  3. Fetch existing policies.
  4. Validate prerequisites via API.
  5. Compare fields; decide action.
  6. Construct payload, call `create_processing_policy` or `update_processing_policy`.
  7. Monitor job, log result.

##### enrichment_policies.py
- **Specifications**: Manages enrichment policies with multi-spec `rules` and `criteria`.
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
                        }
                    ]
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
  1. Load "EnrichmentPolicy", "EnrichmentRules", "EnrichmentCriteria" sheets into `pandas.DataFrame`.
  2. Group `EnrichmentRules` and `EnrichmentCriteria` by `policy_name` and `spec_index` using `groupby`.
  3. For each `policy_name` in "EnrichmentPolicy", build a `specifications` list from grouped data.
  4. Fetch available sources per node via GET `/EnrichmentSource`.
  5. Fetch existing policies via GET `/EnrichmentPolicy`.
  6. Validate each `source` against fetched sources.
  7. Compare with existing: NOOP if identical, SKIP if invalid, CREATE/UPDATE otherwise.
  8. Construct payload and call `create