## Comprehensive Plan, Engineering, and Specifications Document for Repos in lp_tenant_importer Project

#### Date and Version
- **Date**: September 26, 2025
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document focuses on the Repos importer and serves as the sole reference for its implementation.

#### Overview
The **Repos** importer is a Python-based module within the `lp_tenant_importer` project, designed to synchronize repository configurations from the "Repo" sheet in Excel (XLSX) files with the LogPoint Director API (version 2.7.0). It handles creation, updating, listing, and monitoring of repositories across multiple tenants (e.g., 'core'). The importer supports multi-value fields like `storage_paths` and `retention_days`, dry-run simulations, async job monitoring, and comprehensive logging. Repos are foundational and have no dependencies on other entities.

#### Project Structure (Relevant to Repos)
The structure is modular, with Repos integrated as follows:
```
lp_tenant_importer/
├── main.py                    # CLI entry point, adds subcommand `import-repos`
├── config_loader.py           # Loads .env and YAML for pool_uuid, nodes
├── core/
│   ├── http.py               # API client with methods for Repos (e.g., create_repo, update_repo)
│   └── nodes.py              # Node management (backends, all_in_one for Repos targets)
├── importers/
│   ├── repos.py              # Repos import logic
├── logging_utils.py           # Logging setup
├── samples/
│   ├── core_config.xlsx      # Contains "Repo" sheet
├── tenants.full.example.yaml  # Tenant config with targets
```

#### General Modules (Relevant Updates)
##### main.py
- **Purpose** : CLI entry point, adds subcommand `import-repos` with arguments `--dry-run`, `--xlsx`, `--tenants`.
- **Functionality** : Initializes `DirectorClient`, loads config and nodes, delegates to `importers.repos.import_repos_for_nodes`.
- **Key Logic** :
  1. Parse arguments.
  2. Load tenant config.
  3. Call importer.
  4. Display results in table/JSON, exit with status (0 success, 1 error, 2 skip).

##### http.py
- **Purpose** : HTTP client for API interactions.
- **Methods for Repos** :
  - `get_repos(pool_uuid, logpoint_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/Repos
  - `get_repo(pool_uuid, logpoint_id, id)`: GET /configapi/{pool_uuid}/{logpoint_id}/Repos/{id}
  - `create_repo(pool_uuid, logpoint_id, payload)`: POST /configapi/{pool_uuid}/{logpoint_id}/Repos
  - `update_repo(pool_uuid, logpoint_id, id, payload)`: PUT /configapi/{pool_uuid}/{logpoint_id}/Repos/{id}
  - `delete_repo(pool_uuid, logpoint_id, id)`: DELETE /configapi/{pool_uuid}/{logpoint_id}/Repos/{id}
- **Key Logic** : Handle requests with auth, retries (3 attempts, 2s delay), monitor async jobs via `monitor_job` (poll until `success: true/false`, max 30 attempts, 2s interval).

##### logging_utils.py
- **Purpose** : Logging configuration.
- **Functionality** : Levels (DEBUG/INFO/WARNING/ERROR), JSON output optional, verbose HTTP debugging.

##### nodes.py
- **Purpose** : Manages SIEM nodes by role (backends, all_in_one for Repos targets).

#### Importers
##### repos.py
- **Specifications** : Manages storage repositories (e.g., `Repo_system`, `Repo_cloud`) with multi-value fields. No dependencies.
- **API Endpoints** (from LogPoint Director API v2.7.0, relevant sections):
  - GET `/configapi/{pool_uuid}/{logpoint_id}/Repos`: Lists all repositories.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/Repos/{id}`: Fetches a repository.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/Repos`: Creates a repository.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/Repos/{id}`: Updates a repository.
  - DELETE `/configapi/{pool_uuid}/{logpoint_id}/Repos/{id}`: Deletes a repository.
- **Payload Structure** :
  - **CREATE** :
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
  - **UPDATE** :
    ```json
    {
      "data": {
        "name": "Repo_system",
        "storage_paths": [
          {"path": "/data_hot", "retention_days": 90},
          {"path": "/cold_nfs", "retention_days": 275}
        ],
        "active": true,
        "used_size": "11583.08301 MB",
        "id": "existing_id"
      }
    }
    ```
- **XLS Structure** : `repo_number, original_repo_name, cleaned_repo_name, storage_paths, retention_days, active, used_size`.
- **Data Formatting and Import Logic** :
  1. Load "Repo" sheet with `pandas.read_excel`.
  2. Parse multi-values: Split `storage_paths` and `retention_days` by `|` to build list of dicts.
  3. Fetch existing repositories via GET `/Repos` per node.
  4. Compare: NOOP if identical (name, storage_paths serialized, active, used_size), UPDATE if different (use ID if available), CREATE if new.
  5. Execute POST/PUT, monitor job, log outcome.
- **Prerequisite Checks via API** :
  - No dependencies; validate storage paths format.
- **Status Handling and Payloads** :
  - **NOOP**: Identical configuration.
    - Payload: N/A.
    - Log: `INFO: No changes needed for Repo_system on lb-backend01`.
  - **SKIP**: Invalid data (e.g., mismatched paths/retentions).
    - Payload: N/A.
    - Log: `WARNING: Skipping Repo_system on lb-backend01 due to invalid storage paths`.
  - **CREATE**: New repository.
    - Payload: As above.
    - Log: `INFO: Created Repo_system on lb-backend01`.
  - **UPDATE**: Changed fields (e.g., retention_days).
    - Payload: Updated fields.
    - Log: `INFO: Updated Repo_system on lb-backend01`.
- **Error Logs** :
  - `ERROR: Failed to create Repo_system on lb-backend01: 400`.
  - `WARNING: Skipping due to inconsistent paths/retentions`.
- **Algorithm** :
  1. Read "Repo" into DataFrame.
  2. For each node in targets:
     - Fetch existing repos via GET `/Repos`.
     - For each row in DataFrame:
       - Build payload (parse multi-values to list of dicts).
       - Validate fields (e.g., len(paths) == len(retentions)).
       - Check if exists by name.
       - If existing and identical: NOOP.
       - If existing and different: UPDATE with ID.
       - If new and valid: CREATE.
       - Monitor job with `monitor_job`, log result.

#### Import Algorithm (Detailed)
1. **Initialization** :
   - Load config (pool_uuid, nodes) from YAML/.env.
   - Initialize `DirectorClient`.
2. **Data Loading** :
   - Read "Repo" into DataFrame.
   - Parse multi-values: e.g., paths = "/data_hot | /cold_nfs" → [{"path": "/data_hot", "retention_days": 90}, ...].
3. **Prerequisite Checks** :
   - Validate lengths of multi-values.
4. **Data Comparison** :
   - Serialize storage_paths (JSON dumps for comparison).
   - Compare with existing (name, active, used_size, storage_paths).
5. **Action Execution** :
   - If dry_run, log simulation.
   - Else, POST/PUT payload, monitor job.
6. **Result Logging** :
   - Log action/result/error.
   - Return results for CLI display.
7. **Cleanup** :
   - Exit with status based on errors/skips.

#### Next Steps
- **Testing** : Execute `test_all.py` for Repos, validate logs.
- **Deployment** : Integrate into GitHub, generate binary.
- **Future Work** : Add support for more multi-value fields if needed.

This document provides a complete blueprint for the Repos importer, covering all engineering details, specifications, and algorithms without requiring external sources.

## Comprehensive Plan, Engineering, and Specifications Document for Routing Policies (RP) in lp_tenant_importer Project

#### Date and Version
- **Date**: September 26, 2025
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document focuses on the Routing Policies importer and serves as the sole reference for its implementation.

#### Overview
The **Routing Policies (RP)** importer is a Python-based module within the `lp_tenant_importer` project, designed to synchronize routing policy configurations from the "RoutingPolicy" sheet in Excel (XLSX) files with the LogPoint Director API (version 2.7.0). It handles creation, updating, listing, and monitoring of routing policies across multiple tenants (e.g., 'core'). The importer supports multiligne grouping by `cleaned_policy_name` for `routing_criteria`, dry-run simulations, async job monitoring, and comprehensive logging. Depends on Repos for `repo` validation.

#### Project Structure (Relevant to RP)
The structure is modular, with RP integrated as follows:
```
lp_tenant_importer/
├── main.py                    # CLI entry point, adds subcommand `import-routing-policies`
├── config_loader.py           # Loads .env and YAML for pool_uuid, nodes
├── core/
│   ├── http.py               # API client with methods for RP (e.g., create_routing_policy, update_routing_policy)
│   └── nodes.py              # Node management (backends, all_in_one for RP targets)
├── importers/
│   ├── routing_policies.py   # RP import logic
├── logging_utils.py           # Logging setup
├── samples/
│   ├── core_config.xlsx      # Contains "RoutingPolicy" sheet
├── tenants.full.example.yaml  # Tenant config with targets
```

#### General Modules (Relevant Updates)
##### main.py
- **Purpose** : CLI entry point, adds subcommand `import-routing-policies` with arguments `--dry-run`, `--xlsx`, `--tenants`.
- **Functionality** : Initializes `DirectorClient`, loads config and nodes, delegates to `importers.routing_policies.import_routing_policies_for_nodes`.
- **Key Logic** :
  1. Parse arguments.
  2. Load tenant config.
  3. Call importer.
  4. Display results in table/JSON, exit with status (0 success, 1 error, 2 skip).

##### http.py
- **Purpose** : HTTP client for API interactions.
- **Methods for RP** :
  - `get_routing_policies(pool_uuid, logpoint_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies
  - `get_routing_policy(pool_uuid, logpoint_id, id)`: GET /configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies/{id}
  - `create_routing_policy(pool_uuid, logpoint_id, payload)`: POST /configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies
  - `update_routing_policy(pool_uuid, logpoint_id, id, payload)`: PUT /configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies/{id}
  - `delete_routing_policy(pool_uuid, logpoint_id, id)`: DELETE /configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies/{id}
- **Key Logic** : Handle requests with auth, retries (3 attempts, 2s delay), monitor async jobs via `monitor_job` (poll until `success: true/false`, max 30 attempts, 2s interval).

##### logging_utils.py
- **Purpose** : Logging configuration.
- **Functionality** : Levels (DEBUG/INFO/WARNING/ERROR), JSON output optional, verbose HTTP debugging.

##### nodes.py
- **Purpose** : Manages SIEM nodes by role (backends, all_in_one for RP targets).

#### Importers
##### routing_policies.py
- **Specifications** : Manages routing policies (e.g., `rp_windows`, `rp_rsa`) with multiligne `routing_criteria`. Depends on Repos for `repo`.
- **API Endpoints** (from LogPoint Director API v2.7.0, relevant sections):
  - GET `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies`: Lists all policies.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies/{id}`: Fetches a policy.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies/{id}`: Updates a policy.
  - DELETE `/configapi/{pool_uuid}/{logpoint_id}/RoutingPolicies/{id}`: Deletes a policy.
- **Payload Structure** :
  - **CREATE** :
    ```json
    {
      "data": {
        "name": "rp_windows",
        "active": true,
        "catch_all": "Repo-core-system",
        "routing_criteria": [
          {
            "rule_type": "KeyPresentValueMatches",
            "key": "event_source",
            "value": "Microsoft-Windows-Sysmon",
            "repo": "Repo-core-system-verbose",
            "drop": false
          }
        ]
      }
    }
    ```
  - **UPDATE** :
    ```json
    {
      "data": {
        "name": "rp_windows",
        "active": true,
        "catch_all": "Repo-core-system",
        "routing_criteria": [
          {
            "rule_type": "KeyPresentValueMatches",
            "key": "event_source",
            "value": "Microsoft-Windows-Sysmon",
            "repo": "Repo-core-system-verbose",
            "drop": false
          }
        ],
        "id": "64f9de0f49a44cde2b327502"
      }
    }
    ```
- **XLS Structure** : `original_policy_name, cleaned_policy_name, active, catch_all, rule_type, key, value, repo, drop, policy_id`.
- **Data Formatting and Import Logic** :
  1. Load "RoutingPolicy" sheet with `pandas.read_excel`.
  2. Group by `cleaned_policy_name` to build `routing_criteria` list.
  3. Fetch existing policies via GET `/RoutingPolicies` per node.
  4. Validate `repo` against existing repos via GET `/Repos`.
  5. Compare: NOOP if identical (name, catch_all, criteria serialized), UPDATE if different (use policy_id), CREATE if new.
  6. Execute POST/PUT, monitor job, log outcome.
- **Prerequisite Checks via API** :
  - Validate `repo` and `catch_all` against fetched repos.
- **Status Handling and Payloads** :
  - **NOOP**: Identical configuration.
    - Payload: N/A.
    - Log: `INFO: No changes needed for rp_windows on lb-backend01`.
  - **SKIP**: Missing repo or invalid data.
    - Payload: N/A.
    - Log: `WARNING: Skipping rp_edr on lb-backend01 due to missing repo`.
  - **CREATE**: New policy.
    - Payload: As above.
    - Log: `INFO: Created rp_windows on lb-backend01`.
  - **UPDATE**: Changed criteria.
    - Payload: Updated criteria.
    - Log: `INFO: Updated rp_rsa on lb-backend01`.
- **Error Logs** :
  - `ERROR: Failed to create rp_windows on lb-backend01: 400`.
  - `WARNING: Skipping due to inconsistent criteria`.
- **Algorithm** :
  1. Read "RoutingPolicy" into DataFrame.
  2. Group criteria by `cleaned_policy_name`.
  3. For each node in targets:
     - Fetch existing policies via GET `/RoutingPolicies`.
     - Fetch repos for validation.
     - For each group:
       - Build payload with criteria list.
       - Validate repos.
       - Check if exists by name/policy_id.
       - If existing and identical: NOOP.
       - If existing and different: UPDATE.
       - If new and valid: CREATE.
       - Monitor job, log result.

#### Import Algorithm (Detailed)
1. **Initialization** :
   - Load config (pool_uuid, nodes) from YAML/.env.
   - Initialize `DirectorClient`.
2. **Data Loading** :
   - Read "RoutingPolicy" into DataFrame.
   - Group by `cleaned_policy_name` to form criteria list.
3. **Prerequisite Checks** :
   - Validate repos against GET `/Repos`.
4. **Data Comparison** :
   - Serialize criteria (JSON dumps).
   - Compare with existing.
5. **Action Execution** :
   - If dry_run, log simulation.
   - Else, POST/PUT payload, monitor job.
6. **Result Logging** :
   - Log action/result/error.
   - Return results for CLI display.
7. **Cleanup** :
   - Exit with status based on errors/skips.

#### Next Steps
- **Testing** : Execute `test_all.py` for RP, validate logs.
- **Deployment** : Integrate into GitHub, generate binary.
- **Future Work** : Enhance multiligne validation.

This document provides a complete blueprint for the RP importer, covering all engineering details, specifications, and algorithms without requiring external sources.

## Comprehensive Plan, Engineering, and Specifications Document for Normalization Policies (NP) in lp_tenant_importer Project

#### Date and Version
- **Date**: September 26, 2025
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document focuses on the Normalization Policies importer and serves as the sole reference for its implementation.

#### Overview
The **Normalization Policies (NP)** importer is a Python-based module within the `lp_tenant_importer` project, designed to synchronize normalization policy configurations from the "NormalizationPolicy" sheet in Excel (XLSX) files with the LogPoint Director API (version 2.7.0). It handles creation, updating, listing, and monitoring of normalization policies across multiple tenants (e.g., 'core'). The importer supports multi-value fields like `normalization_packages` and `compiled_normalizer`, dry-run simulations, async job monitoring, and comprehensive logging. Depends on RP for routed flows.

#### Project Structure (Relevant to NP)
The structure is modular, with NP integrated as follows:
```
lp_tenant_importer/
├── main.py                    # CLI entry point, adds subcommand `import-normalization-policies`
├── config_loader.py           # Loads .env and YAML for pool_uuid, nodes
├── core/
│   ├── http.py               # API client with methods for NP (e.g., create_normalization_policy, update_normalization_policy)
│   └── nodes.py              # Node management (backends, all_in_one for NP targets)
├── importers/
│   ├── normalization_policies.py # NP import logic
├── logging_utils.py           # Logging setup
├── samples/
│   ├── core_config.xlsx      # Contains "NormalizationPolicy" sheet
├── tenants.full.example.yaml  # Tenant config with targets
```

#### General Modules (Relevant Updates)
##### main.py
- **Purpose** : CLI entry point, adds subcommand `import-normalization-policies` with arguments `--dry-run`, `--xlsx`, `--tenants`.
- **Functionality** : Initializes `DirectorClient`, loads config and nodes, delegates to `importers.normalization_policies.import_normalization_policies_for_nodes`.
- **Key Logic** :
  1. Parse arguments.
  2. Load tenant config.
  3. Call importer.
  4. Display results in table/JSON, exit with status (0 success, 1 error, 2 skip).

##### http.py
- **Purpose** : HTTP client for API interactions.
- **Methods for NP** :
  - `get_normalization_policies(pool_uuid, logpoint_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy
  - `get_normalization_policy(pool_uuid, logpoint_id, id)`: GET /configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy/{id}
  - `create_normalization_policy(pool_uuid, logpoint_id, payload)`: POST /configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy
  - `update_normalization_policy(pool_uuid, logpoint_id, id, payload)`: PUT /configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy/{id}
  - `delete_normalization_policy(pool_uuid, logpoint_id, id)`: DELETE /configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy/{id}
- **Key Logic** : Handle requests with auth, retries (3 attempts, 2s delay), monitor async jobs via `monitor_job` (poll until `success: true/false`, max 30 attempts, 2s interval).

##### logging_utils.py
- **Purpose** : Logging configuration.
- **Functionality** : Levels (DEBUG/INFO/WARNING/ERROR), JSON output optional, verbose HTTP debugging.

##### nodes.py
- **Purpose** : Manages SIEM nodes by role (backends, all_in_one for NP targets).

#### Importers
##### normalization_policies.py
- **Specifications** : Manages normalization policies (e.g., `np_windows`, `np_rsa`) with multi-value fields. Depends on RP for routed flows.
- **API Endpoints** (from LogPoint Director API v2.7.0, relevant sections):
  - GET `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy`: Lists all policies.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy/{id}`: Fetches a policy.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy/{id}`: Updates a policy.
  - DELETE `/configapi/{pool_uuid}/{logpoint_id}/NormalizationPolicy/{id}`: Deletes a policy.
- **Payload Structure** :
  - **CREATE** :
    ```json
    {
      "data": {
        "name": "np_windows",
        "normalization_packages": "",
        "compiled_normalizer": "WindowsSysmonCompiledNormalizer | LPA_Windows"
      }
    }
    ```
  - **UPDATE** :
    ```json
    {
      "data": {
        "name": "np_windows",
        "normalization_packages": "",
        "compiled_normalizer": "WindowsSysmonCompiledNormalizer | LPA_Windows",
        "id": "existing_id"
      }
    }
    ```
- **XLS Structure** : `policy_name, normalization_packages, compiled_normalizer`.
- **Data Formatting and Import Logic** :
  1. Load "NormalizationPolicy" sheet with `pandas.read_excel`.
  2. Parse multi-values: Split `normalization_packages` and `compiled_normalizer` by `|`.
  3. Fetch existing policies via GET `/NormalizationPolicy` per node.
  4. Compare: NOOP if identical (name, packages/ normalizers serialized), UPDATE if different (use ID), CREATE if new.
  5. Execute POST/PUT, monitor job, log outcome.
- **Prerequisite Checks via API** :
  - Validate against RP (fetched via GET `/RoutingPolicies`), but optional as no strict dependency enforced.
- **Status Handling and Payloads** :
  - **NOOP**: Identical configuration.
    - Payload: N/A.
    - Log: `INFO: No changes needed for np_windows on lb-backend01`.
  - **SKIP**: Invalid data (e.g., missing name).
    - Payload: N/A.
    - Log: `WARNING: Skipping np_windows on lb-backend01 due to invalid normalizer`.
  - **CREATE**: New policy.
    - Payload: As above.
    - Log: `INFO: Created np_windows on lb-backend01`.
  - **UPDATE**: Changed normalizers.
    - Payload: Updated fields.
    - Log: `INFO: Updated np_rsa on lb-backend01`.
- **Error Logs** :
  - `ERROR: Failed to create np_windows on lb-backend01: 400`.
  - `WARNING: Skipping due to inconsistent packages`.
- **Algorithm** :
  1. Read "NormalizationPolicy" into DataFrame.
  2. For each node in targets:
     - Fetch existing policies via GET `/NormalizationPolicy`.
     - For each row:
       - Build payload (parse multi-values).
       - Validate fields.
       - Check if exists by name.
       - If existing and identical: NOOP.
       - If existing and different: UPDATE.
       - If new and valid: CREATE.
       - Monitor job, log result.

#### Import Algorithm (Detailed)
1. **Initialization** :
   - Load config (pool_uuid, nodes) from YAML/.env.
   - Initialize `DirectorClient`.
2. **Data Loading** :
   - Read "NormalizationPolicy" into DataFrame.
   - Parse multi-values: e.g., normalizers = "A | B" → "A | B" (keep as string or list).
3. **Prerequisite Checks** :
  - Optional validation against RP.
4. **Data Comparison** :
   - Serialize fields (JSON dumps).
   - Compare with existing.
5. **Action Execution** :
   - If dry_run, log simulation.
   - Else, POST/PUT payload, monitor job.
6. **Result Logging** :
   - Log action/result/error.
   - Return results for CLI display.
7. **Cleanup** :
   - Exit with status based on errors/skips.

#### Next Steps
- **Testing** : Execute `test_all.py` for NP, validate logs.
- **Deployment** : Integrate into GitHub, generate binary.
- **Future Work** : Enhance multi-value parsing.

This document provides a complete blueprint for the NP importer, covering all engineering details, specifications, and algorithms without requiring external sources.

## Comprehensive Plan, Engineering, and Specifications Document for Enrichment Policies (EP) in lp_tenant_importer Project

#### Date and Version
- **Date**: September 26, 2025
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document focuses on the Enrichment Policies importer and serves as the sole reference for its implementation.

#### Overview
The **Enrichment Policies (EP)** importer is a Python-based module within the `lp_tenant_importer` project, designed to synchronize enrichment policy configurations from the "EnrichmentPolicy", "EnrichmentRules", and "EnrichmentCriteria" sheets in Excel (XLSX) files with the LogPoint Director API (version 2.7.0). It handles creation, updating, listing, and monitoring of enrichment policies across multiple tenants (e.g., 'core'). The importer supports multiligne specifications grouping by `spec_index`, dry-run simulations, async job monitoring, and comprehensive logging. Depends on NP for normalized data.

#### Project Structure (Relevant to EP)
The structure is modular, with EP integrated as follows:
```
lp_tenant_importer/
├── main.py                    # CLI entry point, adds subcommand `import-enrichment-policies`
├── config_loader.py           # Loads .env and YAML for pool_uuid, nodes
├── core/
│   ├── http.py               # API client with methods for EP (e.g., create_enrichment_policy, update_enrichment_policy)
│   └── nodes.py              # Node management (backends, all_in_one for EP targets)
├── importers/
│   ├── enrichment_policies.py # EP import logic
├── logging_utils.py           # Logging setup
├── samples/
│   ├── core_config.xlsx      # Contains "EnrichmentPolicy", "EnrichmentRules", "EnrichmentCriteria" sheets
├── tenants.full.example.yaml  # Tenant config with targets
```

#### General Modules (Relevant Updates)
##### main.py
- **Purpose** : CLI entry point, adds subcommand `import-enrichment-policies` with arguments `--dry-run`, `--xlsx`, `--tenants`.
- **Functionality** : Initializes `DirectorClient`, loads config and nodes, delegates to `importers.enrichment_policies.import_enrichment_policies_for_nodes`.
- **Key Logic** :
  1. Parse arguments.
  2. Load tenant config.
  3. Call importer.
  4. Display results in table/JSON, exit with status (0 success, 1 error, 2 skip).

##### http.py
- **Purpose** : HTTP client for API interactions.
- **Methods for EP** :
  - `get_enrichment_policies(pool_uuid, logpoint_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy
  - `get_enrichment_policy(pool_uuid, logpoint_id, id)`: GET /configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy/{id}
  - `create_enrichment_policy(pool_uuid, logpoint_id, payload)`: POST /configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy
  - `update_enrichment_policy(pool_uuid, logpoint_id, id, payload)`: PUT /configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy/{id}
  - `delete_enrichment_policy(pool_uuid, logpoint_id, id)`: DELETE /configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy/{id}
  - `get_enrichment_sources(pool_uuid, logpoint_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/EnrichmentSource
- **Key Logic** : Handle requests with auth, retries (3 attempts, 2s delay), monitor async jobs via `monitor_job` (poll until `success: true/false`, max 30 attempts, 2s interval).

##### logging_utils.py
- **Purpose** : Logging configuration.
- **Functionality** : Levels (DEBUG/INFO/WARNING/ERROR), JSON output optional, verbose HTTP debugging.

##### nodes.py
- **Purpose** : Manages SIEM nodes by role (backends, all_in_one for EP targets).

#### Importers
##### enrichment_policies.py
- **Specifications** : Manages enrichment policies (e.g., `Threat_Intelligence`, `UEBA_ENRICHMENT_POLICY`) with multiligne `specifications` (rules/criteria). Depends on NP for normalized data.
- **API Endpoints** (from LogPoint Director API v2.7.0, relevant sections):
  - GET `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy`: Lists all policies.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy/{id}`: Fetches a policy.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy/{id}`: Updates a policy.
  - DELETE `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentPolicy/{id}`: Deletes a policy.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/EnrichmentSource`: Validates sources.
- **Payload Structure** :
  - **CREATE** :
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
              }
            ]
          }
        ]
      }
    }
    ```
  - **UPDATE** :
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
              }
            ]
          }
        ],
        "id": "62dcc0c3f1fa2022ab0872e7"
      }
    }
    ```
- **XLS Structure** :
  - "EnrichmentPolicy": `spec_index, policy_name, description, tags, active, source, policy_id`.
  - "EnrichmentRules": `policy_name, source, spec_index, category, source_key, prefix, operation, type, event_key`.
  - "EnrichmentCriteria": `policy_name, source, spec_index, type, key, value`.
- **Data Formatting and Import Logic** :
  1. Load all three sheets with `pandas.read_excel`.
  2. Group rules and criteria by `policy_name` and `spec_index`.
  3. Fetch existing policies via GET `/EnrichmentPolicy` per node.
  4. Validate sources against GET `/EnrichmentSource`.
  5. Compare: NOOP if identical (name, description, specifications serialized), UPDATE if different (use policy_id), CREATE if new.
  6. Execute POST/PUT, monitor job, log outcome.
- **Prerequisite Checks via API** :
  - Validate sources against fetched EnrichmentSources.
- **Status Handling and Payloads** :
  - **NOOP**: Identical configuration.
    - Payload: N/A.
    - Log: `INFO: No changes needed for Threat_Intelligence on lb-backend01`.
  - **SKIP**: Missing source or invalid data.
    - Payload: N/A.
    - Log: `WARNING: Skipping Threat_Intelligence on lb-backend01 due to missing source`.
  - **CREATE**: New policy.
    - Payload: As above.
    - Log: `INFO: Created Threat_Intelligence on lb-backend01`.
  - **UPDATE**: Changed specifications.
    - Payload: Updated specifications.
    - Log: `INFO: Updated Threat_Intelligence on lb-backend01`.
- **Error Logs** :
  - `ERROR: Failed to create Threat_Intelligence on lb-backend01: 400`.
  - `WARNING: Skipping due to inconsistent spec_index`.
- **Algorithm** :
  1. Read all three sheets into DataFrames.
  2. Group rules and criteria by `policy_name` and `spec_index`.
  3. For each node in targets:
     - Fetch existing policies via GET `/EnrichmentPolicy`.
     - Fetch sources for validation.
     - For each policy_name:
       - Build specifications list.
       - Validate sources.
       - Check if exists by name/policy_id.
       - If existing and identical: NOOP.
       - If existing and different: UPDATE.
       - If new and valid: CREATE.
       - Monitor job, log result.

#### Import Algorithm (Detailed)
1. **Initialization** :
   - Load config (pool_uuid, nodes) from YAML/.env.
   - Initialize `DirectorClient`.
2. **Data Loading** :
   - Read sheets into DataFrames.
   - Group to form specifications list.
3. **Prerequisite Checks** :
   - Validate sources against GET `/EnrichmentSource`.
4. **Data Comparison** :
   - Serialize specifications (JSON dumps).
   - Compare with existing.
5. **Action Execution** :
   - If dry_run, log simulation.
   - Else, POST/PUT payload, monitor job.
6. **Result Logging** :
   - Log action/result/error.
   - Return results for CLI display.
7. **Cleanup** :
   - Exit with status based on errors/skips.

#### Next Steps
- **Testing** : Execute `test_all.py` for EP, validate logs.
- **Deployment** : Integrate into GitHub, generate binary.
- **Future Work** : Separate rules/criteria into sub-modules if needed.

This document provides a complete blueprint for the EP importer, covering all engineering details, specifications, and algorithms without requiring external sources.

## Comprehensive Plan, Engineering, and Specifications Document for Processing Policies (PP) in lp_tenant_importer Project

#### Date and Version
- **Date**: September 26, 2025
- **Project Version**: Based on GitHub repository https://github.com/DeDobbeleer/DirectorSync/tree/main/lp_tenant_importer, latest commit as of analysis. This document focuses on the Processing Policies importer and serves as the sole reference for its implementation.

#### Overview
The **Processing Policies (PP)** importer is a Python-based module within the `lp_tenant_importer` project, designed to synchronize processing policy configurations from the "ProcessingPolicy" sheet in Excel (XLSX) files with the LogPoint Director API (version 2.7.0). It handles creation, updating, listing, and monitoring of processing policies across multiple tenants (e.g., 'core'). The importer supports references to NP and EP, dry-run simulations, async job monitoring, and comprehensive logging. Depends on EP for enriched data.

#### Project Structure (Relevant to PP)
The structure is modular, with PP integrated as follows:
```
lp_tenant_importer/
├── main.py                    # CLI entry point, adds subcommand `import-processing-policies`
├── config_loader.py           # Loads .env and YAML for pool_uuid, nodes
├── core/
│   ├── http.py               # API client with methods for PP (e.g., create_processing_policy, update_processing_policy)
│   └── nodes.py              # Node management (backends, all_in_one for PP targets)
├── importers/
│   ├── processing_policies.py # PP import logic
├── logging_utils.py           # Logging setup
├── samples/
│   ├── core_config.xlsx      # Contains "ProcessingPolicy" sheet
├── tenants.full.example.yaml  # Tenant config with targets
```

#### General Modules (Relevant Updates)
##### main.py
- **Purpose** : CLI entry point, adds subcommand `import-processing-policies` with arguments `--dry-run`, `--xlsx`, `--tenants`.
- **Functionality** : Initializes `DirectorClient`, loads config and nodes, delegates to `importers.processing_policies.import_processing_policies_for_nodes`.
- **Key Logic** :
  1. Parse arguments.
  2. Load tenant config.
  3. Call importer.
  4. Display results in table/JSON, exit with status (0 success, 1 error, 2 skip).

##### http.py
- **Purpose** : HTTP client for API interactions.
- **Methods for PP** :
  - `get_processing_policies(pool_uuid, logpoint_id)`: GET /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy
  - `get_processing_policy(pool_uuid, logpoint_id, id)`: GET /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}
  - `create_processing_policy(pool_uuid, logpoint_id, payload)`: POST /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy
  - `update_processing_policy(pool_uuid, logpoint_id, id, payload)`: PUT /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}
  - `delete_processing_policy(pool_uuid, logpoint_id, id)`: DELETE /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}
- **Key Logic** : Handle requests with auth, retries (3 attempts, 2s delay), monitor async jobs via `monitor_job` (poll until `success: true/false`, max 30 attempts, 2s interval).

##### logging_utils.py
- **Purpose** : Logging configuration.
- **Functionality** : Levels (DEBUG/INFO/WARNING/ERROR), JSON output optional, verbose HTTP debugging.

##### nodes.py
- **Purpose** : Manages SIEM nodes by role (backends, all_in_one for PP targets).

#### Importers
##### processing_policies.py
- **Specifications** : Manages processing policies (e.g., `pp_windows`, `pp_rsa`) with references to NP/EP/RP. Depends on EP for enriched data.
- **API Endpoints** (from LogPoint Director API v2.7.0, relevant sections):
  - GET `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`: Lists all policies.
  - GET `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`: Fetches a policy.
  - POST `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`: Creates a policy.
  - PUT `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`: Updates a policy.
  - DELETE `/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`: Deletes a policy.
- **Payload Structure** :
  - **CREATE** :
    ```json
    {
      "data": {
        "name": "pp_windows",
        "active": true,
        "norm_policy": "np_windows",
        "enrich_policy": null,
        "routing_policy_id": "64f9de0f49a44cde2b327502"
      }
    }
    ```
  - **UPDATE** :
    ```json
    {
      "data": {
        "name": "pp_windows",
        "active": true,
        "norm_policy": "np_windows",
        "enrich_policy": null,
        "routing_policy_id": "64f9de0f49a44cde2b327502",
        "id": "64f9ded28e8df427ea06b3de"
      }
    }
    ```
- **XLS Structure** : `original_policy_name, cleaned_policy_name, active, norm_policy, enrich_policy, routing_policy_id, policy_id`.
- **Data Formatting and Import Logic** :
  1. Load "ProcessingPolicy" sheet with `pandas.read_excel`.
  2. Map IDs to target IDs via API lookups (NP, EP, RP).
  3. Fetch existing policies via GET `/ProcessingPolicy` per node.
  4. Validate prerequisites (NP/EP/RP existence).
  5. Compare: NOOP if identical (name, active, norm_policy, enrich_policy, routing_policy_id), UPDATE if different (use policy_id), CREATE if new.
  6. Execute POST/PUT, monitor job, log outcome.
- **Prerequisite Checks via API** :
  - Validate `norm_policy`, `enrich_policy`, `routing_policy_id` against fetched policies.
- **Status Handling and Payloads** :
  - **NOOP**: Identical configuration.
    - Payload: N/A.
    - Log: `INFO: No changes needed for pp_windows on lb-backend01`.
  - **SKIP**: Missing prerequisite (e.g., norm_policy).
    - Payload: N/A.
    - Log: `WARNING: Skipping pp_windows on lb-backend01 due to invalid norm_policy`.
  - **CREATE**: New policy.
    - Payload: As above.
    - Log: `INFO: Created pp_windows on lb-backend01`.
  - **UPDATE**: Changed dependency.
    - Payload: Updated fields.
    - Log: `INFO: Updated pp_rsa on lb-backend01`.
- **Error Logs** :
  - `ERROR: Failed to create pp_windows on lb-backend01: 400`.
  - `WARNING: Skipping due to missing enrich_policy`.
- **Algorithm** :
  1. Read "ProcessingPolicy" into DataFrame.
  2. For each node in targets:
     - Fetch existing policies via GET `/ProcessingPolicy`.
     - Fetch prerequisites (NP/EP/RP) for validation.
     - For each row:
       - Build payload.
       - Validate prerequisites.
       - Check if exists by name/policy_id.
       - If existing and identical: NOOP.
       - If existing and different: UPDATE.
       - If new and valid: CREATE.
       - Monitor job, log result.

#### Import Algorithm (Detailed)
1. **Initialization** :
   - Load config (pool_uuid, nodes) from YAML/.env.
   - Initialize `DirectorClient`.
2. **Data Loading** :
   - Read "ProcessingPolicy" into DataFrame.
3. **Prerequisite Checks** :
   - Validate against fetched NP/EP/RP.
4. **Data Comparison** :
   - Compare fields directly.
5. **Action Execution** :
   - If dry_run, log simulation.
   - Else, POST/PUT payload, monitor job.
6. **Result Logging** :
   - Log action/result/error.
   - Return results for CLI display.
7. **Cleanup** :
   - Exit with status based on errors/skips.

#### Next Steps
- **Testing** : Execute `test_all.py` for PP, validate logs.
- **Deployment** : Integrate into GitHub, generate binary.
- **Future Work** : Add more dependency validations.