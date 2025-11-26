# DirectorSync V3 – Pre-Design for Repos and Routing Policies

## 1. Introduction

This document describes the pre-design for the first two configuration types to be migrated from DirectorSync V2 to V3:

- **Repos**
- **Routing Policies**

The objective is to extract existing logic from V2, classify functional behaviour, and propose the V3 architecture using:

- external database as the authoritative desired state,
- YAML-based resource profiles,
- generic and resource-specific transformers,
- a unified sync pipeline.

This document forms the foundation for the V3 design and implementation.

---

## 2. Common V3 Concepts (Reminder)

V3 introduces the following architecture principles:

### 2.1. External Database
Desired configuration is loaded from SQL tables instead of XLSX files.

### 2.2. Resource Profiles (YAML)
Each configuration type is defined declaratively:
- data source (DB)
- Director API endpoints
- mapping rules
- comparison rules
- ordered preprocess and postprocess transformers

### 2.3. Transformers
Small, composable functions that:
- validate,
- clean up,
- enrich,
- convert,
- normalize,
- or build substructures for Director API calls.

Transformers can be:
- **generic**, reusable across all resource types,
- **resource-specific**, implementing domain logic.

### 2.4. Universal Sync Pipeline
All configuration types share the same pipeline:
1. load desired state (DB)
2. preprocess (transformers)
3. load current state (Director)
4. diff
5. plan + dry-run
6. apply (create/update/delete)
7. postprocess (transformers)
8. reporting

---

# 3. Repos – V2 Behaviour Analysis

## 3.1. Input (V2)
Repos are extracted from XLSX (sheet “Repo”) with fields such as:
- name / cleaned_repo_name
- storage_paths (multi-value)
- retention_days (multi-value)
- repoha_li / repoha_day (optional HA configuration)

Paths are normalized and validated.

## 3.2. Canonical Desired Structure (V2)
ReposProfile builds a canonical structure:

```json
{
  "name": "...",
  "hiddenrepopath": [
    {"path": ".../", "retention": "XX"},
    ...
  ],
  "repoha": [
    {"ha_li": "...", "ha_day": "XX"},
    ...
  ] or null
}
````

## 3.3. Director API (V2)

* Core resource: `Repos`
* Supports create, update, list
* Canonical compare fields:

  * hiddenrepopath
  * repoha

## 3.4. Specific V2 Logic

* storage_paths and retention_days must have identical length
* repoha_li and repoha_day must both be empty or aligned
* Repo paths must exist on backend or importer skips the repo

---

# 4. Repos – V3 Resource Profile (Draft)

```yaml
resources:
  repos:
    data_source:
      type: sql
      table: repos
      tenant_column: tenant_code
      external_id_column: external_id
      unique_key: ["name"]

    api:
      core:
        list:
          endpoint: /api/director/v2/repos
          method: GET
        create:
          endpoint: /api/director/v2/repos
          method: POST
        update:
          endpoint: /api/director/v2/repos/{id}
          method: PUT

    mapping:
      fields:
        name: name
      collections:
        hiddenrepopath:
          column: hiddenrepopath
          type: list_of_dict
        repoha:
          column: repoha
          type: list_of_dict

    comparison:
      key_fields: ["name"]
      canonical_fields:
        - hiddenrepopath
        - repoha
      list_normalization:
        hiddenrepopath:
          mode: list_of_dicts
          sort_by: ["path"]
        repoha:
          mode: list_of_dicts
          sort_by: ["ha_li"]

    preprocess: []
    postprocess: []
```

---

# 5. Repos – Candidate Transformers

## Preprocess (generic + resource-specific)

* `validate_required`
* `normalize_hiddenrepopath`
  Ensures trailing slash and consistent formatting.
* `normalize_repoha`
* `coerce_retention_types`

## Postprocess

* `verify_repo_paths`
* `update_external_id_in_db`

---

# 6. Routing Policies – V2 Behaviour Analysis

## 6.1. Input (V2)

Routing Policies use sheets: `"RoutingPolicy"` or `"RP"`.

Columns include:

* cleaned_policy_name
* catch_all
* rule_type
* key
* value
* repo
* drop

### Two line types in V2:

1. **Catch-all only lines**
   No rule fields populated → only catch_all is set.

2. **Rule lines**
   At least one rule field is set → importer requires *all* rule fields.

Repo mapping sheet may provide cleaned repo names.

## 6.2. V2 Canonical Structure

```json
{
  "name": "PolicyName",
  "catch_all": "...",
  "rules": [
    {
      "rule_type": "...",
      "key": "...",
      "value": "...",
      "repo": "...",
      "drop": "..."
    }
  ]
}
```

Converted later to `routing_criteria` for API calls.

## 6.3. Director API (V2)

* Resource: `"routing_policies"`
* Canonical compare fields:

  * name
  * catch_all
  * routing_criteria

---

# 7. Routing Policies – V3 Resource Profile (Draft)

```yaml
resources:
  routing_policies:
    data_source:
      type: sql
      table: routing_policies
      tenant_column: tenant_code
      external_id_column: external_id
      unique_key: ["name"]

    api:
      core:
        list:
          endpoint: /api/director/v2/routing-policies
          method: GET
        create:
          endpoint: /api/director/v2/routing-policies
          method: POST
        update:
          endpoint: /api/director/v2/routing-policies/{id}
          method: PUT

    mapping:
      fields:
        name: name
        catch_all: catch_all
      collections:
        rules:
          column: rules
          type: list_of_dict

    comparison:
      key_fields: ["name"]
      canonical_fields:
        - catch_all
        - routing_criteria
      list_normalization:
        routing_criteria:
          mode: list_of_dicts
          sort_by: ["rule_type", "key", "value", "repo", "drop"]

    preprocess: []
    postprocess: []
```

---

# 8. Routing Policies – Candidate Transformers

## Preprocess

* `validate_required`
* `build_routing_rules_from_rows`
* `routing_policies_classify_lines`
  Implements “catch-all only” vs “rule line”.
* `routing_policies_build_routing_criteria`
* `apply_repo_aliases` (optional)

## Postprocess

* `update_external_id_in_db`

---

# 9. Next Steps (Team Skeleton Phase)

1. Create initial V3 directory structure.
2. Write empty resource profile YAML files:

   * `repos.yml`
   * `routing_policies.yml`
3. Define SQL schema for:

   * `repos`
   * `routing_policies`
4. Build the first generic transformers:

   * `validate_required`
5. Prepare a minimal SyncEngine skeleton and pipeline structure.

