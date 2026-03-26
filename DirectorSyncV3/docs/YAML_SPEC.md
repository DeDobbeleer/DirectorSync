# DirectorSync V3 – YAML Resource Profile Specification

This document defines the structure of a V3 YAML resource profile as
used by DirectorSyncV3.

The goal is:
- one **generic Sync Engine**,
- zero resource-specific branching in Python,
- all differences expressed in the YAML profile.

Each resource profile is loaded into a `ResourceProfile` instance
(`lp_sync.core.profiles.ResourceProfile`).

---

## 1. Top-level structure

A profile file defines one or more resources under the `resources` key:

```yaml
resources:
  <resource_name>:
    enabled: true
    order: 10
    depends_on:
      - other_resource

    data_source: ...
    api: ...
    mapping: ...
    comparison: ...
    constraints: ...
    pipeline: ...
````

### 1.1 Common fields

* `enabled` (bool, optional, default `true`)
  If `false`, the resource is ignored.

* `order` (int, optional, default `0`)
  Relative ordering hint. Lower values are processed first.

* `depends_on` (list of strings, optional)
  List of other resources that must be processed first (e.g.
  `routing_policies` depends on `repos`).

---

## 2. `data_source`

Describes where the **desired state** is stored (DB) and how to load it.

Two patterns are supported:

### 2.1 Simple table

```yaml
data_source:
  table: desired_repos
  tenant_column: tenant
  key_columns:
    - tenant
    - name
```

The loader will:

* run `SELECT * FROM <table> WHERE <tenant_column> = :tenant`,
* order by `key_columns` if provided.

### 2.2 Header + children (generic)

For resources with a “header + 1..N rows” pattern (e.g. routing policies
with criteria):

```yaml
data_source:
  header:
    table: desired_routing_policies
    tenant_column: tenant
    key_columns:
      - tenant
      - policy_name
    id_column: id               # optional, default "id"

  children:
    - alias: "criteria_rows"    # name of the collection in each item
      table: desired_routing_policy_rules
      foreign_key_column: routing_policy_id
      order_column: criteria_index
      tenant_column: tenant     # optional, defaults to header.tenant_column
```

The DesiredStateLoader will:

* load header rows from `header.table`,
* for each child definition in `children`:

  * load rows from `child.table`,
  * group by `foreign_key_column`,
  * attach the list of rows to the corresponding header under
    `item[alias]` (e.g. `item["criteria_rows"]`).

The loader does not assign any special meaning to the alias name.

---

## 3. `api`

Describes how to talk to the Director API for this resource.

```yaml
api:
  base_path: "/configapi/{pool_uuid}/{logpoint_identifier}"

  list:
    method: GET
    path: "{base_path}/Repos"

  create:
    method: POST
    path: "{base_path}/Repos"

  update:
    method: PUT
    path: "{base_path}/Repos/{id}"
    id_field: "id"

  delete:
    method: DELETE
    path: "{base_path}/Repos/{id}"
    id_field: "id"

  # Optional pre-checks (e.g. filesystem paths)
  prechecks:
    - name: "check_repo_path"
      method: POST
      path: "{base_path}/Repos/CheckPath"
      request_template: |
        { "path": "{{ path }}" }
      success_condition: "status == 200"
```

The `DirectorClient` is responsible for:

* templating `base_path`, `path` using tenant context,
* evaluating `success_condition` for pre-checks.

---

## 4. `mapping`

Describes how to build Director API payloads from desired state rows,
and optionally how to map API responses back to the DB.

```yaml
mapping:
  # Simple DB -> API field mapping (DB column -> JSON field)
  desired_to_api:
    name: "name"
    active: "active"
    hiddenrepopath: "hiddenrepopath"
    repoha: "repoha"

  # Optional arrays: build API arrays from collections on the item
  arrays:
    - source: "criteria_rows"        # item["criteria_rows"] (list of dicts)
      dest: "routing_criteria"       # payload["routing_criteria"]
      fields:                        # per-element mapping
        repo: "repo"
        drop: "drop"
        type: "type"
        key: "key"
        value: "value"
        category: "category"
        operation: "operation"
        prefix: "prefix"
        event_key: "event_key"
        source_key: "source_key"
        value_type: "value_type"

  # Optional API -> DB mapping (e.g. Director-assigned IDs)
  api_to_desired:
    id: "director_id"
```

The generic `build_payloads()` function will:

* read `mapping.desired_to_api` for simple fields,
* read `mapping.arrays` for arrays.

---

## 5. `comparison`

Describes how to compare desired vs current state.

```yaml
comparison:
  identity_keys:
    - name

  significant_fields:
    - active
    - hiddenrepopath
    - repoha

  canonicalization:
    sort_arrays:
      - "hiddenrepopath"
    ignore_fields:
      - "used_size"
      - "repo_number"
```

The diff engine will:

* use `identity_keys` to match desired/current items,
* only consider `significant_fields` for updates,
* apply `canonicalization` before comparing.

---

## 6. `constraints`

Encodes validation rules and cross-resource references.

```yaml
constraints:
  required_fields:
    - tenant
    - name
    - hiddenrepopath

  uniqueness:
    - keys: ["tenant", "name"]

  field_rules:
    - field: "criteria_rows[].drop"
      allowed_values: ["store", "drop"]

  references:
    - source_field: "catch_all"
      target_resource: "repos"
      target_field: "name"
      on_missing: "error"        # or "skip_resource", "skip_policy"

    - source_field: "criteria_rows[].repo"
      target_resource: "repos"
      target_field: "name"
      on_missing: "skip_policy"

  director_checks:
    - type: "filesystem_path_exists"
      target: "hiddenrepopath[].path"
      operation: "check_repo_path"   # refers to api.prechecks[].name
      on_failure: "error"
```

Generic functions:

* `validate_required_fields()` reads `required_fields`.
* `validate_references()` reads `references` and can:

  * raise an error,
  * or mark an item as skipped (depending on `on_missing`).
* A dedicated transformer (e.g. `generic.director_checks`) reads
  `director_checks` and delegates to the Director client.

---

## 7. `pipeline`

Describes the ordered list of transformers to run for this resource.

```yaml
pipeline:
  preprocess:
    - generic.validate_required
    - generic.validate_references
    - generic.director_checks
    - generic.build_payloads

  postprocess:
    - generic.handle_response
```

Each entry is either:

* a simple string: `"generic.validate_required"`, or
* a mapping:

  ```yaml
  - name: "generic.validate_required"
    params:
      extra_field: "value"
  ```

The `TransformerPipeline` resolves these names to Python classes under
`lp_sync.transformers.<namespace>.<short_name>` and calls their `run()`
method.

All resources share the same transformer implementations. The behaviour
is driven entirely by the profile configuration.
