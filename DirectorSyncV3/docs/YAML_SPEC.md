# DirectorSync V3 – YAML Resource Profile Specification

This document defines the structure, required fields, and semantic rules of a V3 YAML resource profile.

---

## 1. Structure Overview

```yaml
resources:
  <resource_name>:
    data_source: ...
    api: ...
    mapping: ...
    comparison: ...
    preprocess: ...
    postprocess: ...
    dependencies: ...
````

---

## 2. Sections

### 2.1 `data_source`

Defines how to load desired state from the database.

```yaml
data_source:
  type: sql
  table: alert_rules
  tenant_column: tenant_code
  external_id_column: external_id
  unique_key:
    - name
```

### 2.2 `api`

Defines Director endpoints for CRUD operations.

```yaml
api:
  core:
    list:
      endpoint: /api/director/v2/alert-rules
      method: GET
    create:
      endpoint: /api/director/v2/alert-rules
      method: POST
    update:
      endpoint: /api/director/v2/alert-rules/{id}
      method: PUT
    delete:        # optional
      endpoint: /api/director/v2/alert-rules/{id}
      method: DELETE

  subresources:     # optional
    rbac:
      endpoint: /api/director/v2/alert-rules/{id}/rbac
      method: PUT
```

---

### 2.3 `mapping`

Defines how DB fields map to API JSON fields.

```yaml
mapping:
  fields:
    name: name
    severity: risk
    query: query

  collections:
    repos:
      column: repos
      type: list_of_dict
```

---

### 2.4 `comparison`

Rules for canonical diffing.

```yaml
comparison:
  key_fields:
    - name
  canonical_fields:
    - severity
    - query
    - repos

  list_normalization:
    repos:
      mode: set
```

Modes for `list_normalization`:

* `set`
* `sorted`
* `list_of_dicts`

---

### 2.5 `preprocess` / `postprocess`

Transformers executed before/after Apply Engine.

```yaml
preprocess:
  - transformer: validate_required
    params:
      fields: ["name", "query"]

postprocess:
  - transformer: update_external_id_in_db
```

---

### 2.6 `dependencies`

Used to order execution across resources.

```yaml
dependencies:
  - repos
```

---

## 3. Validation Rules

* Each profile must specify `data_source`, `api`, `comparison`.
* `unique_key` must resolve exactly one item in the DB.
* Transformers must be listed in correct order.
* `subresources` are optional but must come with post-transformers.

---

## 4. Reuse Across Resources

The YAML spec is intentionally universal.
No special cases belong in the SyncEngine.

