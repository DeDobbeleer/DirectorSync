### *DirectorSync V3 – Generic Transformers Implementation Specification*

**Version:** 2025-11-29

---

# 0. Overview

Transformers are pluggable processing units executed by the
`TransformerPipeline` during:

* **preprocess** (before diff)
* **postprocess** (after apply)

Transformers operate on **individual resource items**, transforming,
normalizing, validating, or discarding them.

A transformer:

* receives: `(item, context, params)`
* returns:

  * the transformed item (`dict`), or
  * `None` to **remove/skip** the item from the sync flow

Transformers **must not** interact with the Director API directly,
except for those explicitly designed for Director checks.

They must remain **generic**, resource-agnostic, YAML-driven.

---

# 1. BaseTransformer Contract

All transformers extend:

```python
class BaseTransformer:
    def run(
        self,
        item: Dict[str, Any],
        context: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        raise NotImplementedError
```

### Required behavior

* Must never raise exceptions for normal validation failure (instead,
  log and return `None` to skip).
* Must never mutate `context`.
* Must log meaningful messages using `get_logger`.
* Must handle missing params gracefully.

---

# 2. Shared Pipeline Context

Transformers receive a context containing at least:

```python
context = {
    "tenant_code": <str>,
    "resource_name": <str>,
    "profile": <ResourceProfile>,
    "director_client": <DirectorClient or None>,
    # optionally more in the future
}
```

They **must not** add keys to the context.

---

# 3. Generic Transformers Spec

We define the four mandatory generic transformers:

1. `validate_required`
2. `validate_references`
3. `director_checks`
4. `build_payloads`

---

# 3.1 `generic.validate_required`

## Purpose

Ensures that required fields defined in the resource profile are present
and non-null in the desired item.

## YAML-driven configuration

From the resource profile:

```yaml
constraints:
  required_fields:
    - tenant
    - policy_name
    - catch_all
```

The transformer does not receive parameters from `pipeline`, it reads
from:

```
context["profile"].constraints.required_fields
```

## Behavior

For each required field:

* If `item[field]` is missing or `None` or `""`:

  * Log a warning
  * Return `None` → item is removed from the sync flow

No exception is thrown.

## Output

* `item` unchanged if all fields are valid.
* `None` if any required field is invalid.

---

# 3.2 `generic.validate_references`

*(Most important transformer in V3)*

## Purpose

Validates cross-resource dependencies defined in the YAML profile.

Examples:

```yaml
constraints:
  references:
    - source_field: "catch_all"
      target_resource: "repos"
      target_field: "name"
      on_missing: "error"

    - source_field: "criteria_rows[].repo"
      target_resource: "repos"
      target_field: "name"
      on_missing: "skip_policy"
```

## Behavior

### Step 1 — Extract referenced values

The transformer must support:

* simple fields:
  `catch_all`
* nested list expansions:
  `criteria_rows[].repo`

### Step 2 — Load target resource index

The transformer looks up from the context:

```
context["dependency_index"][target_resource]
```

This index is prepared by the SyncEngine and contains:

```
{
  "repos": set(["repoA", "repoB", ...]),
  "routing_policies": set([...]),
  ...
}
```

(**We will produce the SyncEngine spec later.**)

### Step 3 — Validate references

If a referenced value is not found in the target index:

* If `on_missing == "error"`
  → log error, return `None`
* If `on_missing == "skip_policy"`
  → log warning, return `None`
* If `on_missing == "skip_resource"`
  → log warning, remove entire resource (handled upstream)
* If unknown policy → treat as `"error"`

### Step 4 — Pass through

If all references exist → item is returned unchanged.

## Output

* `item` unchanged if all references resolve.
* `None` if skip or error policy applies.

---

# 3.3 `generic.director_checks`

## Purpose

Executes *remote validations* through Director API to ensure
prerequisites are met before diff/apply.

Example:

```yaml
constraints:
  director_checks:
    - type: "filesystem_path_exists"
      target: "hiddenrepopath[].path"
      operation: "check_repo_path"
      on_failure: "error"
```

And in the API section:

```yaml
api:
  prechecks:
    - name: "check_repo_path"
      method: POST
      path: "{base_path}/Repos/CheckPath"
      request_template: |
        { "path": "{{ path }}" }
      success_condition: "status == 200"
```

## Behavior

### Step 1 — Resolve target fields

Supports scalar and array expansion like `validate_references`.

### Step 2 — For each value, build precheck request

* load API precheck definition from
  `context["profile"].api.prechecks`
* perform variable substitution in `request_template`
* send HTTP request via `director_client`.

### Step 3 — Evaluate success condition

If any precheck fails:

* If `on_failure == "error"` → return `None`
* If `on_failure == "skip_policy"` → return `None`

If all prechecks succeed → return `item` unchanged.

## Output

* `item` unchanged if all checks pass.
* `None` on failure according to `on_failure`.

---

# 3.4 `generic.build_payloads`

*(Critical transformer – constructs Director API payloads)*

## Purpose

Convert validated desired items into API-ready payloads based on the
`mapping` section of the YAML profile.

Example:

```yaml
mapping:
  desired_to_api:
    policy_name: "policy_name"
    catch_all: "catch_all"
    active: "active"

  arrays:
    - source: "criteria_rows"
      dest: "routing_criteria"
      fields:
        repo: "repo"
        drop: "drop"
        type: "type"
        key: "key"
        value: "value"
```

## Behavior

### Step 1 — Base payload

Build a dict:

```
payload = {}
```

For each entry in:

```yaml
mapping.desired_to_api
```

Do:

```
payload[target_field] = item[source_field]
```

### Step 2 — Arrays

For each array mapping:

```yaml
- source: "criteria_rows"
  dest: "routing_criteria"
  fields:
    repo: "repo"
    drop: "drop"
    ...
```

The transformer performs:

```
payload[dest] = [
    { target_field: element[source_field] for each mapping }
    for element in item[source]
]
```

### Step 3 — Error handling

If a field is missing in source:

* log warning
* use `None` as value

### Step 4 — Attach payload

Store final payload as:

```
item["_payload"] = payload
```

### Purpose

This isolates payload generation from:

* diff calculation (which compares original item)
* apply phase (which uses `_payload`)

## Output

* Modified `item` with `_payload` key
* Never returns `None`

---

# 4. Transformer Error Policy

Transformers must adhere to:

* **Validation error** → return `None`, do not raise
* **System error** (e.g. director_client network exception) → log and return `None`
* **Do not modify other items**
* **Do not modify context**

---

# 5. Ordering Rules

Transformers must be executed in this canonical order (unless YAML profile customizes it):

### Preprocess

1. validate_required
2. validate_references
3. director_checks
4. build_payloads

### Postprocess

Used primarily for:

* response mapping
* audit logging
* cleanup tasks

---

# 6. Testing Requirements

Each transformer must be unit-tested with scenarios covering:

* success path
* missing fields
* null values
* nested field extraction
* array expansion
* invalid references
* Director precheck failure
* mapping correctness (`build_payloads`)

---

# 7. Future Extensions (reserved)

* `normalize_fields`
* `merge_defaults`
* `auto_increment`
* `strip_whitespace`
* `resolve_alias_paths`

---

That’s the full **transformer spec** used by your Sync V3 engine.

