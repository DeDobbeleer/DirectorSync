### *DirectorSync V3 – Core Sync Engine Implementation Specification*

**Version:** 2025-11-29

---

# 1. Overview

The DirectorSyncV3 Core Sync Engine synchronizes:

* a **desired state** (stored in the DB, aligned with Director API models),
* with the **current state** retrieved from the Director API.

The system is **fully generic**, meaning:

* no resource-specific logic exists in Python,
* all resource-specific behavior is expressed in the YAML resource profiles,
* the pipeline + diff + apply logic handles any resource type the same way.

A resource profile defines:

* how to load desired data (`data_source`)
* how to build API payloads (`mapping`)
* how to compare objects (`comparison`)
* how to validate items (`constraints`)
* how to process items (`pipeline`)
* how to interact with Director (`api`)

The Core Sync Engine manipulates only:

* Python dictionaries for desired/current items,
* Normalized profile data coming from `ResourceProfile`.

**Important:**
Any decision to *skip* an item (failed prerequisites, broken references, invalid field values, etc.) is made **in transformers**, not in the diff engine.

The Diff Engine only produces:
`create`, `update`, `delete`, `noop`.

---

# 2. DesiredStateLoader

`lp_sync/core/desired_state_loader.py`

## 2.1 Responsibility

Loads the **desired state** for a resource and tenant from the SQL database, based solely on the `data_source` section of the resource profile.

Supported patterns:

### 1) Simple table

```yaml
data_source:
  table: desired_repos
  tenant_column: tenant
  key_columns:
    - tenant
    - name
```

### 2) Header + children (generic)

```yaml
data_source:
  header:
    table: desired_routing_policies
    tenant_column: tenant
    key_columns:
      - tenant
      - policy_name
    id_column: id

  children:
    - alias: "criteria_rows"
      table: desired_routing_policy_rules
      foreign_key_column: routing_policy_id
      order_column: criteria_index
      tenant_column: tenant
```

Meaning:

* Header rows form main items.
* Each `children[]` definition attaches a list of related rows under `item[alias]`.
* No business logic is applied.
* The engine does not interpret alias names.

## 2.2 Input/Output Contract

Signature:

```python
def load(self, profile: Any, tenant_code: str) -> List[Dict[str, Any]]:
```

Input:

* `profile` with `.data_source` populated from the resource YAML.
* `tenant_code` for filtering DB rows.

Output:

* A list of dictionaries representing desired items, possibly enriched with child lists when using header/children mode.

## 2.3 Implementation Details

* SQL identifiers (table/column names) are validated using a strict regex:
  `^[A-Za-z_][A-Za-z0-9_]*$`
* Child tables are indexed by their `foreign_key_column`,
  then attached to each header based on `header[id_column]`.
* Ordering is controlled by `key_columns` and `order_column`.

---

# 3. TransformerPipeline

`lp_sync/core/transformer_pipeline.py`

## 3.1 Responsibility

Executes pipeline steps defined in the resource profile:

```yaml
pipeline:
  preprocess:
    - generic.validate_required
    - generic.validate_references
    - generic.build_payloads

  postprocess:
    - generic.handle_response
```

Each step may be:

### Simple string

```
"generic.validate_required"
```

### Object with parameters

```yaml
- name: "generic.validate_required"
  params:
    strict: true
```

The pipeline:

* Resolves transformer names into Python classes (`BaseTransformer`),
* Instantiates and executes them sequentially,
* Removes an item from the flow if a transformer returns `None`,
* Passes a shared `context` containing:

  * `profile`
  * `tenant_code`
  * optionally `director_client`
  * other engine metadata

## 3.2 Naming Convention

Transformer identifier:

```
generic.validate_required
```

Maps to:

* module: `lp_sync.transformers.generic.validate_required`
* class:  `ValidateRequiredTransformer`

This allows adding new transformers without modifying core logic.

## 3.3 Input/Output Contract

```python
def run(
    self,
    pipeline_config: Sequence[Any],
    items: List[Dict[str, Any]],
    context: Dict[str, Any],
) -> List[Dict[str, Any]]:
```

Output:

* A filtered + transformed list of items.
* Items removed by returning `None` are **skipped before diff**.

---

# 4. DiffEngine & PlannedAction

`lp_sync/core/diff_engine.py`

## 4.1 Responsibility

Compares two validated sets:

* **desired**: returned by the preprocess pipeline.
* **current**: returned by the Director API.

It uses only the `comparison` section of the profile:

```yaml
comparison:
  identity_keys:
    - policy_name
  significant_fields:
    - catch_all
    - routing_criteria
  canonicalization:
    sort_arrays:
      - routing_criteria
    ignore_fields:
      - used_size
```

DiffEngine **does not** make SKIP decisions.

It produces exactly the following actions:

* `create`
* `update`
* `delete`
* `noop`

## 4.2 PlannedAction Data Model

```python
@dataclass
class PlannedAction:
    action: str                   # create / update / delete / noop
    key: Tuple[Any, ...] | None   # identity based on identity_keys
    desired: Dict[str, Any] | None
    current: Dict[str, Any] | None
    reason: str | None = None
```

## 4.3 Behavior

### Create

Item exists in desired but not current.

### Delete

Item exists in current but not desired.

### Update

Item exists in both, but differs on `significant_fields`.

### Noop

Item exists in both and is identical on `significant_fields`.

## 4.4 Canonicalization

* Removes any fields listed in `ignore_fields`
* Sorts lists listed in `sort_arrays`
* Comparison uses canonicalized objects only.

---

# 5. ApplyEngine

`lp_sync/core/apply_engine.py`

## 5.1 Responsibility

Executes `PlannedAction` objects against the Director API.

Uses an abstraction:

```python
director_client
```

Supports **dry-run mode**:

* No HTTP calls are made,
* Actions are logged,
* The reason field is annotated with `"dry-run; no HTTP call performed"`.

The engine **does not evaluate SKIP**; it simply applies the actions produced by the diff.

## 5.2 Input/Output Contract

```python
def apply(self, actions, dry_run=False) -> List[PlannedAction]:
```

### Noop

Logged at debug level.

### Create/Update/Delete

* Logged at info level.
* When not dry-run, these will later call:

  * `director_client.create(payload)`
  * `director_client.update(id, payload)`
  * `director_client.delete(id)`

---

# 6. End-to-End Sequence

For each resource and tenant:

1. Load YAML profile → `ResourceProfile`
2. Load desired data →
   `DesiredStateLoader.load(profile, tenant)`
3. Preprocess desired items →
   `TransformerPipeline.run(preprocess)`
4. Retrieve current items →
   `DirectorClient.list(profile.api, tenant)`
5. Diff desired vs current →
   `DiffEngine.diff(profile, desired, current)`
6. Apply →
   `ApplyEngine.apply(actions, dry_run)`
7. (Optional) Postprocess actions →
   `TransformerPipeline.run(postprocess)`

---

# 7. Next Documentation Tasks (TODO)

* Add specs for generic transformers:

  * `validate_required`
  * `validate_references`
  * `director_checks`
  * `build_payloads`
* Add API contract for `DirectorClient`
* Add error handling and retry strategy specification
* Add SyncEngine global orchestration spec

