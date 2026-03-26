# SyncEngine – Orchestration Specification
Version: 2025-11-29

## Purpose

`SyncEngine` orchestrates the complete sync flow for a given resource
and tenant:

1. Load desired state from DB
2. Run preprocess transformers
3. Load current state from Director
4. Compute diff (planned actions)
5. Apply actions (optionally dry-run)
6. Optionally run postprocess transformers

The engine is **resource-agnostic** and driven by:

- ResourceProfile
- Generic transformers
- DirectorClient abstraction
- DiffEngine + ApplyEngine

## High-level Responsibilities

For each `(resource_name, tenant_code)`:

1. Resolve the `ResourceProfile` from loaded profiles.
2. Ensure the resource is `enabled` and dependencies are satisfied.
3. Build a `context` dict for transformers with:
   - `tenant_code`
   - `resource_name`
   - `profile`
   - `director_client`
   - (optionally) `dependency_index` for ValidateReferences
4. Execute the pipeline:
   - `DesiredStateLoader.load(...)`
   - `TransformerPipeline.run(preprocess, ...)`
   - `DirectorClient.list(...)`
   - `DiffEngine.diff(...)`
   - `ApplyEngine.apply(...)`
   - `TransformerPipeline.run(postprocess, ...)` (optional)

## Input/Output

### Public API

```python
def sync_resource_for_tenant(
    self,
    resource_name: str,
    tenant_code: str,
    dry_run: bool = False,
) -> List[PlannedAction]:
    ...
````

* `resource_name`: key from the YAML profiles (e.g. "repos", "routing_policies")
* `tenant_code`: tenant to sync
* `dry_run`: if True, ApplyEngine will not issue HTTP calls

Returns:

* The list of `PlannedAction` objects produced by the engine.

### Dependency Index

To support `validate_references`, `SyncEngine` builds a simple
`dependency_index` structure:

```python
dependency_index = {
  "repos": { "repoA", "repoB", ... },
  "routing_policies": { "policy1", "policy2", ... },
  ...
}
```

For a first version, we only need:

* `repos` → names from desired state (or current, depending on strategy)

The index is injected into the pipeline context as:

```python
context["dependency_index"] = dependency_index
```

## Error Handling

* Fail-fast for structural errors:

  * missing profile
  * invalid data_source
* Safe degradation for validation:

  * transformers may drop items by returning `None`
* ApplyEngine respects `dry_run`.

## Future extensions

* Sync multiple tenants in batch.
* Sync all resources in dependency order (topological sort).
* Collect rich metrics and audit logs.
