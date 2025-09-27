# HOWTO_add_importer.md

1. Subclass `BaseImporter` and set:
   - `resource_name`
   - `sheet_names`
   - `required_columns`
   - `key_fn(row) -> str`
   - `canon_desired(row) -> dict`
   - `canon_existing(obj) -> dict`
   - `build_payload_create(row)`
   - `build_payload_update(row, existing)`

2. Implement `fetch_existing(client, pool_uuid, node)` with pagination if needed.

3. That's it: the base class will call your hooks and orchestrate the rest.
