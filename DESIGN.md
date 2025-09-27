# DESIGN.md — v2 Common Trunk

## Goals
- Kill redundancy across importers by extracting shared mechanics into a single place.
- Make adding a new importer a matter of writing a small adapter.

## Components
- `core/director_client.py`: JSON-first HTTP client + monitor polling, requests.Session under the hood.
- `core/config.py`: .env + tenants.yml loader (global targets only), consistent errors.
- `core/logging_utils.py`: one-liner setup; env `LP_LOG_LEVEL` supported.

- `utils/diff_engine.py`: compare desired vs existing, return operations with reasons.
- `utils/resolvers.py`: caches name→id lookups per node (devices, groups, policies, repos).
- `utils/validators.py`: XLSX sheet checks and required fields.
- `utils/reporting.py`: table/json renderer, stable columns.

- `importers/base.py`: template methods with clean lifecycle hooks.
- `importers/repos.py`: reference importer implementing full flow (incl. repo path checks).
