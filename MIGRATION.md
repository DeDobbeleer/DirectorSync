# MIGRATION.md — From v1 to v2 (internal)

**End-user usage remains identical.** Changes are internal only.

- CLI commands, flags, `.env`, and `tenants.yml` schema are preserved.
- We now rely solely on **global** `defaults.target[...]` (tenant-specific overrides ignored with a WARNING).
- All HTTP operations go through `DirectorClient` (JSON helpers + monitor polling).
- Importers implement only resource-specific bits (validation, equality, payload builders).
