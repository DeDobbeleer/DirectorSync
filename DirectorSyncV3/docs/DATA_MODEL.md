# DirectorSyncV3 – Data Model (V3 Aligned)

## 1. Scope and Principles

This document describes the **SQL data model** used by DirectorSyncV3 as the
**source of truth for the desired configuration state**.

Key principles:

- The database stores **desired state only** (no historical or audit data).
- Each configuration type (e.g. `repos`, `routing_policies`) has a dedicated
  `desired_*` table (plus auxiliary tables when needed).
- **Multi-tenancy** is handled via an explicit `tenant` column on each table.
- The **Sync Engine**:
  - reads desired state from SQL,
  - fetches current state from Logpoint Director,
  - computes a diff,
  - plans and applies changes via the Director API.

The data model is intentionally **vendor-agnostic** (PostgreSQL-friendly, but
usable with SQLite or other SQL databases).

Migration-specific notions (such as `original_xxx_name` / `cleaned_xxx_name`)
do not appear in the V3 schema. Those concerns belong to separate migration
tools, not to the steady-state DirectorSyncV3 model.

---

## 2. Naming Conventions

- Tables storing desired configuration are prefixed with `desired_`, e.g.:
  - `desired_repos`
  - `desired_routing_policies`
  - `desired_routing_policy_rules`
- All identifiers are snake_case.
- Each table includes:
  - a surrogate primary key `id`,
  - a natural key (often `(tenant, name)`),
  - `created_at` / `updated_at` timestamps (optional),
  - dedicated columns for core semantics,
  - no migration-specific naming.

---

## 3. Repos Data Model (`desired_repos`)

### 3.1 Purpose

The `desired_repos` table represents the **target repository configuration**
that should exist in Logpoint Director for each tenant.

Each row corresponds to **one repository definition** in the desired state.

Unlike V2, the V3 schema is **aligned directly with the Director API
payload fields**, so that the DB can be mapped to JSON with minimal
transformation.

Typical Director API fields for a repository include:

- `name` (string)
- `active` (boolean)
- `hiddenrepopath` (list of objects: `{ "path": str, "retention": int }`)
- `repoha` (list of objects: `{ "ha_day": int, "ha_li": str }`)
- `used_size` (numeric, informational)
- `repo_number` (numeric, informational)
- `tid` (string, internal identifier)

The V3 DB schema mirrors these fields as closely as possible.

### 3.2 Table Definition

```sql
CREATE TABLE IF NOT EXISTS desired_repos (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant          VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    active          BOOLEAN NOT NULL,
    hiddenrepopath  TEXT NOT NULL,
    repoha          TEXT,
    used_size       BIGINT,
    repo_number     INTEGER,
    tid             VARCHAR(255),
    created_at      TIMESTAMP NULL,
    updated_at      TIMESTAMP NULL,
    CONSTRAINT uq_desired_repos_tenant_name
        UNIQUE (tenant, name)
);
````

Indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_desired_repos_tenant
    ON desired_repos (tenant);

CREATE INDEX IF NOT EXISTS idx_desired_repos_active
    ON desired_repos (tenant, active);
```

### 3.3 Column Semantics

* `tenant`
  Logical tenant identifier used by DirectorSyncV3. A separate
  mapping table links this to Director concepts such as `pool_uuid`
  and `logpoint_identifier`.

* `name`
  Repository name, as expected by the Director API (`name` field).

* `active`
  Indicates whether the repository should be active in Director
  (maps to API field `active`).

* `hiddenrepopath`
  JSON-encoded list of objects describing storage paths and retention,
  for example:

  ```json
  [
    { "path": "/opt/immune/storage/", "retention": 365 },
    { "path": "/opt/immune/cold/", "retention": 730 }
  ]
  ```

  This maps directly to the Director API `hiddenrepopath` field.

* `repoha`
  Optional JSON-encoded list describing high-availability configuration,
  for example:

  ```json
  [
    { "ha_day": 2, "ha_li": "10.0.0.10" }
  ]
  ```

  This maps directly to the Director API `repoha` field.

* `used_size`, `repo_number`, `tid`
  Optional, primarily informational fields that may be read back from
  Director but are not required for create/update payloads.

* `created_at`, `updated_at`
  Optional audit timestamps at the DB level (not tied to Director
  audit fields).

### 3.4 Relationship with V2 Migration

Any mapping from legacy V2 XLSX columns (e.g. `repo_number`,
`cleaned_repo_name`, `storage_paths`, `retention_days`, etc.) into the
V3 `desired_repos` schema must be implemented in **separate import or
migration scripts**.

The steady-state schema remains aligned with the Director API and does
not contain V2-specific naming.


## 4. Routing Policies Data Model

Routing policies are modeled using **two tables**:

- `desired_routing_policies` (policy header, 1 row per policy),
- `desired_routing_policy_rules` (rules/criteria, 1..N rows per policy).

This matches the Director API structure, where a routing policy is
defined by:

- a header (`policy_name`, `catch_all`, etc.),
- a list of `routing_criteria` objects.

### 4.1 Routing Policy Header (`desired_routing_policies`)

#### 4.1.1 Purpose

The `desired_routing_policies` table represents the high-level definition
of a routing policy for a given tenant.

Each row corresponds to one logical routing policy, identified by a
tenant and a `policy_name`.

#### 4.1.2 Table Definition

```sql
CREATE TABLE IF NOT EXISTS desired_routing_policies (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant       VARCHAR(255) NOT NULL,
    policy_name  VARCHAR(255) NOT NULL,
    catch_all    VARCHAR(255) NOT NULL,
    active       BOOLEAN,
    description  TEXT,
    created_at   TIMESTAMP NULL,
    updated_at   TIMESTAMP NULL,
    CONSTRAINT uq_desired_routing_policies_tenant_name
        UNIQUE (tenant, policy_name)
);
````

Indexes:

```sql
CREATE INDEX IF NOT EXISTS idx_desired_routing_policies_tenant
    ON desired_routing_policies (tenant);

CREATE INDEX IF NOT EXISTS idx_desired_routing_policies_active
    ON desired_routing_policies (tenant, active);
```

#### 4.1.3 Column Semantics

* `tenant`
  Logical tenant identifier, consistent with `desired_repos`.

* `policy_name`
  Name of the routing policy, mapping directly to the Director API
  field `policy_name`.

* `catch_all`
  Name of the repository used as the catch-all target, mapping to the
  Director API field `catch_all`. This should correspond to an
  existing `desired_repos.name` for the same tenant.

* `active`
  Optional flag indicating whether the policy should be active.

* `description`
  Optional free-text description for documentation purposes.

* `created_at`, `updated_at`
  Optional DB-level timestamps.

### 4.2 Routing Policy Rules (`desired_routing_policy_rules`)

#### 4.2.1 Purpose

The `desired_routing_policy_rules` table represents **individual routing
criteria** attached to a routing policy. Each row corresponds to one
element of the `routing_criteria` list in the Director API.

#### 4.2.2 Table Definition

```sql
CREATE TABLE IF NOT EXISTS desired_routing_policy_rules (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    routing_policy_id  BIGINT NOT NULL,
    criteria_index     INTEGER NOT NULL,
    repo               VARCHAR(255),
    drop               VARCHAR(32),
    type               VARCHAR(64),
    key                TEXT,
    value              TEXT,
    category           VARCHAR(32),
    operation          VARCHAR(32),
    prefix             BOOLEAN,
    event_key          TEXT,
    source_key         TEXT,
    value_type         VARCHAR(16),
    created_at         TIMESTAMP NULL,
    updated_at         TIMESTAMP NULL,
    CONSTRAINT fk_routing_policy
        FOREIGN KEY (routing_policy_id)
        REFERENCES desired_routing_policies (id)
        ON DELETE CASCADE
);

```

Index:

```sql
CREATE INDEX IF NOT EXISTS idx_routing_policy_rules_policy
    ON desired_routing_policy_rules (routing_policy_id);
```

#### 4.2.3 Column Semantics

The columns are intentionally aligned with the Director API routing
criteria fields.

* `routing_policy_id`
  Foreign key to `desired_routing_policies.id`.

* `criteria_index`
  Zero-based or one-based index defining the order of evaluation in
  the `routing_criteria` list.

* `repo`
  Target repository name for this criterion, mapping to the API field
  `repo`. This should reference an existing `desired_repos.name` for
  the same tenant when non-empty.

* `drop`
  Action flag, typically `"store"` or `"drop"`, mapping directly to
  the API field `drop`.

* `type`
  Criterion type, e.g. `"KeyPresent"`, `"KeyPresentValueMatches"`,
  or other values supported by Director.

* `key`, `value`
  Key and value associated with the criterion, mapping to the API
  fields `key` and `value`.

* `category`, `operation`, `prefix`, `event_key`, `source_key`,
  `value_type`
  Optional advanced fields corresponding to more sophisticated routing
  criteria variants described in the Director API documentation.

#### 4.2.4 Relationship with V2 Migration

In V2, routing policies were typically described with columns such as
`rule_type`, `key`, `value`, `repo`, `drop` in XLSX templates.

The V3 schema intentionally **drops V2-specific naming** and uses fields
aligned with the Director API.

Any XLSX → V3 mapping (for example, from V2 migration tools) should be
implemented in dedicated import scripts or transformers, not in the
steady-state schema.

## 5. Future Extensions

Future configuration types (alert rules, tenants, collectors, etc.) should
follow the same pattern:

- a `desired_*` table for each resource type,
- explicit `tenant` and `name` (or equivalent natural key),
- no migration-specific naming,
- additional auxiliary tables when 1..N relationships are required
  (like routing policy rules),
- clear mapping to a YAML resource profile and the Sync Engine.

Any migration-specific concerns (such as V2 XLSX column names) should be
handled by **separate import/migration scripts**, not encoded in the steady
state schema or naming.
