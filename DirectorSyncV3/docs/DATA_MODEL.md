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

In V2 XLSX templates, repositories were described with columns such as:

- `repo_number`
- `original_repo_name`
- `cleaned_repo_name`
- `storage_paths`
- `retention_days`
- `active`
- `used_size`

In V3, we keep the functional semantics but remove migration-specific naming.
`name` becomes the canonical repository name, typically derived from the former
`cleaned_repo_name`. The remaining fields are kept in a form that is easy to
populate from XLSX while being stable for the Sync Engine.

### 3.2 Table Definition (Logical)

```sql
CREATE TABLE desired_repos (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant          VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,  -- V3 canonical repo name
    description     TEXT,
    order_index     INTEGER,                -- typically from XLSX repo_number
    storage_paths   TEXT,                   -- raw, e.g. "/data_hot | /cold_nfs"
    retention_days  TEXT,                   -- raw, e.g. "90 | 275"
    is_enabled      BOOLEAN,                -- from XLSX "active"
    used_size       TEXT,                   -- raw "11583.08301 MB"
    created_at      TIMESTAMP NULL,
    updated_at      TIMESTAMP NULL,
    CONSTRAINT uq_desired_repos_tenant_name
        UNIQUE (tenant, name)
);
```

Field semantics:

- `tenant`: logical owner of the repository (e.g. `CORE`).
- `name`: canonical repository name in V3.
- `description`: optional free-text description.
- `order_index`: optional ordering hint, usually imported from XLSX
  `repo_number`.
- `storage_paths`: raw representation of paths, often a pipe-separated list
  (e.g. `"/data_hot | /cold_nfs"`). Transformers can later normalize this into
  a structured format for the Director API.
- `retention_days`: raw representation of retention configuration, possibly
  multi-valued (e.g. `"90 | 275"`).
- `is_enabled`: whether the repo should be active (from XLSX `active`).
- `used_size`: raw size string, including units, as present in the source.
- `created_at`, `updated_at`: optional timestamps managed by the application
  or the database.

### 3.3 Recommended Indexes

```sql
CREATE INDEX idx_desired_repos_tenant
    ON desired_repos (tenant);

CREATE INDEX idx_desired_repos_enabled
    ON desired_repos (tenant, is_enabled);
```

These indexes support common queries such as “list all desired repos for a
tenant” or “list all enabled repos for a tenant”.

### 3.4 Mapping from V2 XLSX (Informative)

A typical V2 XLSX → V3 import mapping for repos is:

- `name`             ← `cleaned_repo_name`
- `order_index`      ← `repo_number`
- `storage_paths`    ← `storage_paths`
- `retention_days`   ← `retention_days`
- `is_enabled`       ← `active`
- `used_size`        ← `used_size`

This mapping is implemented in separate migration/import scripts, not in the
Sync Engine itself.

---

## 4. Routing Policies Data Model

Routing policies are modeled using **two tables**:

- `desired_routing_policies` (policy header, 1 row per policy),
- `desired_routing_policy_rules` (rules/criteria, 1..N rows per policy).

This reflects the semantics of the V2 XLSX, where columns like
`rule_type`, `key`, `value`, `repo`, `drop` define specific criteria that can
appear multiple times for a single logical routing policy.

### 4.1 Routing Policy Header (`desired_routing_policies`)

#### 4.1.1 Purpose

The `desired_routing_policies` table represents the high-level definition of a
routing policy:

- its canonical name in V3,
- whether it is enabled,
- its catch-all target repository,
- an optional external identifier (e.g. a Director `policy_id`),
- optional metadata (description, timestamps).

In V2 XLSX templates, header-related information typically comes from columns
like:

- `original_policy_name`
- `cleaned_policy_name`
- `active`
- `catch_all`
- `policy_id`

In V3, we keep a single canonical `name` and remove migration-specific naming.

#### 4.1.2 Table Definition (Logical)

```sql
CREATE TABLE desired_routing_policies (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant              VARCHAR(255) NOT NULL,
    name                VARCHAR(255) NOT NULL,  -- V3 canonical policy name
    description         TEXT,
    is_enabled          BOOLEAN,               -- from XLSX "active"
    catch_all_repo_name VARCHAR(255),          -- from XLSX "catch_all"
    external_id         VARCHAR(255),          -- from XLSX "policy_id"
    created_at          TIMESTAMP NULL,
    updated_at          TIMESTAMP NULL,
    CONSTRAINT uq_desired_routing_policies_tenant_name
        UNIQUE (tenant, name)
);
```

Field semantics:

- `tenant`: logical owner of the routing policy.
- `name`: canonical routing policy name in V3.
- `description`: optional free-text description.
- `is_enabled`: whether the policy should be active (from XLSX `active`).
- `catch_all_repo_name`: name of the repository used as catch-all (from XLSX
  `catch_all`).
- `external_id`: optional identifier used to link to an existing Director
  routing policy (from XLSX `policy_id` when present).

#### 4.1.3 Recommended Indexes

```sql
CREATE INDEX idx_desired_routing_policies_tenant
    ON desired_routing_policies (tenant);

CREATE INDEX idx_desired_routing_policies_enabled
    ON desired_routing_policies (tenant, is_enabled);
```

These indexes support common queries such as “list all policies for a tenant”
or “list all enabled policies for a tenant”.

#### 4.1.4 Mapping from V2 XLSX (Informative)

A typical V2 XLSX → V3 import mapping for routing policy headers is:

- `name`                ← `cleaned_policy_name`
- `is_enabled`          ← `active`
- `catch_all_repo_name` ← `catch_all`
- `external_id`         ← `policy_id`

Again, this mapping is implemented in migration/import scripts.

---

### 4.2 Routing Policy Rules (`desired_routing_policy_rules`)

#### 4.2.1 Purpose

The `desired_routing_policy_rules` table represents individual rules or
criteria attached to a routing policy.

In V2 XLSX templates, the following columns define per-rule behavior:

- `rule_type`
- `key`
- `value`
- `repo`
- `drop` (e.g. `store` / `drop`)

There can be **multiple such rules** per logical routing policy. V3 models this
explicitly as a separate table with a foreign key to
`desired_routing_policies`.

#### 4.2.2 Table Definition (Logical)

```sql
CREATE TABLE desired_routing_policy_rules (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    routing_policy_id   BIGINT NOT NULL,
    rule_index          INTEGER,          -- for preserving evaluation order
    rule_type           TEXT,             -- from XLSX "rule_type"
    key_name            TEXT,             -- from XLSX "key"
    value_expression    TEXT,             -- from XLSX "value"
    target_repo_name    VARCHAR(255),     -- from XLSX "repo"
    action              VARCHAR(32),      -- from XLSX "drop" (e.g. "store"/"drop")
    created_at          TIMESTAMP NULL,
    updated_at          TIMESTAMP NULL,
    CONSTRAINT fk_routing_policy
        FOREIGN KEY (routing_policy_id)
        REFERENCES desired_routing_policies (id)
        ON DELETE CASCADE
);
```

Field semantics:

- `routing_policy_id`: foreign key referencing the header row in
  `desired_routing_policies`.
- `rule_index`: optional integer to preserve the rule order as defined in the
  original XLSX (e.g. line number or explicit priority).
- `rule_type`: textual discriminator describing how to interpret the rule
  (e.g. `KeyPresentValueMatches`, ...).
- `key_name`: the field or attribute to match (from XLSX `key`).
- `value_expression`: the expected value or expression (from XLSX `value`).
- `target_repo_name`: the repository name targeted by this rule (from XLSX
  `repo`).
- `action`: describes what to do when the rule matches (e.g. `"store"` or
  `"drop"` from XLSX `drop`).

#### 4.2.3 Recommended Indexes

```sql
CREATE INDEX idx_routing_policy_rules_policy
    ON desired_routing_policy_rules (routing_policy_id);
```

#### 4.2.4 Mapping from V2 XLSX (Informative)

For each row in the V2 routing policy sheet:

- Find or create the corresponding policy header in
  `desired_routing_policies` (based on `cleaned_policy_name` and `tenant`).
- Insert a row into `desired_routing_policy_rules` with:
  - `rule_type`        ← `rule_type`
  - `key_name`         ← `key`
  - `value_expression` ← `value`
  - `target_repo_name` ← `repo`
  - `action`           ← `drop`
  - `rule_index`       ← line number or another ordering hint

---

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
