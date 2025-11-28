"""Database schema definition for DirectorSyncV3 desired state tables.

This module defines the SQL DDL statements used to create the core
`desired_*` tables and exposes a helper function to apply the schema on a
PEP 249–compatible database connection.

The schema is:
- vendor-agnostic (PostgreSQL-friendly, but usable with SQLite),
- aligned with the V3 data model (no migration-specific naming),
- structured with a header + rules model for routing policies.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

LOGGER = logging.getLogger(__name__)


DESIRED_REPOS_DDL = """
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
"""

DESIRED_REPOS_INDEXES_DDL: tuple[str, ...] = (
    """
    CREATE INDEX IF NOT EXISTS idx_desired_repos_tenant
        ON desired_repos (tenant);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_desired_repos_active
        ON desired_repos (tenant, active);
    """,
)

DESIRED_ROUTING_POLICIES_DDL = """
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
"""

DESIRED_ROUTING_POLICIES_INDEXES_DDL: tuple[str, ...] = (
    """
    CREATE INDEX IF NOT EXISTS idx_desired_routing_policies_tenant
        ON desired_routing_policies (tenant);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_desired_routing_policies_active
        ON desired_routing_policies (tenant, active);
    """,
)

DESIRED_ROUTING_POLICY_RULES_DDL = """
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
"""

DESIRED_ROUTING_POLICY_RULES_INDEXES_DDL: tuple[str, ...] = (
    """
    CREATE INDEX IF NOT EXISTS idx_routing_policy_rules_policy
        ON desired_routing_policy_rules (routing_policy_id);
    """,
)

SCHEMA_DDL_STATEMENTS: tuple[str, ...] = (
    DESIRED_REPOS_DDL,
    *DESIRED_REPOS_INDEXES_DDL,
    DESIRED_ROUTING_POLICIES_DDL,
    *DESIRED_ROUTING_POLICIES_INDEXES_DDL,
    DESIRED_ROUTING_POLICY_RULES_DDL,
    *DESIRED_ROUTING_POLICY_RULES_INDEXES_DDL,
)

def apply_schema(connection: Any, statements: Iterable[str] | None = None) -> None:
    """Create or update the database schema on the given connection.

    Parameters
    ----------
    connection:
        A PEP 249–compatible DB-API connection object. It must expose
        ``cursor()``, ``commit()`` and ``rollback()`` methods.
    statements:
        Optional iterable of DDL statements to execute. When omitted,
        the default DirectorSyncV3 schema (`SCHEMA_DDL_STATEMENTS`) is used.

    Raises
    ------
    Exception
        Propagates any database error after rolling back the transaction.
    """
    ddl_statements = tuple(statements or SCHEMA_DDL_STATEMENTS)
    if not ddl_statements:
        LOGGER.info("No DDL statements provided, nothing to apply.")
        return

    cursor = connection.cursor()
    try:
        for ddl in ddl_statements:
            ddl_preview = " ".join(ddl.strip().splitlines()[:1])
            LOGGER.debug("Executing DDL: %s", ddl_preview)
            cursor.execute(ddl)
        connection.commit()
        LOGGER.info("Database schema successfully applied.")
    except Exception:
        connection.rollback()
        LOGGER.exception("Failed to apply database schema.")
        raise
    finally:
        cursor.close()
