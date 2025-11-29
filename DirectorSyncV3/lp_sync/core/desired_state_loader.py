"""Desired state loader.

This module contains logic to load the desired configuration state for a
given resource type and tenant from the SQL database.

It is intentionally generic:
- It only knows about the structure of `data_source` in the resource
  profile.
- It does not embed any resource-specific business logic.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Sequence

from lp_sync.utils.logging import get_logger


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class DesiredStateLoader:
    """Load desired state from the configured data source."""

    def __init__(self, connection: Any) -> None:
        """Create a new DesiredStateLoader.

        Args:
            connection: A DB-API compatible connection object. The concrete
                driver (psycopg, sqlite3, etc.) is configured elsewhere.
        """
        self._connection = connection
        self._logger = get_logger(self.__class__.__name__)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def load(self, profile: Any, tenant_code: str) -> List[Dict[str, Any]]:
        """Load desired items for a resource and tenant.

        The method supports two patterns for `data_source`:

        - simple table:
            data_source:
              table: desired_repos
              tenant_column: tenant
              key_columns: [tenant, name]

        - header + children:
            data_source:
              header: { ... }
              children:
                - alias: ...
                  table: ...
                  foreign_key_column: ...
                  order_column: ...
                  tenant_column: ...

        Args:
            profile: Resource profile that describes the data source. It may be
                a dataclass with a `data_source` attribute or a plain dict with
                a `data_source` key.
            tenant_code: Tenant identifier (used to filter rows).

        Returns:
            A list of dictionaries representing desired items (header rows
            potentially enriched with child collections).
        """
        data_source = self._extract_data_source(profile)
        if not data_source:
            resource_name = getattr(profile, "name", "<unknown>")
            self._logger.warning(
                "No data_source defined for resource '%s'. Returning empty list.",
                resource_name,
            )
            return []

        # Header + children (generic pattern)
        if "header" in data_source:
            return self._load_header_with_children(data_source, tenant_code)

        # Simple single-table resource
        if "table" in data_source:
            return self._load_table(
                table=data_source["table"],
                tenant_column=data_source.get("tenant_column", "tenant"),
                tenant_code=tenant_code,
                key_columns=data_source.get("key_columns") or [],
            )

        raise ValueError(
            f"Unsupported data_source configuration: {data_source!r}"
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _extract_data_source(self, profile: Any) -> Mapping[str, Any]:
        """Extract the data_source mapping from a profile-like object."""
        # Dataclass-style profile with a data_source attribute
        if hasattr(profile, "data_source"):
            ds = getattr(profile, "data_source")
            if isinstance(ds, Mapping):
                return ds

        # Dataclass-style profile exposing raw YAML in .raw
        raw = getattr(profile, "raw", None)
        if isinstance(raw, Mapping) and "data_source" in raw:
            ds = raw["data_source"]
            if isinstance(ds, Mapping):
                return ds

        # Plain dict profile
        if isinstance(profile, Mapping) and "data_source" in profile:
            ds = profile["data_source"]
            if isinstance(ds, Mapping):
                return ds

        return {}

    def _load_header_with_children(
        self,
        data_source: Mapping[str, Any],
        tenant_code: str,
    ) -> List[Dict[str, Any]]:
        """Load a header table and attach child rows defined in data_source.

        Expected shape:

        data_source:
          header:
            table: ...
            tenant_column: tenant
            key_columns: [tenant, policy_name]
            id_column: id           # optional, default "id"

          children:
            - alias: "criteria_rows"
              table: ...
              foreign_key_column: routing_policy_id
              order_column: criteria_index
              tenant_column: tenant
        """
        header_cfg = data_source.get("header") or {}
        if not isinstance(header_cfg, Mapping):
            raise ValueError(f"Invalid header configuration: {header_cfg!r}")

        header_table = str(header_cfg["table"])
        header_tenant_column = str(header_cfg.get("tenant_column", "tenant"))
        header_key_columns: Sequence[str] = header_cfg.get(
            "key_columns", []
        ) or []
        header_id_column = str(header_cfg.get("id_column", "id"))

        headers = self._load_table(
            table=header_table,
            tenant_column=header_tenant_column,
            tenant_code=tenant_code,
            key_columns=header_key_columns,
        )

        children_cfg = data_source.get("children") or []
        if not children_cfg:
            return headers

        # For each child definition, load its rows and attach to headers
        for child_def in children_cfg:
            if not isinstance(child_def, Mapping):
                raise ValueError(
                    "Invalid child configuration in data_source.children: "
                    f"{child_def!r}"
                )

            alias = str(child_def["alias"])
            table = str(child_def["table"])
            fk_column = str(child_def["foreign_key_column"])
            tenant_col = str(
                child_def.get("tenant_column", header_tenant_column)
            )
            order_column = child_def.get("order_column")

            child_rows = self._load_table(
                table=table,
                tenant_column=tenant_col,
                tenant_code=tenant_code,
                key_columns=[fk_column] + ([order_column] if order_column else []),
            )

            # Index child rows by foreign key
            by_fk: Dict[Any, List[Dict[str, Any]]] = {}
            for row in child_rows:
                fk_value = row.get(fk_column)
                if fk_value is None:
                    continue
                by_fk.setdefault(fk_value, []).append(row)

            # Attach the collection under the alias
            for header in headers:
                header_id = header.get(header_id_column)
                attached = by_fk.get(header_id, [])
                header[alias] = attached

        return headers

    def _load_table(
        self,
        table: str,
        tenant_column: str,
        tenant_code: str,
        key_columns: Sequence[str] | None = None,
    ) -> List[Dict[str, Any]]:
        """Load rows from a single table filtered by tenant."""
        if self._connection is None:
            self._logger.warning(
                "No DB connection available. Returning empty desired state "
                "for table '%s'.",
                table,
            )
            return []

        table_sql = self._validate_identifier(table, kind="table")
        tenant_col_sql = self._validate_identifier(tenant_column, kind="column")

        order_by_clause = ""
        if key_columns:
            cols = [
                self._validate_identifier(col, kind="column")
                for col in key_columns
            ]
            order_by_clause = " ORDER BY " + ", ".join(cols)

        sql = (
            f"SELECT * FROM {table_sql} "
            f"WHERE {tenant_col_sql} = %s"
            f"{order_by_clause}"
        )

        cursor = self._connection.cursor()
        try:
            cursor.execute(sql, (tenant_code,))
            rows = cursor.fetchall()
            column_names = (
                [desc[0] for desc in cursor.description]
                if cursor.description
                else []
            )
        finally:
            try:
                cursor.close()
            except Exception:  # pragma: no cover - defensive
                self._logger.exception(
                    "Failed to close DB cursor for table '%s'.", table_sql
                )

        return [dict(zip(column_names, row)) for row in rows]

    def _validate_identifier(self, value: str, kind: str) -> str:
        """Ensure a table/column name is safe to interpolate into SQL."""
        if not _IDENTIFIER_RE.match(value):
            raise ValueError(
                f"Invalid {kind} name {value!r}: only letters, digits and "
                f"underscore are allowed, and it cannot start with a digit."
            )
        return value
