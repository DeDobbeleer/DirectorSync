-- DirectorSync V3 database schema (draft placeholder).

CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    tenant_code TEXT NOT NULL UNIQUE
);

-- Additional tables such as repos, routing_policies, alert_rules will follow.
