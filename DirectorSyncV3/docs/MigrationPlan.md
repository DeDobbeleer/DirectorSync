# **Logpoint – DirectorSync V3 Migration Plan**

## **1. Introduction**

This document describes the migration strategy from the current **DirectorSync v2 framework** (multi-importer architecture, XLSX-driven) toward a new **DirectorSync V3** based on:

* a **unified generic sync engine**,
* **external database–driven configuration**,
* **YAML-based resource profiles**,
* and **generic + resource-specific transformers** orchestrated as pipelines.

The objective is to significantly reduce custom Python logic per importer, improve maintainability, ensure idempotence, and allow new configuration types to be added through configuration rather than code.

---

# **2. High-Level Objectives**

### **2.1. Simplify the architecture**

* Replace multiple importer classes with a single, generic sync engine.
* Remove direct XLSX parsing logic.
* Reduce code duplication across importers.

### **2.2. Externalize the desired configuration**

* All desired state is extracted from an **external SQL database**.
* XLSX files (tenant, core) will only be used as *optional loaders* during transition.

### **2.3. Configuration-driven behaviour**

* Each configuration type (Alert Rules, PP, EP, Collectors, etc.) is fully defined via:

  * a **resource profile in YAML**
  * a set of **pipeline transformers**

### **2.4. Improve maintainability and extensibility**

* Add new config types without writing new importer code.
* Add/modify rules by writing or adjusting a transformer.

---

# **3. Universal Sync Pipeline (V3)**

The V3 pipeline is **identical for all configuration types**.
Only configuration (YAML) + transformers change.

### **Step 1 – Context Loading**

* Tenant selection
* Resource type selection
* Load resource profile (YAML)

### **Step 2 – Desired State Loading**

* Fetch desired configuration from **external DB**:

  * table name
  * tenant column
  * unique key
  * external_id column
* Normalize DB values into internal model (“raw desired state”).

### **Step 3 – Pre-Processing (Transformers)**

Ordered pipeline of transformations:

* validation rules
* Jinja templating
* reference resolution (repos, groups, devices)
* type coercion
* MITRE enrichment
* metadata extraction
* domain-specific business rules

Output: **clean, normalised desired state**.

### **Step 4 – Current State Loading**

* Request current configuration via Director API.
* Normalise into comparable objects.

### **Step 5 – Diff / Decision Engine**

Compare desired vs current using:

* functional key (name, id, etc.)
* canonical fields defined in YAML
* normalisation rules (set, sorted lists, kv lists …)

Decision:

* `NOOP`
* `CREATE`
* `UPDATE`
* `DELETE` (optional per resource strategy)
* `SKIP` (preprocessor request)

### **Step 6 – Plan & Dry-Run**

* Construct complete list of actions.
* In dry-run → output the plan without touching Director.

### **Step 7 – Apply**

* Perform the actions using Director API:

  * core payload create/update/delete
  * error handling & retries
  * dependency ordering (declared in YAML)

### **Step 8 – Post-Processing**

Another ordered pipeline:

* update external_id in DB
* manage subresources (RBAC, notifications, sources, etc.)
* validate or patch final state
* logging/auditing hooks

### **Step 9 – Reporting**

* Summary per tenant, per resource type
* Created / Updated / No-op / Skipped / Errors
* Optional export (json, log, DB)

---

# **4. Resource Profiles (YAML)**

Each resource type is defined by a **single YAML block** describing:

### **4.1. Data Source**

```yaml
data_source:
  type: sql
  table: alert_rules
  tenant_column: tenant_code
  external_id_column: external_id
  unique_key: ["name"]
```

### **4.2. Director API Endpoints**

```yaml
api:
  core:
    list:
      endpoint: /api/director/v2/alert-rules
      method: GET
    create:
      endpoint: /api/director/v2/alert-rules
      method: POST
    update:
      endpoint: /api/director/v2/alert-rules/{id}
      method: PUT

  subresources:
    rbac:
      endpoint: /api/director/v2/alert-rules/{id}/rbac
      method: PUT
```

### **4.3. Field Mapping**

```yaml
mapping:
  fields:
    name: name
    risk: severity
    query: query
    description: description
  collections:
    repos:
      column: repos
      type: list
```

### **4.4. Comparison Rules**

```yaml
comparison:
  key_fields: ["name"]
  canonical_fields:
    - severity
    - query
    - description
    - repos
  list_normalization:
    repos:
      mode: set
```

### **4.5. Pre-/Post-Processing Pipelines**

```yaml
preprocess:
  - transformer: validate_required
    params:
      fields: ["name", "query"]

  - transformer: jinja_render
    params:
      fields: ["query"]

  - transformer: resolve_references
    params:
      refs:
        repos:
          from: repos
          lookup: director.repos.by_name

postprocess:
  - transformer: update_external_id_in_db
  - transformer: alert_rules_apply_rbac
```

---

# **5. Transformer Architecture**

Transformers provide **all flexibility** of V3.

## **5.1 Types of Transformers**

### **Generic Transformers (shared by all resources)**

* `validate_required`
* `normalize_lists`
* `coerce_types`
* `jinja_render`
* `resolve_references`
* `metadata_from_columns`
* `mark_disabled_if_flag`

### **Resource-Specific Transformers**

* **AlertRules**

  * `alert_rules_business_rules`
  * `alert_rules_apply_notifications`
  * `alert_rules_apply_rbac`
* **Processing Policies**

  * `pp_build_condition_tree`
* **Syslog Collectors**

  * `collectors_build_input_output`

## **5.2 Transformer Specification**

Each transformer defines:

* name
* scope (`generic` or resource-specific)
* phase (`pre` or `post`)
* parameters
* error behaviour (`fail_item`, `skip_item`, `ignore`)
* expected input/output structure

Transformers must be:

* **idempotent**
* **pure** (no hidden side effects)
* **composable**

---

# **6. Database Model (High Level)**

### **6.1. Principles**

* One table per resource type *or* one generic table + JSONB payload.
* Each row describes a desired configuration item.
* Required fields:

  * tenant_code
  * unique key
  * external_id (Director ID, nullable)
  * main config fields
  * raw payload (JSONB) for advanced cases

### **6.2. Example**

```sql
CREATE TABLE alert_rules (
    id SERIAL PRIMARY KEY,
    tenant_code TEXT NOT NULL,
    external_id TEXT,
    name TEXT NOT NULL,
    severity TEXT,
    query TEXT,
    metadata JSONB,
    mitre_techniques TEXT[],
    enabled BOOLEAN DEFAULT TRUE,
    raw_payload JSONB,
    UNIQUE(tenant_code, name)
);
```

---

# **7. Migration Strategy**

## **7.1 Phase 1 — Inventory & Classification**

For each V2 importer:

* extract all logic and split between:

  * **generic transformer candidate**
  * **resource-specific transformer**
  * **static mapping that moves to YAML**
  * **hardcoded sequences → pipeline steps**

Outputs:

* Global transformer catalog
* First version of YAML schema

## **7.2 Phase 2 — Database Model Definition**

* Define all tables required
* Build initial DB loader (convert XLSX → DB)
* Build tenant/environment metadata tables

## **7.3 Phase 3 — Generic Engine Implementation**

A minimal version with:

* desired loader (DB)
* current loader (Director)
* diff engine
* apply engine
* transformer pipeline engine
* reporting

## **7.4 Phase 4 — Build Transformers**

* Implement generic transformers first
* Implement AlertRules as the **pilot resource**
* Validate correctness & idempotence

## **7.5 Phase 5 — Resource Profiles**

* Write YAML profile for:

  * AlertRules
  * PP
  * EP
  * Collectors
  * Repos
  * Device Groups
  * UDLs

## **7.6 Phase 6 — Validation & Rollout**

* Parallel-run V2 and V3 on selected tenants
* Compare results (automatic diff)
* Documentation + handover to internal teams

---

# **8. Deliverables**

* V3 Sync Engine (Python package)
* Transformer Library (generic + domain-specific)
* Resource Profile YAMLs
* Database schema & migrations
* CLI Tool (`lp-sync`)
* Migration scripts (XLSX → DB)
* Documentation (architecture, onboarding)
* Test suite + sample configs

---

# **9. Benefits**

### **Operational**

* Faster onboarding of new customers
* Less error-prone than XLSX manipulation
* Unified sync logic → simpler debugging

### **Engineering**

* Clear separation of responsibilities
* Reduced codebase size
* Faster time to introduce new resource types
* Testable transformers
* Declarative behaviour (YAML), predictable output

---

# **10. Conclusion**

DirectorSync V3 modernizes and unifies the entire configuration synchronization process:

* One pipeline
* One engine
* Database-driven desired state
* YAML profiles for each resource
* Transformers for flexibility
* Minimal code per configuration type

V3 is designed to be **predictable, maintainable, extensible, testable, and future-proof**.
