# DirectorSyncV3 – Project Context Summary

## 1. Overview

DirectorSyncV3 is a next-generation synchronization framework for **Logpoint Director**, replacing legacy XLSX-based importers with a **database-driven**, **YAML-configurable**, and **transformer-based** architecture.

The system aims to provide a **generic, extensible, and unified** pipeline able to synchronize any type of Director configuration object (Repos, Routing Policies, Alert Rules, etc.) using a reusable core engine and resource-specific profiles.

This project is co-developed (Gaetan + AI assistant) and is currently in the **early skeleton phase (V3 pre-design)**.

---

## 2. High-Level Goals

* Standardize all importer logic around **one universal sync pipeline**.
* Replace Excel ingestion with **SQL desired state tables**.
* Define synchronization behavior using **YAML resource profiles**.
* Support **preprocess/postprocess transformers**, both generic and resource-specific.
* Provide a **clean Python package (`lp_sync`)**, PEP-8 compliant, fully documented, safe, and testable.
* Enable **idempotent, dry-run-friendly** synchronization.
* Ensure **full logging, error handling, and traceability**.
* Deliver a framework that can scale to additional configuration types without new importer classes.

---

## 3. Current Scope (Phase 1)

The initial V3 scope focuses on two resource types:

1. **Repos**
2. **Routing Policies**

Each is described by its own YAML profile and will use a minimal set of early transformers.

---

## 4. Architecture Summary

### 4.1 Core Components

* **SyncEngine**
  Orchestrates the universal pipeline:

  1. Load desired state (SQL)
  2. Preprocess transformers
  3. Load current state (Director API)
  4. Diff engine
  5. Plan + dry-run
  6. Apply engine
  7. Post-transformers
  8. Reporting

* **ResourceProfile**
  YAML-defined behavior per resource, including mappings, API endpoints, comparison rules, and transformer pipelines.

* **DesiredStateLoader**
  Extracts desired items from SQL.

* **CurrentStateLoader**
  Fetches existing Director config.

* **DiffEngine**
  Produces canonical CREATE/UPDATE/DELETE/NOOP actions.

* **ApplyEngine**
  Executes actions via Director API.

* **TransformerPipeline**
  Runs ordered transformers on items before/after apply.

---

## 5. Transformers

### Generic Transformers (shared across all resources)

* validate_required
* normalize_lists
* coerce_types
* resolve_references
* jinja_render

### Resource-Specific Transformers (future expansion)

* Repos: normalize paths, repo HA logic
* Routing Policies: build routing criteria, apply repo aliases

---

## 6. YAML Resource Profiles

Each resource defines:

* SQL data source
* Director API endpoints
* Field mappings
* Comparison rules
* Pre/post transformer pipelines
* Dependencies

Example structure:

```yaml
resources:
  repos:
    data_source: ...
    api: ...
    mapping: ...
    comparison: ...
    preprocess: [...]
    postprocess: [...]
```

---

## 7. Project Structure (simplified)

```
DirectorSyncV3/
  lp_sync/
    core/
    transformers/
    profiles/
    utils/
    cli.py
  docs/
  db/
  scripts/
  tests/
  pyproject.toml
```

---

## 8. Development Constraints & Principles

* **Package name**: `lp_sync`
* **Project name**: `DirectorSyncV3`
* **Code language**: **English only**
* **Output language for explanations**: English (unless otherwise requested)
* **Coding guidelines**:

  * PEP-8 compliant
  * Fully documented (docstrings + comments)
  * Self-explanatory code (clear naming)
  * Full logging (debug + info + error paths)
  * Robust error handling (never crash silently)
* **Transformers and sync logic must be deterministic** and **idempotent**.

---

## 9. Current Status

* Skeleton project structure: ✔
* Core modules: ✔
* Basic CLI: ✔
* YAML profiles for Repos / Routing Policies: ✔
* Placeholder DB schema: ✔
* Archive tool: ✔
* Transformers (minimal): ✔

Next major steps:

1. Define SQL schema in `DATA_MODEL.md`
2. Implement real transformers for Repos & Routing Policies
3. Implement SyncEngine logic step by step
4. Integrate Director API v2 behaviour
5. Add end-to-end tests

---

## 10. Partner and Collaboration Context

This project is developed jointly by:

* **Gaetan (Logpoint engineer)**
* **AI assistant (OpenAI LLM)**

LLM must:

* maintain consistency with the V3 architecture
* follow strict coding rules
* never improvise behaviour outside the spec
* verify each step logically before coding
* help design, document, generate code, and validate choices

---

## 11. Summary for LLM

This context describes the entire **DirectorSyncV3** project: an extensible framework for synchronizing Logpoint Director configuration using **SQL + YAML + Transformers** wrapped in a reusable pipeline engine.

All future answers MUST respect this architecture, vocabulary, and constraints.

