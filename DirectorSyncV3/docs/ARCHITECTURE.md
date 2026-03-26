# DirectorSync V3 – Architecture Overview

## 1. Purpose

DirectorSync V3 introduces a unified, extensible and database-driven synchronization framework for Logpoint Director.  
Its goals are:

- replace XLSX-based importers with an SQL-based desired state,
- unify all importer logic into a single Sync Engine,
- model configuration types using declarative YAML “Resource Profiles”,
- use reusable and composable “Transformers” for validation, enrichment, and structure building.

---

## 2. High-Level Architecture

```

+-----------------------+
|      CLI / Runner     |
+-----------------------+
|
v
+-----------------------+
|     ResourceProfile   |  <- YAML per resource type
+-----------------------+
|
v
+----------------------------------------+
|              SyncEngine                |
+----------------------------------------+
| 1. Load Desired (DB)                   |
| 2. Preprocess (Transformers)           |
| 3. Load Current (Director API)         |
| 4. Diff (canonical compare)            |
| 5. Plan + Dry-run                      |
| 6. Apply (create/update/delete)        |
| 7. Postprocess (Transformers)          |
| 8. Reporting                           |
+----------------------------------------+
|
+-------------------------------+
|                               |
v                               v
+-----------------------+       +---------------------------+
| DesiredStateLoader    |       | CurrentStateLoader        |
| (SQL)                 |       | (Director API)            |
+-----------------------+       +---------------------------+

```

---

## 3. Components

### 3.1 SyncEngine
The orchestrator.  
Executes the entire universal sync pipeline, calling loaders, transformer pipelines, diff engine, and apply engine.

### 3.2 ResourceProfile
Parses YAML and exposes:

- data source definition,
- Director API mapping,
- field mapping rules,
- canonical comparison rules,
- transformer pipelines (pre/post),
- dependencies.

### 3.3 DesiredStateLoader (DB)
Extracts desired state for a tenant from SQL tables based on the resource profile.

### 3.4 CurrentStateLoader (Director)
Fetches existing configuration through the Director API.

### 3.5 DiffEngine
Compares desired vs current using:

- key fields,
- canonical normalized fields,
- list normalization strategies.

Produces:
- NOOP  
- CREATE  
- UPDATE  
- DELETE (optional)  
- SKIP  

### 3.6 ApplyEngine
Executes POST/PUT/DELETE accordingly.

### 3.7 TransformerPipeline
Runs ordered lists of transformers:

- preprocess: before diff  
- postprocess: after apply  

### 3.8 DirectorClient
Generic HTTP wrapper with:

- base URL,
- bearer token,
- retry logic,
- logging,
- pagination-awareness.

---

## 4. Data Flow

1. Tenant & resource selected by CLI.  
2. YAML profile loaded → defines behaviour.  
3. Desired state pulled from DB.  
4. Preprocess transformers enrich/normalize.  
5. Current state fetched from Director.  
6. Canonical diff computed.  
7. Plan built; dry-run optionally stops here.  
8. Apply performed on Director.  
9. Post-transformers run (subresources, ID update).  
10. Reporting generated.

---

## 5. Extending V3

To add a new resource type:

1. Create SQL table.  
2. Write YAML profile.  
3. Implement any resource-specific transformers (if needed).  
4. Add no importer class, no engine modification.  

V3 is *configuration-first*.

