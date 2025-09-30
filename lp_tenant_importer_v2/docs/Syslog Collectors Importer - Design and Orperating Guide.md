# Syslog Collectors Importer (V2) — Design & Operating Guide

> **Scope**: This document specifies the end-to-end design of the `syslog_collectors` importer for DirectorSync V2 — from framework integration to test coverage. It reflects **the corrected product truth** agreed during our exchanges (Excel is filtered on `app = SyslogCollector`, Device context only, no `log_collector` field, and the proxy rules described below).

---

## Table of Contents

1. [Framework Integration (recap)](#1-framework-integration-recap)
2. [Functional Contract (corrected product truth)](#2-functional-contract-corrected-product-truth)
   - [Scope & filtering](#21-scope--filtering)
   - [Required fields for Create/Update](#22-required-fields-for-both-create-post-and-update-put)
   - [Proxy rules](#23-proxy-rules-hard-requirements)
   - [Processing Policy resolution](#24-processing-policy-pp-resolution)
   - [APIs used](#25-apis-used-readwrite)
3. [Desired vs Existing & Idempotent Decision Logic](#3-desired-vs-existing--idempotent-decision-logic)
   - [Unit of Work & key](#31-unit-of-work--key)
   - [Loading & normalization (desired)](#32-loading--normalization-desired)
   - [Partition & ordering (3 phases)](#33-partition--ordering-3-phases)
   - [Discovering existing (SIEM)](#34-discovering-existing-siem)
   - [Canonical comparison & decisions](#35-canonical-comparison--decisions)
4. [Validation Rules & Error Catalog](#4-validation-rules--error-catalog)
   - [Validation matrix](#41-validation-matrix)
   - [Resolutions & dependencies](#42-resolutions--dependencies)
   - [Standard error codes/messages](#43-standard-error-codesmessages-examples)
5. [Execution Plan, Concurrency & Dry-Run](#5-execution-plan-concurrency--dry-run)
   - [Orchestration in 3 phases](#51-orchestration-in-3-phases)
   - [Dry-run semantics](#52-dry-run-semantics)
   - [Failure handling](#53-failure-handling)
6. [Reporting & Logging](#6-reporting--logging)
   - [Report (tabular)](#61-report-tabular)
   - [Logging](#62-logging)
7. [Test Plan (scenarios & acceptance)](#7-test-plan-scenarios--acceptance)
   - [Representative scenarios](#71-representative-scenarios)
   - [Acceptance criteria](#72-acceptance-criteria)
8. [Appendix A — Excel Sheet spec](#appendix-a--excel-sheet-syslogcollector-quick-spec)

---

## 1) Framework Integration (recap)

**Goal**: add `lp_tenant_importer_v2/importers/syslog_collectors.py` that plugs into the existing V2 framework without reinventing plumbing.

- **Importer lifecycle**: reuse `BaseImporter` pipeline  
  `load → validate → fetch_existing → diff → plan → apply → report`
- **Registration**: register under `key="syslog_collectors"` (CLI name: `import-syslog-collectors`) via `registry.py`.
- **HTTP layer**: use `DirectorClient` helpers exclusively (no hardcoded URLs).
- **Reporting**: use the common reporting utilities (same table/fields/semantics as other importers).
- **Targets**: driven by `tenants.yml` (`defaults.target.syslog_collectors`, typically `["backends"]`).

---

## 2) Functional Contract (corrected product truth)

### 2.1 Scope & filtering
- **Excel filter**: consider only rows where **`app = SyslogCollector`**.
- **Context**: **Device-based only** (no LCP in this project).  
  We always resolve the **Device ID** from the **Device name** in the XLSX.

### 2.2 Required fields for both Create (POST) and Update (PUT)
- **Device_id** — resolved from `device_name` via Devices API (mandatory)
- **Charset** (mandatory)
- **Parser** (mandatory)
- **Proxy_condition** ∈ `{use_as_proxy, uses_proxy, None}` (mandatory)

### 2.3 Proxy rules (hard requirements)
- **`use_as_proxy`**
  - `proxy_ip` **must be empty**
  - `hostname` **must be empty**
  - `processpolicy` **must be empty**
- **`uses_proxy`**
  - `proxy_ip` **must exist** (one or more IPs) and **each IP** must be backed by **at least one** `use_as_proxy` with the same IP (either already on the target SIEM or created from the same Excel in Phase 1).
  - `hostname` **must exist**
  - `processpolicy` **must exist**
- **`None`**
  - `proxy_ip` **must be empty**
  - `hostname` **must be empty**
  - `processpolicy` **must exist**

### 2.4 Processing Policy (PP) resolution
- In the Excel, you provide a **source PP ID**.  
  We map that ID to a **PP name** via the **`ProcessingPolicies`** sheet (source view).
- On the **target SIEM**, we resolve **PP name → PP ID** using the **ProcessingPolicy List** API.
- The importer always uses the **target PP ID** in payloads.  
  *(The `log_collector` field is deliberately ignored in this project.)*

### 2.5 APIs used (read/write)
- **Inventory & resolution**:  
  - `Devices/List`, `Devices/{id}/plugins` (to discover current SyslogCollector per device)  
  - `ProcessingPolicy/List` (to resolve PP name → target PP ID)  
  - (Optional) `Charsets/List` (to pre-validate `charset`)
- **Actions**:  
  - `POST /.../SyslogCollector` (Create)  
  - `PUT  /.../SyslogCollector/{id}` (Update)

> There is no global “SyslogCollector list”; **existing** collectors are discovered via `Devices/{id}/plugins` (plugin `app = SyslogCollector`).

---

## 3) Desired vs Existing & Idempotent Decision Logic

### 3.1 Unit of Work & key
- **1 Excel row ⇔ 1 SyslogCollector plugin on 1 device**.  
- **Key**: `device_name` (must be unique in the sheet) ⇒ resolved to `device_id`.

### 3.2 Loading & normalization (desired)
- Always require: `device_name`, `parser`, `charset`, `proxy_condition`.
- Enforce the proxy matrix (see §2.3).
- Lists (`proxy_ip`, `hostname`): split on `,` or `|`, trim, **deduplicate**, **sort** (order-insensitive compare).
- `parser`: must be in the allowed set (extendable if needed).
- `charset`: non-empty; if API allows, pre-validate against `Charsets/List`.
- `processpolicy`: if required by matrix, resolve to **target PP ID** (via name).

### 3.3 Partition & ordering (3 phases)
- Partition rows:  
  `A = use_as_proxy`, `B = None`, `C = uses_proxy`.
- Build an **XLSX proxy index**: `proxy_ip → {use_as_proxy rows}` (from `A`).
- **Execution order** (with barriers):  
  Phase 1 **A** → barrier (monitor complete + re-inventory) →  
  Phase 2 **B** → (optional barrier) →  
  Phase 3 **C** (allowed only if every `proxy_ip` exists on the SIEM after Phase 1).

### 3.4 Discovering existing (SIEM)
- For each `device_id`, call `Devices/{id}/plugins`, isolate `app=SyslogCollector`.
- Canonical **existing** object:
  - `collector_id` (UUID for PUT), `device_id`
  - `proxy_condition`, `parser`, `charset`
  - `processpolicy_id` (and cached name if needed)
  - `proxy_ip[]`, `hostname[]` (sorted, unique)

### 3.5 Canonical comparison & decisions
- Compare **desired vs existing** on relevant fields:
  - Always: `proxy_condition`, `parser`, `charset`
  - If `use_as_proxy`: assert `processpolicy=None` and empty `proxy_ip[]`, `hostname[]`
  - If `uses_proxy`: compare `processpolicy_id`, `proxy_ip[]`, `hostname[]`
  - If `None`: compare `processpolicy_id`, and empty `proxy_ip[]`, `hostname[]`
- **NOOP**: all relevant fields equal  
- **UPDATE**: plugin exists, at least one relevant field differs  
- **CREATE**: plugin absent  
- **SKIP**: validation/dependency failed (never call mutating APIs)

---

## 4) Validation Rules & Error Catalog

### 4.1 Validation matrix

| `proxy_condition` | `proxy_ip`                | `hostname`           | `processpolicy`           |
|---|---|---|---|
| `use_as_proxy`    | **must be empty**         | **must be empty**    | **must be empty**         |
| `uses_proxy`      | **required (≥1)** & each IP must be backed by ≥1 `use_as_proxy` on target after Phase 1 | **required (≥1)** | **required** (resolved to target PP ID) |
| `None`            | **must be empty**         | **must be empty**    | **required** (resolved to target PP ID) |

**Always required**: `device_name` (→ `device_id`), `parser`, `charset`, `proxy_condition`.

### 4.2 Resolutions & dependencies
- `device_name → device_id` via Devices/List (must be unique).
- `PP source id → PP name` via Excel `ProcessingPolicies` sheet → **target** `PP id` via ProcessingPolicy/List.
- `uses_proxy` IPs: verified **after Phase 1** against **SIEM inventory** (proxies actually created/existing).

### 4.3 Standard error codes/messages (examples)
- `E-SC-VAL-001 InvalidProxyCondition: expected one of {use_as_proxy, uses_proxy, None}.`
- `E-SC-VAL-002 DeviceNotFound: device="dc01" not found or ambiguous.`
- `E-SC-VAL-003 ParserInvalid: parser="XYZ" is not allowed.`
- `E-SC-VAL-004 CharsetInvalid: charset="…" unknown on target.`
- `E-SC-VAL-005 MissingField: <field> is required.`
- `E-SC-VAL-006 MustBeEmpty: proxy_ip must be empty for use_as_proxy/None.`
- `E-SC-VAL-007 MustBeEmpty: hostname must be empty for use_as_proxy/None.`
- `E-SC-VAL-008 MustBeEmpty: processpolicy must be empty for use_as_proxy.`
- `E-SC-DEP-001 MissingPP: processpolicy "name=…" not found on target.`
- `E-SC-DEP-002 MissingProxy: proxy_ip="x.x.x.x" has no use_as_proxy on target after Phase1.`
- `E-SC-API-4xx CreateFailed: HTTP 400 …`
- `E-SC-API-4xx UpdateFailed: HTTP 409 …`

> **Policy**: invalid lines are **SKIPped** (no POST/PUT). Dependency failures are **SKIP** with explicit reason.

---

## 5) Execution Plan, Concurrency & Dry-Run

### 5.1 Orchestration in 3 phases
1. **Phase 1 – `use_as_proxy`**  
   Apply all A (NOOP/UPDATE/CREATE). Wait for monitors to complete. **Re-inventory** SIEM.
2. **Phase 2 – `None`**  
   Apply all B. (Optional barrier + re-inventory.)
3. **Phase 3 – `uses_proxy`**  
   Only apply C rows whose **every `proxy_ip` is present** on SIEM (post-Phase 1). Otherwise **SKIP** with `E-SC-DEP-002`.

**Concurrency**: allowed **within** a phase; **not across** phase boundaries (barriers are mandatory).

### 5.2 Dry-run semantics
- Perform **all validations** and **all resolutions** (devices, PP, initial inventory).
- **Simulate** Phase 1 success for rows that would CREATE/UPDATE successfully, then evaluate Phase 3 against the **post-Phase-1 expected state**.
- Emit **“would CREATE/UPDATE/NOOP/SKIP”** decisions; **no** mutating API calls.

### 5.3 Failure handling
- If a Phase 1 proxy creation fails, all dependent Phase 3 rows referencing its IP **SKIP** with a message that points to the failed proxy.
- API failures are surfaced as `E-SC-API-…` with HTTP code and brief response excerpt.
- The importer remains **idempotent**: after a successful run, immediate re-run ⇒ **NOOP**.

---

## 6) Reporting & Logging

### 6.1 Report (tabular)
Same structure as other importers:

| siem | node | device | result | action | status | monitor_ok | monitor_branch | error | corr |
|---|---|---|---|---|---|---|---|---|---|

- **result**: `noop | update | create | skip`
- **action**: textual reason, e.g. `Identical`, `Create`, `Update: changed [parser, charset]`, `Skip: validation`, `Skip: missing dependency (proxy/PP)`
- **status/monitor**: populated from `DirectorClient` monitor helpers
- **error**: standardized code + message (see §4.3)
- **corr**: optional correction hint (e.g., `Provide processpolicy for None/uses_proxy`)

### 6.2 Logging
- **DEBUG**: normalized desired/existing payloads, diff details, device/PP resolution maps, proxy index, called endpoints (with token masking).
- **INFO**: per-phase summary (counts by `create/update/noop/skip`).
- **WARNING**: degradations and soft issues (e.g., optional API unavailability if ever relevant).
- **ERROR**: HTTP/API errors and unrecoverable failures.

> Logs must be sufficient to reconstruct decisions (why SKIP vs UPDATE, which dependency was missing, etc.).

---

## 7) Test Plan (scenarios & acceptance)

### 7.1 Representative scenarios
- **Validation & parsing**: invalid `proxy_condition`; invalid `parser`; invalid `charset` (if validated); missing mandatory fields; rule “must be empty”; duplicate `device_name`; unresolved device.
- **Phase 1 (`use_as_proxy`)**: create new proxy; update proxy; reject if `processpolicy` not empty.
- **Phase 2 (`None`)**: create with PP; reject if PP missing.
- **Phase 3 (`uses_proxy`)**:  
  - reference proxy created in Phase 1 (OK),  
  - reference proxy already present on SIEM (OK),  
  - mixed IPs (one missing) ⇒ SKIP,  
  - missing `hostname` ⇒ SKIP,  
  - missing `processpolicy` ⇒ SKIP.
- **Transitions** between proxy types (all six directions) respecting the matrix.
- **Idempotence**: re-run ⇒ NOOP.
- **Dry-run**: correct “would …” decisions including barrier-aware proxy checks.
- **Robustness**: PP not found; PP API unavailable; Create/Update API errors; device not accessible.

### 7.2 Acceptance criteria
1. **All validations** occur **before** any POST/PUT (non-dry runs).
2. **Phase order** strictly enforced with **re-inventory** after Phase 1.
3. `uses_proxy` is **never** applied if **any** referenced IP lacks a backing `use_as_proxy` on the SIEM (post-Phase 1).
4. **Idempotence**: unchanged inputs ⇒ 100% NOOP.
5. **Dry-run** mirrors real decisions with “would …” labels.
6. Report & logs are **consistent** with other importers and sufficiently diagnostic.

---

## Appendix A — Excel Sheet (SyslogCollector) quick spec

**Required columns** (after filtering `app = SyslogCollector`):
- `device_name`, `parser`, `charset`, `proxy_condition`  
- `proxy_ip` (only for `uses_proxy`) — list split by `,` or `|`  
- `hostname` (only for `uses_proxy`) — list split by `,` or `|`  
- `processpolicy` (PP **name** on target; name is obtained by mapping source PP ID → name via `ProcessingPolicies` sheet, then used to resolve target PP ID)

**Normalization**:
- Trim all cells; split lists on `,` or `|`; deduplicate & sort lists; enforce exact enum values.

**Uniqueness**:
- Exactly **one row per `device_name`**; extra rows are **SKIPped** as duplicates.
