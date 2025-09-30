Parfait — vous avez dit **GO** 👉 je bascule en **anglais** pour la documentation.

# AlertRules Importer — Spreadsheet-to-API Mapping (Spec)

**Scope.** This document maps every column in sheet **`Alert`** of `core_config.xlsx` (59 columns, 37 rows in the provided file) to the **Logpoint Director AlertRules API**: listing (fetch), creation, edit/update, activation, sharing, and per-type notifications. No code is included. All endpoint semantics are sourced from the official API docs for AlertRules (v2.8.0 at time of writing). ([docs.logpoint.com][1])

---

## 0) Sheet profile (as provided)

* Workbook sheets include: `Repo`, `RoutingPolicy`, `NormalizationPolicy`, `ProcessingPolicy`, `EnrichmentPolicy`, `EnrichmentRules`, `EnrichmentCriteria`, `Device`, `DeviceFetcher`, `DeviceGroups`, **`Alert`**.
* `Alert` has **59** columns (indices 0–58). Below is a full mapping for each.
  *(Source: your `core_config.xlsx`.)*

---

## 1) “List” (GET list) — which endpoint to use

Choose the **fetch** endpoint by scope (driven by your `tenant_scope` column):

* **My rules:** `POST …/AlertRules/MyAlertRules/fetch` — filters: `active` (bool), `log_source` ([string]). ([docs.logpoint.com][1])
* **Shared rules:** `POST …/AlertRules/SharedAlertRules/fetch` — filters: `active`, `log_source`. ([docs.logpoint.com][1])
* **Vendor rules:** `POST …/AlertRules/VendorAlertRules/fetch` — filter: `log_source`. ([docs.logpoint.com][1])
* **Used vendor rules:** `POST …/AlertRules/UsedAlertRules/fetch` — filters: `active`, `log_source`. ([docs.logpoint.com][1])
* **Used shared rules:** `POST …/AlertRules/UsedSharedAlertRules/fetch` — filters: `active`, `log_source`. ([docs.logpoint.com][1])

**Typical search keys from the sheet:** `name` (exact/like), `settings.active`, `settings.log_source`, `settings.repos`, `tenant_scope`.

---

## 2) Create / Edit — core endpoints & parameters

* **Create:** `POST …/AlertRules` (the rule definition). ([docs.logpoint.com][1])
* **Edit:** `PUT …/AlertRules/{id}` (same schema; plus path `id`). ([docs.logpoint.com][1])
* **Activate:** `POST …/AlertRules/{id}/activate` ; **Deactivate:** `POST …/AlertRules/{id}/deactivate`. ([docs.logpoint.com][1])

> The **Create** parameters explicitly documented include: `searchname`, `risk`, `repos`, `aggregate`, `condition_option`, `condition_value`, `limit`, `query`, `description`, `owner`, `assigned_to`, `attack_tag`, `log_source`, `metadata`, `alert_context_template`, `flush_on_trigger`, `search_interval_minute`, `timerange_minute|hour|day`, `throttling_*`, etc. (with specific required/optional flags). ([docs.logpoint.com][1])

---

## 3) Notifications — per-type sub-resources

For each notification object in `settings.notifications`:

* **Email:** `POST …/AlertRules/{id}/EmailNotification`. ([docs.logpoint.com][1])
* **Syslog:** `POST …/AlertRules/{id}/SyslogNotification`. ([docs.logpoint.com][1])
* **HTTP:** `POST …/AlertRules/{id}/HTTPNotification`. ([docs.logpoint.com][1])
* **SMS:** `POST …/AlertRules/{id}/SMSNotification`. ([docs.logpoint.com][1])
* **SNMP:** `POST …/AlertRules/{id}/SNMPNotification`. ([docs.logpoint.com][1])
* **SSH:** `POST …/AlertRules/{id}/SSHNotification`. ([docs.logpoint.com][1])

*(Each API section defines its own fields/flags such as `notify_email`, `notify_syslog`, `http_*`, `sms_*`, etc.)*

---

## 4) Sharing / Ownership (if present in your sheet)

* **Share with users/groups:** `POST …/AlertRules/{id}/share` with `rbac_config`. ([docs.logpoint.com][1])
* **Unshare:** `POST …/AlertRules/{id}/unshare`. ([docs.logpoint.com][1])
* **Transfer ownership:** `POST …/AlertRules/{id}/transferOwnership` with `userid`. ([docs.logpoint.com][1])

---

## 5) Column-by-column mapping (complete)

> Legend — **API usage**: C=Create, E=Edit, A=Activate/Deactivate, F=Fetch/list, S=Share/Unshare, N=Notification (sub-resource), R=Read-only/diagnostic.

### A) Identity, ownership & visibility

|  # | Spreadsheet column          | API usage | API field / endpoint                        | Notes                                                                        |
| -: | --------------------------- | --------- | ------------------------------------------- | ---------------------------------------------------------------------------- |
|  0 | `alert_index`               | R         | —                                           | Internal indexing only (not posted).                                         |
|  1 | `name`                      | C/E       | `searchname` (Create/Edit)                  | Primary display name. ([docs.logpoint.com][1])                               |
| 20 | `settings.name`             | C/E       | `searchname` (alt source)                   | Prefer `name` if both present.                                               |
|  2 | `settings.active`           | A         | call `…/activate` or `…/deactivate`         | Convert boolean to the appropriate call. ([docs.logpoint.com][1])            |
| 16 | `settings.user`             | C/E       | `owner`                                     | Owner user id (required in Create). ([docs.logpoint.com][1])                 |
| 21 | `settings.assigned_to`      | C/E       | `assigned_to`                               | Optional assignee. ([docs.logpoint.com][1])                                  |
|  9 | `settings.visible_to`       | S         | `…/share` `rbac_config.group_permissions[]` | Map to group IDs + permissions. ([docs.logpoint.com][1])                     |
| 15 | `settings.visible_to_users` | S         | `…/share` `rbac_config.user_permissions[]`  | Map to user IDs + permissions. ([docs.logpoint.com][1])                      |
| 24 | `settings.attack_tag`       | C/E       | `attack_tag`                                | Array of attack tag IDs. ([docs.logpoint.com][1])                            |
| 26 | `settings.metadata`         | C/E       | `metadata[{field,value}]`                   | Array of KV objects. ([docs.logpoint.com][1])                                |
| 58 | `tenant_scope`              | F         | choose fetch endpoint                       | Drives which fetch to call (My/Shared/Vendor/Used). ([docs.logpoint.com][1]) |

### B) Description & risk model

|  # | Column                 | API usage | Field         | Notes                              |        |                                           |                                                |
| -: | ---------------------- | --------- | ------------- | ---------------------------------- | ------ | ----------------------------------------- | ---------------------------------------------- |
|  3 | `settings.description` | C/E       | `description` | Optional. ([docs.logpoint.com][1]) |        |                                           |                                                |
| 14 | `settings.risk`        | C/E       | `risk`        | `low                               | medium | high                                      | critical` (required). ([docs.logpoint.com][1]) |
| 17 | `settings.aggregate`   | C/E       | `aggregate`   | `min                               | max    | avg` (required). ([docs.logpoint.com][1]) |                                                |

### C) Repos & sources

|  # | Column                | API usage | Field                                | Notes                                                                    |
| -: | --------------------- | --------- | ------------------------------------ | ------------------------------------------------------------------------ |
|  6 | `settings.repos`      | C/E       | `repos`                              | Required array; resolve to valid repo IDs/keys. ([docs.logpoint.com][1]) |
| 25 | `settings.log_source` | C/E/F     | `log_source` (C/E) ; filter in fetch | Optional in create; useful filter in fetch. ([docs.logpoint.com][1])     |

### D) Query & time window

|  # | Column                                            | API usage | Field(s)                 | Notes                                                           |
| -: | ------------------------------------------------- | --------- | ------------------------ | --------------------------------------------------------------- |
| 30 | `settings.livesearch_data.query`                  | C/E       | `query`                  | Primary query text. ([docs.logpoint.com][1])                    |
|  5 | `settings.extra_config.query`                     | C/E       | (merge to) `query`       | Secondary/extra filters if you use them.                        |
| 37 | `settings.livesearch_data.searchname`             | C/E       | `searchname`             | Alt source of name.                                             |
| 47 | `settings.livesearch_data.timerange_minute`       | C/E       | `timerange_minute`       | Use one of minute/hour/day. ([docs.logpoint.com][1])            |
| 35 | `settings.livesearch_data.timerange_hour`         | C/E       | `timerange_hour`         | — ([docs.logpoint.com][1])                                      |
| 46 | `settings.livesearch_data.timerange_day`          | C/E       | `timerange_day`          | — ([docs.logpoint.com][1])                                      |
|  4 | `settings.time_range_seconds`                     | C/E       | derive → `timerange_*`   | Convert seconds to one of the above.                            |
| 48 | `settings.livesearch_data.limit`                  | C/E       | `limit`                  | Required ≥1. ([docs.logpoint.com][1])                           |
| 55 | `settings.livesearch_data.search_interval_minute` | C/E       | `search_interval_minute` | Optional interval. ([docs.logpoint.com][1])                     |
| 11 | `settings.data_privacy_request`                   | C/E       | `original_data` (bool)   | If using original/encrypted data flag. ([docs.logpoint.com][1]) |
| 33 | `settings.livesearch_data.description`            | R         | —                        | Descriptive text for UI; not part of Create spec.               |
| 32 | `settings.livesearch_data.generated_by`           | R         | —                        | Diagnostic.                                                     |
| 36 | `settings.livesearch_data.timerange_second`       | R         | —                        | Seconds granularity is not an API field; convert.               |

### E) Trigger behavior & throttling

|  # | Column                                      | API usage | Field                   | Notes                                                           |
| -: | ------------------------------------------- | --------- | ----------------------- | --------------------------------------------------------------- |
| 10 | `settings.flush_on_trigger`                 | C/E       | `flush_on_trigger`      | Use `"on"` when true. ([docs.logpoint.com][1])                  |
| 29 | `settings.livesearch_data.flush_on_trigger` | C/E       | `flush_on_trigger`      | Same effect; prefer top-level if both.                          |
| 49 | `settings.throttling_enabled`               | C/E       | `throttling_enabled`    | `"on"` when true. ([docs.logpoint.com][1])                      |
| 52 | `settings.throttling_field`                 | C/E       | `throttling_field`      | Required if throttling is on. ([docs.logpoint.com][1])          |
| 51 | `settings.throttling_time_range`            | C/E       | `throttling_time_range` | Minutes; required if throttling is on. ([docs.logpoint.com][1]) |

### F) Condition (threshold for result count/metric)

|  # | Column                                | API usage | Field              | Notes                                                                   |
| -: | ------------------------------------- | --------- | ------------------ | ----------------------------------------------------------------------- |
| 18 | `settings.condition.condition_option` | C/E       | `condition_option` | e.g., `greaterthan`, `equalsto`, … (required). ([docs.logpoint.com][1]) |
| 19 | `settings.condition.condition_value`  | C/E       | `condition_value`  | Integer ≥0 (required). ([docs.logpoint.com][1])                         |

### G) Context template & simple view

|  # | Column                                 | API usage | Field                     | Notes                                                |
| -: | -------------------------------------- | --------- | ------------------------- | ---------------------------------------------------- |
| 50 | `settings.context_template`            | C/E       | `alert_context_template`  | Jinja template text. ([docs.logpoint.com][1])        |
| 27 | `settings.is_context_template_enabled` | C/E       | may toggle template usage | When true, ensure template provided.                 |
| 53 | `settings.simple_view`                 | N (Email) | `simple_view` (email)     | Email-notif option if used. ([docs.logpoint.com][1]) |

### H) Notifications (multi-type via `settings.notifications`)

|  # | Column                   | API usage | Endpoint & key fields                                                                | Notes                       |
| -: | ------------------------ | --------- | ------------------------------------------------------------------------------------ | --------------------------- |
| 22 | `settings.notifications` | N         | For each item by `type`: **Email**, **Syslog**, **HTTP**, **SMS**, **SNMP**, **SSH** | See per-type mapping below. |

**Per-type keys commonly seen in sheets (map to the corresponding endpoint fields):**

* **Email** → `…/EmailNotification`: `notify_email` (“on”), `email_emails` ([to]), `subject`, `email_template` (body), `email_threshold_option/value`, `simple_view`, `dispatch_option`, `logo_enable`, `b64_logo`, `link_disable`, etc. ([docs.logpoint.com][1])
* **Syslog** → `…/SyslogNotification`: `notify_syslog` (“on”), `server`, `port`, `protocol` (UDP/TCP), `facility`, `severity`, `message`, `split_rows`, `threshold_option/value`, `dispatch_option`. ([docs.logpoint.com][1])
* **HTTP** → `…/HTTPNotification`: `notify_http` (“on”), `http_url`, `http_request_type` (GET/POST/…), `http_body`, `http_header` (incl. auth), `http_querystring`, `http_threshold_option/value`, `dispatch_option`. ([docs.logpoint.com][1])
* **SMS** → `…/SMSNotification`: `notify_sms` (“on”), `sms_server`, `sms_port`, `sms_sender`, `sms_password`, `sms_receivers` ([tel]), `sms_body`, `sms_threshold_option/value`, `dispatch_option`. ([docs.logpoint.com][1])
* **SNMP** → `…/SNMPNotification`: `notify_snmp` (“on”), `snmp_agent` (+ version/security fields), plus threshold/dispatch if applicable. ([docs.logpoint.com][1])
* **SSH** → `…/SSHNotification`: `notify_ssh` (“on”), `ssh_server`, `ssh_port`, `ssh_auth_type` (password|key), `ssh_username`, `ssh_auth_password`/**key**, `ssh_command`, threshold/dispatch. ([docs.logpoint.com][1])

> **Posting sequence:** Create/Edit the rule first, then attach per-type notifications with the rule `id`.

### I) Read-only / export-only fields (do not send on Create/Edit)

|                # | Column                                                              | Reason                                                                                                      |
| ---------------: | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
|                7 | `settings.vid`                                                      | Version id from exports.                                                                                    |
|                8 | `settings.used_from`                                                | Usage metadata.                                                                                             |
|               11 | `settings.data_privacy_request`                                     | Typically maps to behavior flags; you will post `original_data` instead in Create. ([docs.logpoint.com][1]) |
|               12 | `settings.version`                                                  | Export metadata.                                                                                            |
|               13 | `settings.tid`                                                      | Tenant id from export.                                                                                      |
|               23 | `settings.alertrule_id`                                             | The rule id (path param for Edit/Activate/Notifications).                                                   |
|               28 | `settings.livesearch_data.vid`                                      | Export metadata.                                                                                            |
|               33 | `…livesearch_data.description`                                      | UI helper text; not in Create spec.                                                                         |
| 38–45, 54, 56–57 | `settings.livesearch_data.query_info.*` and `…data_privacy_request` | Derived/diagnostic (fieldsToExtract, grouping, lucene_query…); not part of Create/Edit spec.                |

---

## 6) Minimal field set required to Create

From the API contract, a **valid Create** requires at least:

* `searchname` (→ `name` / `settings.livesearch_data.searchname`)
* `owner` (→ `settings.user`)
* `risk` (→ `settings.risk`)
* `repos` (→ `settings.repos`)
* `aggregate` (→ `settings.aggregate`)
* `condition_option` + `condition_value` (→ `settings.condition.*`)
* `limit` (→ `settings.livesearch_data.limit`)
* `timerange_minute` **or** (`timerange_hour`/`timerange_day`) (→ `settings.livesearch_data.timerange_*` or convert from `settings.time_range_seconds`)
  Optional but common: `query`, `description`, `search_interval_minute`, `flush_on_trigger`, `metadata`, `manageable_by`, `log_source`, `attack_tag`, `alert_context_template`. ([docs.logpoint.com][1])

---

## 7) Activation, Sharing & Ownership

* After create/edit, drive **active state** by calling `…/activate` or `…/deactivate` based on `settings.active`. ([docs.logpoint.com][1])
* Apply **sharing** from `settings.visible_to` / `settings.visible_to_users` via `…/share` with `rbac_config`; remove all with `…/unshare`. ([docs.logpoint.com][1])
* Transfer ownership with `…/transferOwnership` if you store a target `userid`. ([docs.logpoint.com][1])

---

## 8) Operational checklists (no code)

### A) Create (idempotent-ready payload assembly)

1. Resolve identities: `owner`, `assigned_to`, groups/users in visibility, `attack_tag`, `repos`, `log_source`.
2. Build **timerange** from `settings.livesearch_data.timerange_*` (or convert from seconds).
3. Validate **requireds**: `searchname`, `owner`, `risk`, `repos`, `aggregate`, `condition_*`, `limit`, `timerange_*`.
4. Attach optional flags: `flush_on_trigger` (“on”), `throttling_*` (when enabled), `search_interval_minute`, `alert_context_template`, `metadata`, `manageable_by`, `original_data`.
5. **POST** to `…/AlertRules`. ([docs.logpoint.com][1])
6. If `settings.active` = true, **POST** `…/activate`. ([docs.logpoint.com][1])
7. For each item in `settings.notifications`, call the matching **Notification** sub-endpoint. ([docs.logpoint.com][1])
8. If visibility set, **POST** `…/share` with `rbac_config`. ([docs.logpoint.com][1])

### B) Update (safe merge)

1. Fetch by scope (`tenant_scope`) + `name` to get `id`. ([docs.logpoint.com][1])
2. Re-build the same Create shape from the sheet; **PUT** `…/AlertRules/{id}`. ([docs.logpoint.com][1])
3. Synchronize active state, notifications (create/update pattern varies by API), sharing and ownership as needed.

### C) List (reporting/reconciliation)

* Use the appropriate **Fetch*** endpoint and optionally filter by `active` and/or `log_source`. ([docs.logpoint.com][1])

---

## 9) Example: one row → endpoint calls (verbally, no code)

* **Identify row:** read `name`, `settings.user`, `settings.risk`, `settings.repos`, `settings.aggregate`, `settings.condition.*`, `settings.livesearch_data.limit`, window, `query`.
* **Create:** `POST …/AlertRules` with those fields (plus optional `description`, `alert_context_template`, `metadata`, …). ([docs.logpoint.com][1])
* **Activate?** If `settings.active` = true → `POST …/activate`. ([docs.logpoint.com][1])
* **Notifications:** For each element of `settings.notifications`, call its sub-endpoint (Email/Syslog/…); pass type-specific parameters from the object. ([docs.logpoint.com][1])
* **Share:** If visibility columns are set → `POST …/share` with `rbac_config`. ([docs.logpoint.com][1])

---

## 10) Notes & conversions

* **Booleans → “on” flags:** `flush_on_trigger`, `throttling_enabled`, `notify_*` fields are strings accepting `"on"` per API; convert from boolean sheet values. ([docs.logpoint.com][1])
* **Timerange normalization:** supply either `timerange_minute` **or** hour/day (convert from `settings.time_range_seconds` if needed). ([docs.logpoint.com][1])
* **Read-only/diagnostic:** columns under `…query_info.*` (fieldsToExtract, grouping, lucene_query, etc.) are not Create/Edit parameters; treat them as export diagnostics.

---

### Appendix — Quick index of AlertRules endpoints (for this importer)

* Activate / Deactivate / Create / Edit: see “Page Contents” and sections on the AlertRules page. ([docs.logpoint.com][1])
* FetchMyRules / FetchSharedRules / FetchVendorRules / FetchUsedRules / FetchUsedSharedRules. ([docs.logpoint.com][1])
* Notifications: Email / Syslog / HTTP / SMS / SNMP / SSH. ([docs.logpoint.com][1])
* Share / Unshare / TransferOwnership. ([docs.logpoint.com][1])

---

If you want, I can now turn this spec into:

* an **import contract** (JSON field dictionary) and
* a **test checklist** (per endpoint, with sample payloads/states),

still **documentation-only**, or proceed directly to implementation when you say “GO code”.

[1]: https://docs.logpoint.com/docs/api-documentation/en/latest/AlertRules.html "AlertRules — API Documentation latest documentation"
