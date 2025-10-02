# AlertRules (MyRules) Importer — Spec & XLSX Mapping (DirectorSync v2)

**Status:** Frozen scope for *MyRules* only.  
**Out of scope (deferred):** Shared/Vendor/Used*, share/unshare/transferOwnership, ownership transfer, notifications (Email/HTTP/SMS/SNMP/SSH/Syslog).

## 1) Scope & Goals

This document defines the exact fields, endpoints, and XLSX mapping used by the **AlertRules (MyRules)** importer in DirectorSync v2. The importer only handles **MyRules** and supports the standard lifecycle: **NOOP / CREATE / UPDATE / SKIP**. Activation state is converged after create/update.

## 2) Endpoints (Config API)

All endpoints are relative to:
```
/configapi/{pool_UUID}/{logpoint_identifier}
```

- **List (fetch existing MyRules for diffing):**  
  `POST /AlertRules/MyAlertRules/fetch`
  - Optional filters: `active` (bool), `log_source` ([string])

- **Create:**  
  `POST /AlertRules`  
  Body: `{ "data": { ...fields below... } }`

- **Edit:**  
  `PUT /AlertRules/{id}`  
  Body: `{ "data": { ...fields below... } }`

- **Activate / Deactivate:**  
  `POST /AlertRules/{id}/activate`  
  `POST /AlertRules/{id}/deactivate`  
  Body: `{ "data": {} }`

## 3) Request Fields (Create/Edit) and XLSX Mapping

> **Note:** Request bodies always use a root key `data`. The table below shows the request field, type, requiredness, the **XLSX column** in the provided file (`core_config.xlsx`, sheet `Alert`), and any transformation applied.

| API field | Type | Required | XLSX column (sheet `Alert`) | Transform / Notes |
|---|---|---:|---|---|
| `searchname` | string | **Yes** | `name` | Use as-is. If blank, row is **SKIP** (reason: missing required). |
| `owner` | string | **Yes** | *(not present in provided sheet)* | **Dependency**: resolve to a valid user ID externally or via tenant defaults; if missing → **SKIP**. |
| `risk` | string | **Yes** | `settings.risk` | Must be one of: `low / medium / high / critical`. |
| `repos` | array of string | **Yes** | `settings.repos` | Expect a list (IDs or resolvable names). **Dependency**: resolve names → IDs. |
| `aggregate` | string | **Yes** | `settings.aggregate` | One of: `min / max / avg`. |
| `condition_option` | string | **Yes** | `settings.condition.condition_option` | E.g. `greaterthan / lessthan / equalsto / moreequal / lessequal / notequal`. |
| `condition_value` | integer | **Yes** | `settings.condition.condition_value` | Integer ≥ 0. |
| `limit` | integer | **Yes** | `settings.livesearch_data.limit` | Integer ≥ 1. |
| `timerange_minute` | integer | *Yes\*** | `settings.livesearch_data.timerange_minute` | Provide at least one of the timerange fields (minute/hour/day). If seconds only are present, convert to minutes (ceil). |
| `timerange_hour` | integer | *Yes\*** | `settings.livesearch_data.timerange_hour` | Same rule as above. |
| `timerange_day` | integer | *Yes\*** | `settings.livesearch_data.timerange_day` | Same rule as above. |
| `query` | string | No | `settings.extra_config.query` (fallback: `settings.livesearch_data.query`) | Prefer `settings.extra_config.query` if both exist. |
| `description` | string | No | `settings.description` | — |
| `log_source` | array of string | No | `settings.log_source` | If present, pass as list. |
| `assigned_to` | string | No | `settings.assigned_to` | Must resolve to a valid user ID. |
| `attack_tag` | array of string | No | `settings.attack_tag` | **Dependency**: resolve MITRE ATT&CK tags → IDs. |
| `metadata` | array of object | No | `settings.metadata` | Expect an array of `{ field, value }`. |
| `apply_jinja_template` | "on" | No | `settings.is_context_template_enabled` | Map truthy to `"on"`. |
| `alert_context_template` | string | No | `settings.context_template` | — |
| `flush_on_trigger` | "on" | No | `settings.flush_on_trigger` | Map truthy to `"on"`. Ignore any duplicate under `livesearch_data`. |
| `throttling_enabled` | "on" | No | `settings.throttling_enabled` | Map truthy to `"on"`. |
| `throttling_field` | string | Cond. | `settings.throttling_field` | Required if throttling is enabled. |
| `throttling_time_range` | integer (minutes) | Cond. | `settings.throttling_time_range` | Required if throttling is enabled. |
| `search_interval_minute` | integer | No | `settings.livesearch_data.search_interval_minute` | — |
| `original_data` | boolean | No | *(not present as such)* | **Do not map** from `settings.data_privacy_request`. Only set if explicitly requested. |
| `delay_interval_minute` | integer | No | *(not present)* | Requires specific system setting; typically not used. |

### Columns observed in `core_config.xlsx` (sheet `Alert`)
A (non-exhaustive) subset of relevant columns identified in the provided file:
- `name`, `settings.active`, `settings.description`, `settings.time_range_seconds`,  
  `settings.extra_config.query`, `settings.repos`, `settings.flush_on_trigger`, `settings.risk`,  
  `settings.assigned_to`, `settings.attack_tag`,  
  `settings.livesearch_data.timerange_hour`, `settings.livesearch_data.timerange_second`,  
  `settings.livesearch_data.searchname`, `settings.livesearch_data.timerange_day`,  
  `settings.livesearch_data.timerange_minute`, `settings.livesearch_data.limit`,  
  `settings.throttling_enabled`

> The importer will **ignore** fields marked out-of-scope and will **SKIP** any row missing a required field after transformation (with a clear reason).

## 4) Dependencies (Resolvers)

- **Repos**: map names/URIs from `settings.repos` to repository IDs.  
- **Users**: resolve values for `owner` (required) and `assigned_to` (optional).  
- **MITRE ATT&CK**: translate `settings.attack_tag` into ATT&CK IDs used by the API.

If a dependency cannot be resolved (e.g., repo name not found), the row becomes **SKIP** with an explicit error in the report.

## 5) Idempotence & Diff

- **Key:** `searchname` (from `name`) is the stable key to correlate XLSX rows and existing rules.
- **Fingerprint:** compare only the **scoped** fields above (ignoring out-of-scope and system-managed attributes).
- **Outcomes:**
  - **NOOP:** identical fingerprint.
  - **CREATE:** not found by `searchname`.
  - **UPDATE:** found but fingerprint differs; send `PUT` with the mapped fields.
  - **SKIP:** missing requireds or unresolved dependencies (reason included).

## 6) Activation Convergence

After CREATE/UPDATE, the importer reconciles activation based on `settings.active`:
- If `true`, call `POST /AlertRules/{id}/activate`.
- If `false`, call `POST /AlertRules/{id}/deactivate`.
- No change if the state already matches.

## 7) Error Handling & Logging

- All HTTP requests are logged at DEBUG with token masking.
- Each row result includes `result` (noop/create/update/skip), `action`, `status` (monitor outcome if relevant), and `error` (if any).

## 8) Future Work (explicitly deferred)

- Vendor/Shared/Used* rule scopes.  
- Sharing, unsharing, and ownership transfer.  
- Notification sub-resources (Email, Syslog, HTTP, SMS, SNMP, SSH).

---

**Appendix A — Example Minimal `data` payload (Create)**

```json
{
  "data": {
    "searchname": "Failed Admin Logins burst",
    "owner": "user-uuid-123",
    "risk": "high",
    "aggregate": "max",
    "condition_option": "greaterthan",
    "condition_value": 10,
    "limit": 100,
    "timerange_minute": 15,
    "repos": ["repo-uuid-1", "repo-uuid-2"],
    "query": "norm_id=Authentication action=Failure user=admin"
  }
}
```

**Appendix B — Example Update fields**  
Same structure as Create; include only fields we manage in scope.