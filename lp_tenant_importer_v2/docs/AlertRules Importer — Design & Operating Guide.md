# AlertRules Importer (v2) — Design & Operating Guide

> DirectorSync v2 framework — English-only technical documentation. Mirrors the style and rigor of the existing v2 importer docs (e.g., Processing Policies).

---

## 1) Purpose & Scope

The **AlertRules importer** ingests rows from the `Alert` sheet in the tenant XLSX and reconciles them against Logpoint Director **Alert Rules** via the v2 framework (`BaseImporter`).

**Objectives**

* Parse the spreadsheet **once**, normalize fields, and build a canonical **desired state** for each alert rule.
* **Plan** deterministic actions (NOOP/CREATE/UPDATE/SKIP) by diffing only the **core rule subset** (not post-apply sub-resources).
* **Apply** in a stable, idempotent sequence:

  1. Create/Update the **core rule**;
  2. Sync **active state** (activate/deactivate);
  3. Apply **sharing** (RBAC: groups/users);
  4. Apply **notifications** by type (Email, Syslog, HTTP, SMS, SNMP, SSH).
* Report status with monitor tracking and actionable error messages.

> This importer deliberately keeps sub-resources (state/sharing/notifications) **outside the diff** to keep planning simple and idempotent; they are reconciled in **post-apply**.

---

## 2) Framework Anchors (v2)

* Base class: `importers/base.py → class BaseImporter` (pipeline: `load → validate → fetch → diff → apply → report`).
* Hooks implemented by this importer:

  * `validate`, `iter_desired`, `key_fn`, `canon_desired`, `canon_existing`, `fetch_existing`, `build_payload_create`, `build_payload_update`, `apply`.
* Registry entry (CLI binding): key `alert_rules`, CLI `import-alert-rules`.

**CLI shape (common trunk)**

```
python -m lp_tenant_importer_v2.main \
  --tenant <tenant_name> \
  --tenants-file <tenants.yml> \
  --xlsx <path/to/config.xlsx> \
  [--dry-run] [--no-verify] \
  import-alert-rules
```

---

## 3) Spreadsheet Contract — `Alert` Sheet

**Required columns** (case-insensitive):

* `name` (→ `searchname`)
* `settings.user` (→ `owner`)
* `settings.risk`
* `settings.repos` (list)
* `settings.aggregate`
* `settings.condition.condition_option`
* `settings.condition.condition_value`
* **At least one** duration: `settings.livesearch_data.timerange_minute` **or** `...timerange_hour` **or** `...timerange_day` **or** `settings.time_range_seconds`
* `settings.livesearch_data.limit`

**Recommended optionals**

* `settings.livesearch_data.query` (or `settings.extra_config.query`)
* `settings.description`
* `settings.flush_on_trigger` (bool)
* `settings.livesearch_data.search_interval_minute`
* `settings.throttling_enabled`, `settings.throttling_field`, `settings.throttling_time_range`
* `settings.metadata` (JSON array of `{field,value}` or CSV `k=v|k2=v2`)
* `settings.log_source` (list)
* `settings.context_template`
* `settings.active` (bool → used for activate/deactivate)
* `settings.visible_to` (groups), `settings.visible_to_users` (users)
* `settings.notifications` (JSON array of typed notification objects)
* `tenant_scope` (drives fetch flavor: My/Shared/Vendor/Used)

**Ignored (export-only/diagnostic)**

* Any `...query_info.*`, `settings.version|vid|tid|used_from`, etc.

---

## 4) Desired Model & Canonical Core

For each row, the importer builds a `_DesiredAlert` with four zones:

* **core** (Create/Edit fields):

  * `searchname`, `owner`, `risk`, `repos[]`, `aggregate`,
  * `condition_option`, `condition_value`, `limit`,
  * **one** of `timerange_day|hour|minute` (convert seconds → minutes if needed),
  * `query`, `description`, `flush_on_trigger`, `search_interval_minute`,
  * `throttling_enabled|field|time_range`, `metadata[{field,value}]`, `log_source[]`,
  * `alert_context_template`.
* **state**: `active` (bool → Activate/Deactivate after core change).
* **rbac**: `visible_to_groups[]`, `visible_to_users[]` → Share/Unshare.
* **notifications**: list of typed objects (`type: email|syslog|http|sms|snmp|ssh`, plus type-specific fields).

**Canonical comparison subset** (diff keys):
`risk, repos, aggregate, condition_option, condition_value, limit,
 timerange_key+timerange_value, query, description, flush_on_trigger,
 search_interval_minute, throttling_enabled, throttling_field, throttling_time_range,
 metadata (as CSV k=v), log_source (CSV), context_template`.

> Only the **core subset** participates in planning; RBAC/notifications/state are reconciled after.

---

## 5) Validation

* Ensures presence of `Alert` sheet and the **required columns**.
* Friendly numeric checks: `limit >= 1`, one timerange present.
* Tolerates aliasing (e.g., `settings.livesearch_data.query` **or** `settings.extra_config.query`).

**Failure policy**

* Missing required column ⇒ **ValidationError** (importer stops early).
* Missing data in a row ⇒ **ValidationError** pointing the rule name.

---

## 6) Fetch Existing Rules

The importer attempts, in order, until one succeeds:

1. `GET configapi/{pool}/{node}/AlertRules` (direct list)
2. `POST .../AlertRules/MyAlertRules/fetch` (monitor)
3. `POST .../AlertRules/SharedAlertRules/fetch` (monitor)
4. `POST .../AlertRules/VendorAlertRules/fetch` (monitor)

It adapts common payload shapes (`result[]`, `data[]`, `response.result[]`, etc.) and returns a map `{searchname → rule_obj_with_id}`.

> If IDs are missing after Create (edge case), a fallback **re-fetch by name** ensures we recover the rule id for post-apply steps.

---

## 7) Planning (Diff Engine)

* Uses `canon_desired(row)` vs `canon_existing(obj)` to decide **NOOP / CREATE / UPDATE**.
* **Excluded** from the diff: `active`, `visible_to*`, `notifications`.
* Lists are normalized (trim, dedupe, sort) and rendered as CSV for stable diffs.

---

## 8) Apply Sequence

1. **Core**

   * CREATE → `POST .../AlertRules` (+ monitor job if returned)
   * UPDATE → `PUT .../AlertRules/{id}` (+ monitor job)

2. **State**

   * `settings.active = true` → `POST .../AlertRules/{id}/activate` (monitor if any)
   * `false` → `POST .../AlertRules/{id}/deactivate`

3. **Sharing / RBAC**

   * If `visible_to*` provided → `POST .../AlertRules/{id}/share` with `rbac_config`.
   * If no visibility desired → `POST .../AlertRules/{id}/unshare`.

4. **Notifications** (for each item in `settings.notifications`)

   * Email → `POST .../AlertRules/{id}/EmailNotification`
   * Syslog → `POST .../AlertRules/{id}/SyslogNotification`
   * HTTP → `POST .../AlertRules/{id}/HTTPNotification`
   * SMS → `POST .../AlertRules/{id}/SMSNotification`
   * SNMP → `POST .../AlertRules/{id}/SNMPNotification`
   * SSH → `POST .../AlertRules/{id}/SSHNotification`

**Idempotence policy for notifications**

* Current implementation posts desired notifications **deterministically** per type (idempotent upsert pattern). If the Director API later exposes per-type read endpoints, this can be extended to a **diff-based** reconcile (NOOP/CREATE/UPDATE/DELETE by type + key).

---

## 9) External Dependencies & Resolution

* **Repos**: values in the sheet must be resolvable to repository identifiers acceptable by the API.
* **Users/Groups**: `owner`, `assigned_to`, and `rbac_config` require valid IDs (or resolvable names).
* **Attack tags** (if used): ensure values align with Director identifiers.
* **Log sources**: must match accepted identifiers.
* **Notification targets**: ensure reachability and correctness (Syslog host/port, HTTP URL/headers, SMS/SNMP/SSH backends, etc.).

> Like other v2 importers, name→ID resolution can be kept in per-node caches during `fetch_existing` or preflight lookup steps.

---

## 10) Data Conversions & Normalization

* **Timerange**: prefer `timerange_day|hour|minute`; if only `time_range_seconds` is present, convert to minutes (≥1).
* **Booleans → "on" flags**: `flush_on_trigger`, `throttling_enabled`, and `notify_*` become string flags (`"on"`) when truthy; otherwise omitted.
* **Lists**: `repos`, `log_source`, RBAC members → normalized (trim, dedupe, sort).
* **Metadata**: accept JSON array of `{field,value}` or CSV `k=v` items; stored canonically as an array.

---

## 11) Error Handling & SKIP Policy

* **SKIP**: when a required *dependency* is missing (unknown repo/user/group, invalid field), return SKIP with a human-friendly reason and keep the run going.
* **FAIL**: for hard API/transport errors (HTTP 4xx/5xx unrelated to operator data) — surfaced with API message.
* **Monitor**: if a job-id/monitor URL is returned, the importer waits and attaches the `monitor_branch` to the report.

---

## 12) Observability & Reporting

* Per-row result table columns (common trunk): `siem | node | name | result | action | status | monitor_ok | monitor_branch | error | corr`.
* Logging levels: DEBUG (payload previews), INFO (plan/apply milestones), WARNING (soft post-apply failures), ERROR (hard failures). Tokens are masked by the common HTTP logging utilities.

---

## 13) Test Checklist

**Dry-run (no API calls):**

* With a known-good `Alert` sheet: expect full **NOOP** on second run.
* Missing required columns: importer stops with `ValidationError`.
* Mixed timerange sources: seconds → minutes conversion verified.

**Create path:**

* Minimal row with required fields only.
* With `active=true`: verify activate call.
* With RBAC groups/users: share posted and monitor OK.
* With notifications: each type posts once with expected fields.

**Update path:**

* Change any diff key (e.g., `risk`, `condition_value`) → UPDATE.
* Non-diff changes (RBAC/notifications/state only) → still **NOOP** in plan; mutations happen in post-apply.

**Error paths:**

* Unknown repo/user/group: SKIP with clear message.
* Syslog/HTTP target invalid: WARNING on post-apply, core success preserved.

---

## 14) Known Limitations & Future Work

* **Notifications diff**: currently upsert-only. Extend to read+diff when API surfaces per-type reads.
* **Per-scope fetch**: importer tries My/Shared/Vendor fetches; add `tenant_scope`-driven selection to reduce calls if needed.
* **Name→ID resolvers**: centralize and cache on the common trunk if resolution complexity grows across modules.

---

## 15) Field Reference (Create/Edit — core subset)

**Required**: `searchname`, `owner`, `risk`, `repos`, `aggregate`, `condition_option`, `condition_value`, `limit`, one `timerange_*`.

**Common optional**: `query`, `description`, `alert_context_template`, `flush_on_trigger`, `search_interval_minute`, `throttling_*`, `metadata[]`, `log_source[]`.

**Post-apply**: `active` (state), `visible_to*` (share/unshare), `notifications[]` (per-type).

---

## 16) Examples (payload shapes)

> JSON examples are illustrative; actual HTTP is encapsulated by `DirectorClient`.

**Create core**

```json
{
  "searchname": "Suspicious Admin Logins",
  "owner": "u_123",
  "risk": "high",
  "repos": ["repo-core"],
  "aggregate": "avg",
  "condition_option": "greaterthan",
  "condition_value": 0,
  "limit": 100,
  "timerange_minute": 15,
  "query": "label=windows AND action=logon AND user IN (\"Administrator\")",
  "description": "Detects Administrator logins",
  "flush_on_trigger": "on",
  "search_interval_minute": 5,
  "throttling_enabled": "on",
  "throttling_field": "host",
  "throttling_time_range": 10,
  "metadata": [{"field": "owner_team", "value": "SOC"}],
  "log_source": ["windows"],
  "alert_context_template": "{{ message }}"
}
```

**Email notification**

```json
{
  "notify_email": true,
  "email_emails": ["soc@example.com"],
  "subject": "[ALERT] Suspicious Admin Logins",
  "email_template": "<p>{{ message }}</p>",
  "email_threshold_option": "minute",
  "email_threshold_value": 1
}
```

**Syslog notification**

```json
{
  "notify_syslog": true,
  "server": "syslog-relay",
  "port": 514,
  "protocol": "UDP",
  "facility": 13,
  "severity": 5,
  "message": "{{ message }}"
}
```

---

## 17) Operational Tips

* Keep names (`searchname`) unique per tenant/scope.
* Start with **core-only** rows; add RBAC and notifications progressively.
* Prefer JSON for `settings.notifications` to avoid parsing ambiguity.
* Ensure repository and user/group identifiers are resolvable on the target Director.

---

**Status**: Ready for implementation and operations. This document will be updated as new API read-backs for notifications/sharing become available for fine-grained diffs.
