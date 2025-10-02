# AlertRules Import — Users & Groups Dependencies, Endpoints, and Migration Playbook

> **Scope:** This note consolidates how *users*, *user groups*, and *incident groups* interact with **AlertRules** in DirectorSync v2-style importers, the API endpoints you need, and a pragmatic action plan for migration where the **user base is not migrated** (manual user provisioning). It also includes a small CLI design and code to list `Alert Name`, `Owner`, `Assign_to`, and `Visible_for` from your Excel (`core_config.xlsx`).

---

## 1) Concepts & Entities that affect AlertRules

- **User**: the account that can be set as `owner` and/or `assigned_to` in an AlertRule.
- **IncidentUserGroup**: groups that can be used in AlertRules for *manageability* (e.g., who can manage incidents created by the rule).
- **UserGroup**: “classic” user groups (RBAC). May be referenced in sharing/visibility.
- **Sharing (RBAC)**: effective visibility of a rule is typically applied *after* creation via a `share` endpoint, where you provide an RBAC configuration for users and/or groups.

**Key AlertRule fields tied to users/groups:**

- `owner` (**required**): user ID (string).
- `assigned_to` (optional): user ID (string).
- `manageable_by` (optional): list of **IncidentUserGroup** IDs (strings).
- **Visibility** (a.k.a. `visible_to_users` in the spreadsheet): implemented by `share`/`unshare` endpoints after the rule exists; it can include user-level permissions and/or group-level permissions.

> **Migration requirement you stated:** the user base will **not** be migrated automatically (manual provisioning). **Therefore:** if a rule references a non-existent user (owner/assigned_to) or non-existent group, **skip** those assignments in the import and leave an audit trail.

---

## 2) AlertRules API endpoints (CRUD, fetch, sharing)

Because plain `GET /AlertRules` may be disallowed, the platform exposes *fetch jobs* per scope:

- **Fetch existing** (by scope/job):
  - `POST /configapi/{pool_uuid}/{logpoint_identifier}/AlertRules/MyAlertRules/fetch`
  - `POST /configapi/{pool_uuid}/{logpoint_identifier}/AlertRules/SharedAlertRules/fetch`
  - `POST /configapi/{pool_uuid}/{logpoint_identifier}/AlertRules/VendorAlertRules/fetch`
  - Monitor job status via:  
    `GET /monitorapi/{pool_uuid}/{logpoint_identifier}/orders/{job_uuid}` (or equivalent job URL returned by the fetch/create call).

- **Create an AlertRule**  
  `POST /configapi/{pool_uuid}/{logpoint_identifier}/AlertRules`  
  **Payload highlights (user/group dependencies):**
  - `owner` (**string**, **required**): an existing user ID
  - `assigned_to` (**string**, optional): an existing user ID
  - `manageable_by` (**string[]**, optional): IDs of **IncidentUserGroups**

- **Update an AlertRule**
  `PUT /configapi/{pool_uuid}/{logpoint_identifier}/AlertRules/{id}`

- **Delete (Trash) an AlertRule**
  `DELETE /configapi/{pool_uuid}/{logpoint_identifier}/AlertRules/{id}`

- **Share / Unshare (visibility)**
  - `POST /configapi/{pool_uuid}/{logpoint_identifier}/AlertRules/{id}/share`
    - Body includes RBAC-like config, e.g. user-level permissions (`READ`, `EDIT`, `FULL`) and/or group-level permissions.
  - `POST /configapi/{pool_uuid}/{logpoint_identifier}/AlertRules/{id}/unshare`

> **Note on monitoring failures like `Invalid user id`:** This is independent of rule payload validation. It typically means the **monitor API** could not resolve the *token’s* user context or the job ownership. The import can still succeed server-side, but you won’t get a good job status. Treat this as **monitoring-only** failure; we’ll keep retry + warn, but do not fail the whole import when creation returns HTTP 2xx.

---

## 3) Users and Groups — API endpoints for dependency checks

### 3.1 Users
- **List / search**: `GET /configapi/{pool_uuid}/{logpoint_identifier}/Users`
  - Useful filters: `pattern`, `role`, `limit`, `offset`.
- **Create**: `POST /.../Users`
- **Update**: `PUT /.../Users/{id}`
- **Delete**: `DELETE /.../Users/{id}`
- **Unlock**: `POST /.../Users/{id}/unlock`

**Field types (most relevant for AlertRules):**
- `id` (string; used as `owner` and `assigned_to`)
- Other attributes like `username`, `email`, `role` are for search/match only.

### 3.2 IncidentUserGroups
- **List**: `GET /configapi/{pool_uuid}/{logpoint_identifier}/IncidentUserGroups`
- **Create**: `POST /.../IncidentUserGroups`
- **Update**: `PUT /.../IncidentUserGroups/{id}`
- **Manage members**: `POST /.../IncidentUserGroups/{id}/addUsers`, `POST /.../IncidentUserGroups/{id}/removeUsers`

**Field types:**
- `id` (string; referenced in `manageable_by` of an AlertRule)

### 3.3 UserGroups (classic groups)
- **List**: `GET /configapi/{pool_uuid}/{logpoint_identifier}/UserGroups`
- **Create / Update**: `POST /.../UserGroups`, `PUT /.../UserGroups/{id}`

**Field types:**
- `id` (string; can be used in sharing/visibility RBAC configuration)

### 3.4 Who am I? (token → user)
- The auth token typically includes the effective user info (id/username/role). If the platform exposes a “refresh” or “introspect” endpoint, call it to obtain `user._id` and correlate with **Users**. Otherwise decode the JWT locally to extract the subject/id for logging & routing.

---

## 4) Required vs Optional fields for AlertRules (user/group–related)

| Field           | Type        | Required | Source                             | On missing entity |
|----------------|-------------|----------|------------------------------------|-------------------|
| `owner`        | string (ID) | **Yes**  | **Users** list                      | **Skip rule** or **set to default owner** (recommended: **skip** per your instruction) |
| `assigned_to`  | string (ID) | No       | **Users** list                      | Omit the field    |
| `manageable_by`| string[]    | No       | **IncidentUserGroups** list         | Omit the field    |
| Visibility     | RBAC config | No       | Users and/or (Incident)UserGroups   | Don’t call `share` when none exist |

> **Your migration policy:** if the referenced **user/group does not exist**, do **not** try to create it; **skip** assigning it and **log SKIP**. For `owner` (required by the API), either **skip the whole rule** or apply a *tenant default* owner that you configure. You asked for **SKIP**.

---

## 5) Migration Plan of Action (when Users are not migrated)

### 5.1 Pre-flight checks (dry run)
1. Read the XLSX (`core_config.xlsx`) and enumerate `AlertRules` rows.
2. Resolve `owner` → user ID via **Users** API (pattern match by username or email).
3. Resolve `assigned_to` similarly (optional).
4. Resolve `manageable_by` groups → IDs via **IncidentUserGroups** API (optional).
5. Resolve visibility mapping (`visible_to_users` / `visible_to_groups`) using **Users** and **UserGroups/IncidentUserGroups**.
6. Produce a **resolution report** with 4 buckets:
   - **OK**: all IDs resolved
   - **SKIP_OWNER**: owner missing → rule will be **skipped** (per your choice)
   - **PARTIAL**: owner OK but some optional references (assigned_to / manageable_by / visibility) missing → they will be omitted
   - **INVALID**: bad configuration (e.g. rule name empty)

### 5.2 Import execution
1. For each rule in **OK** or **PARTIAL**:
   - `POST /AlertRules` with resolved `owner`, optional `assigned_to`, optional `manageable_by`.
   - If creation OK (HTTP 2xx), call `POST /AlertRules/{id}/share` **only** if you resolved visibility recipients.
   - Monitor the job URL; if monitor returns `Invalid user id`, **warn** and continue (do not fail the whole batch).
2. For each rule in **SKIP_OWNER**: log a **SKIP**, include `owner` string that failed resolution.
3. Output a final **CSV/Markdown** summary.

### 5.3 Logging policy
- **INFO**: All HTTP requests and successful responses
  - Fields: `event=http.request|http.ok`, `method`, `path`, `action`, `tenant_or_pool`, `node`, `rule`, `keys`, `size`.
- **WARNING**: Monitor failures, missing optional references, visibility subsets not found, per-row skips.
- **ERROR**: HTTP 4xx/5xx on create/update/delete, schema/validation errors.
- **DEBUG**: Full payloads (redact secrets), matching traces for user/group resolution.

---

## 6) CLI Design — new helper to list XLSX visibility references

We add a **helper subcommand** to your `main.py` and a small `register.py` hook, to print a clean table from the Excel file:

### 6.1 CLI usage

```bash
python -m lp_tenant_importer_v2.main   --xlsx /path/to/core_config.xlsx   list-alert-user-visibility   [--sheet AlertRules]   [--out table.md]   [--format md|csv|json]
```

- `--xlsx` (required): path to the Excel config.
- `--sheet` (optional): sheet name; defaults to auto-detect across common variants.
- `--out` (optional): write output to a file instead of stdout.
- `--format` (optional): output format; default `md` (Markdown table).

### 6.2 `register.py` (subparser registration)

```python
# lp_tenant_importer_v2/register.py
def register_list_alert_user_visibility(subparsers):
    p = subparsers.add_parser(
        "list-alert-user-visibility",
        help="List AlertRules Name/Owner/Assign_to/Visible_for from the XLSX"
    )
    p.add_argument("--xlsx", required=True, help="Path to core_config.xlsx")
    p.add_argument("--sheet", default=None, help="Sheet name (optional)")
    p.add_argument("--out", default=None, help="Output file (md|csv|json inferred by --format)")
    p.add_argument("--format", default="md", choices=["md", "csv", "json"], help="Output format")
    p.set_defaults(func="cmd_list_alert_user_visibility")
```

> If you already have a registrar pattern, just import this function and call it inside your `main.py` parser construction.

### 6.3 `main.py` (command implementation)

```python
# lp_tenant_importer_v2/main.py (excerpt)
import argparse, json, sys
from pathlib import Path
import pandas as pd

def _load_alertrules_sheet(xlsx_path: str, explicit_sheet: str|None):
    candidates = [explicit_sheet] if explicit_sheet else [
        "AlertRules", "alert_rules", "ALERTRULES", "ALERT_RULES", "Alerts", "Rules"
    ]
    last_err = None
    for name in filter(None, candidates):
        try:
            return pd.read_excel(xlsx_path, sheet_name=name, engine="openpyxl")
        except Exception as e:
            last_err = e
    raise SystemExit(f"Unable to find an AlertRules sheet in {xlsx_path}: {last_err}")

def _choose_col(df, *candidates, default=None):
    for c in candidates:
        if c in df.columns:
            return c
    return default

def _maybe_parse_json(v):
    if isinstance(v, str):
        s = v.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                import json
                return json.loads(s)
            except json.JSONDecodeError:
                return v
    return v

def _visible_to_repr(row, user_cols, group_cols):
    import pandas as pd
    users = []
    groups = []
    for c in user_cols:
        if c and c in row and pd.notna(row[c]):
            val = _maybe_parse_json(row[c])
            if isinstance(val, list):
                users.extend([str(x) for x in val])
            else:
                users.append(str(val))
    for c in group_cols:
        if c and c in row and pd.notna(row[c]):
            val = _maybe_parse_json(row[c])
            if isinstance(val, list):
                groups.extend([str(x) for x in val])
            else:
                groups.append(str(val))
    parts = []
    if users:
        parts.append("users: " + ", ".join(users))
    if groups:
        parts.append("groups: " + ", ".join(groups))
    return " ; ".join(parts) if parts else ""

def cmd_list_alert_user_visibility(args):
    df = _load_alertrules_sheet(args.xlsx, args.sheet)

    name_col = _choose_col(df, "name", "Name", "rule_name", "Rule", default=None)
    owner_col = _choose_col(df, "owner", "Owner", "rule_owner", default=None)
    assign_col = _choose_col(df, "assigned_to", "Assign_to", "assignee", "Assignee", default=None)

    # try a few common column variants for visibility
    vis_user_cols  = [c for c in ["visible_to_users", "share_users", "rbac_users", "users_visibility"] if c in df.columns]
    vis_group_cols = [c for c in ["visible_to_groups", "share_groups", "rbac_groups", "groups_visibility"] if c in df.columns]

    if not name_col:
        raise SystemExit("Could not determine the rule name column (tried name/Name/rule_name/Rule).")

    out_rows = []
    for _, row in df.iterrows():
        name = str(row.get(name_col, "")).strip()
        if not name:
            continue
        owner = str(row.get(owner_col, "")).strip() if owner_col else ""
        assign = str(row.get(assign_col, "")).strip() if assign_col else ""
        visible = _visible_to_repr(row, vis_user_cols, vis_group_cols)
        out_rows.append({"Alert Name": name, "Owner": owner, "Assign_to": assign, "Visible_for": visible})

    if args.format == "json":
        import json
        payload = json.dumps(out_rows, ensure_ascii=False, indent=2)
    elif args.format == "csv":
        # simple CSV without extra deps
        import io, csv
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=["Alert Name", "Owner", "Assign_to", "Visible_for"])
        w.writeheader()
        for r in out_rows:
            w.writerow(r)
        payload = buf.getvalue()
    else:
        # markdown table
        lines = []
        lines.append("| Alert Name | Owner | Assign_to | Visible_for |")
        lines.append("|---|---|---|---|")
        for r in out_rows:
            lines.append(f"| {r['Alert Name']} | {r['Owner']} | {r['Assign_to']} | {r['Visible_for']} |")
        payload = "\n".join(lines)

    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
    else:
        import sys
        sys.stdout.write(payload + "\n")

def build_parser():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    # existing commands...
    # register list-alert-user-visibility
    sp = sub.add_parser("list-alert-user-visibility", help="List AlertRules Name/Owner/Assign_to/Visible_for")
    sp.add_argument("--xlsx", required=True, help="Path to core_config.xlsx")
    sp.add_argument("--sheet", default=None, help="Sheet name (optional)")
    sp.add_argument("--out", default=None, help="Output file (md|csv|json inferred by --format)")
    sp.add_argument("--format", default="md", choices=["md", "csv", "json"], help="Output format")
    sp.set_defaults(func=cmd_list_alert_user_visibility)
    return p

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
```

---

## 7) Import Algorithm (pseudocode) — user/group resolution with SKIP strategy

```text
for each node in nodes:
  existing = fetch_alert_rules(node)   # via POST /AlertRules/<Scope>/fetch (+ monitor)
  for rule_row in xlsx_rows:
    desired = build_payload(rule_row)

    # 1) Resolve mandatory owner
    owner_id = lookup_user_id(desired.owner)  # GET /Users?pattern=...
    if not owner_id:
      log(SKIP_OWNER, rule_row.name, reason="owner not found")
      continue   # SKIP the rule entirely (per your policy)

    desired.owner = owner_id

    # 2) Optional assigned_to
    if desired.assigned_to:
      assignee_id = lookup_user_id(desired.assigned_to)
      if assignee_id:
        desired.assigned_to = assignee_id
      else:
        warn(partial="assigned_to not found → omitted")
        del desired.assigned_to

    # 3) Optional manageable_by (IncidentUserGroups [])
    desired.manageable_by = []
    for g in rule_row.manageable_by_list:
      gid = lookup_incident_group_id(g)
      if gid: desired.manageable_by.append(gid)
    if not desired.manageable_by:
      remove from payload

    # 4) Upsert rule (create or update)
    res = create_or_update_alert_rule(desired)

    # 5) Visibility / sharing
    vis = resolve_visibility(rule_row)  # map to user IDs or group IDs (UserGroups/IncidentUserGroups)
    if vis:
      share_rule(res.id, vis)           # POST /AlertRules/{id}/share

    # 6) Monitor job (warn-only if "Invalid user id")
    monitor(res.job_url)
```

---

## 8) Example: robust log lines (consistent with your v2 importers)

- `INFO` — request start/end:
  - `event=http.request method=POST path=configapi/.../AlertRules action=create tenant_or_pool=<pool> node=<node> rule=<name> size=<bytes>`
  - `event=http.ok ...`
- `WARNING` — monitor or resolution issues:
  - `event=monitor.fail reason=create monitor failed ...`
  - `event=resolve.skip field=owner reason=user not found rule=<name>`
- `ERROR` — hard API errors:
  - `event=http.error status=4xx/5xx ... body=<truncated>`
- `DEBUG` — full payloads/mapping decisions (redact secrets).

---

## 9) Appendix — Excel column mapping tips

Common headings encountered in various tenants:
- Name: `name`, `Name`, `rule_name`, `Rule`
- Owner: `owner`, `Owner`, `rule_owner`
- Assigned_to: `assigned_to`, `Assign_to`, `assignee`, `Assignee`
- Visibility (users): `visible_to_users`, `share_users`, `rbac_users`, `users_visibility`
- Visibility (groups): `visible_to_groups`, `share_groups`, `rbac_groups`, `groups_visibility`

Cells may contain **JSON** (`["u1","u2"]`) or **comma-separated** strings; the helper above accepts both (best-effort).

---

## 10) Quick checklist

- [ ] Pre-flight **resolve** all user/group references (users, incident groups, classic groups).
- [ ] Apply **SKIP** when owner cannot be resolved.
- [ ] Omit optional references when missing.
- [ ] Create/Update first, then **share**.
- [ ] Monitor job; warn if monitor says `Invalid user id`.
- [ ] Produce a final report (OK / PARTIAL / SKIP / INVALID).

---

**End of document.**