# LogPoint Migration Helper — Step-by-Step Procedure (v3.0.1)

## 1) Overview

**Purpose.** The LogPoint Migration Helper is a command-line tool that streamlines the migration of LogPoint data and configuration from an existing platform to a new one.

**What it can migrate**

* Repos (logs and indexes)
* Backups
* Report templates
* Alert templates
* CSV enrichment sources
* Apps

## 2) Compatibility

* Tested with LogPoint: **6.6.0 (OK; needs further testing), 6.9.0 (OK), 6.10.0 (OK), 6.11.2 (OK), 6.12.1 (OK)**
* **6.0.0: Not working** (missing `.multiple_tier_info`).
* Older versions may work but are untested.
* **Important:** Source and destination **must run the same LogPoint version** for a seamless migration.

## 3) Supported Migration Paths

| From \ To       | All-in-One | Distributed |
| --------------- | ---------: | ----------: |
| **All-in-One**  |          ✅ |           ✅ |
| **Distributed** |          — |           ✅ |

> Distributed → All-in-One is not covered by the tool’s documented scenarios.

## 4) Prerequisites & Planning Checklist

**Platform**

* Align source and destination LogPoint versions.
* Right-size the target (CPU/RAM/storage/tiers/retention).
* Plan an outage window: ingestion may be briefly impacted. Sequence operations to minimize downtime.

**Repos**

* Decide which repos to migrate (vs. leave).
* Destination tiering/retention can differ; configure this first.
* Estimate data volume; plan chunked transfers for large histories.

**Applications & Enrichment**

* Apps (and versions) **must match** on source and destination.
* Some apps install their own enrichment CSVs; verify checksums and copy as needed.

**Backups & Configuration**

* Backups cannot be restored if app sets/versions differ.

## 5) Tool Installation & Key Setup

1. **Install** LogPoint Migration Helper on both source and target platforms.
2. **Generate li-admin SSH keys** on each target (first run will prompt you).
   Keys are stored under: `/home/li-admin/.ssh/li-admin_<IP>`

## 6) Pre-Migration: App Parity

Use the tool to compare apps between source and target. Install or upgrade missing/mismatched apps on the target until parity is achieved.

```bash
lp_tool check_apps --dst_host=<TARGET_IP>
# Example:
lp_tool check_apps --dst_host=192.168.0.187
```

Typical output flags:

* `MISMATCH: <App> (local X != remote Y)`
* `NOT_FOUND: <App> (X.Y.Z)`

## 7) Configuration Migration

1. **On source:** Create a configuration backup.
2. **Copy backups to target, then restore on target.**

   ```bash
   lp_tool copy_backup --dst_host=<TARGET_IP>
   ```
3. **Copy report templates** to target:

   ```bash
   lp_tool copy_report --dst_host=<TARGET_IP>
   ```
4. **Copy alert templates** to target:

   ```bash
   lp_tool copy_alert --dst_host=<TARGET_IP>
   ```
5. **Enrichment CSVs: check & sync**

   * Detect missing/different CSVs:

     ```bash
     lp_tool check_enrichment --dst_host=<TARGET_IP> --exclude_csv=''
     ```
   * Copy required CSVs and (re)process:

     ```bash
     lp_tool copy_enrichment --dst_host=<TARGET_IP> \
       --include_csv='airprobe.csv,WatchGuard_*,Windows_Access.csv,windows_dns.csv'
     ```

> The tool will stop/restart relevant enrichment services on the target as needed.

## 8) Repo Preparation on Target

* In LogPoint UI, adjust repo definitions on the **destination** (tiers, paths, retention).
* **Recommendation:** Restart target LP services/servers so the latest repo settings are active.

## 9) Cutover (Hot Day) — Copy Today’s Data

Copy the **current day (hot, R/W)** from source to target and re-generate headers so searches resume smoothly on the target.

```bash
lp_tool copy_repo --dst_host=<TARGET_IP> \
  --regen_headers=true \
  --include_date="YYYY/MM/DD" \
  --include_repo="*" \
  --exclude_repo="_*"
# Example:
lp_tool copy_repo --dst_host=192.168.0.187 \
  --regen_headers=true \
  --include_date="2021/08/06" \
  --include_repo="*" \
  --exclude_repo="_*"
```

**What it does**

* Stops local file/index services for the selected repo(s) during copy.
* Copies logs and indexes for the given date(s).
* Regenerates headers (if requested) so data is searchable immediately.

**Validate**

* Use search UI on target to confirm today’s data is searchable.

## 10) Switch Ingestion

* Update IPs, load balancer, or agent configuration so **new logs flow to the target**.

## 11) Historical Backfill (Cold, R/O)

Copy the remaining historical data in **chunks**, keeping target services running to avoid disrupting searches/ingestion.

```bash
lp_tool copy_repo --dst_host=<TARGET_IP> \
  --regen_headers=true \
  --dst_stop_svc=false \
  --include_date="*/*/*" \
  --exclude_date="<TODAY_YYYY/MM/DD>" \
  --include_repo="*" \
  --exclude_repo="_*"
# Example:
lp_tool copy_repo --dst_host=192.168.0.187 \
  --regen_headers=true \
  --dst_stop_svc=false \
  --include_date="*/*/*" \
  --exclude_date="2021/08/06" \
  --include_repo="*" \
  --exclude_repo="_*"
```

**Notes**

* `--dst_stop_svc=false` keeps searches and collection active while data is copied.
* `--regen_headers=true` ensures both old and new data remain searchable throughout.

## 12) Post-Migration Validation

* **Data parity:** Spot-check event counts across representative time ranges.
* **Searchability:** Queries return expected results for hot and historical days.
* **Apps & enrichment:** All required apps present; enrichment services running; CSV checksums aligned.
* **Reports & alerts:** Templates exist; scheduled items run.
* **Repos:** Tier locations correct; retention policies enforced; storage within thresholds.
* **Services:** File/index services healthy on both source and target.

## 13) Command Reference

### 13.1 Syntax

```
lp_tool <action> <options> ...
```

### 13.2 Actions

* `check_repo` – List repo logs/indexes matching filters.
* `copy_repo` – Copy local logs/indexes to remote per filters.
* `purge_repo` – Fully purge remote repos per filters.
* `copy_backup` – Copy local backups to remote.
* `copy_report` – Copy report config/data to remote.
* `copy_alert` – Copy alert templates to remote.
* `check_enrichment` – Compare MD5 of local vs. remote enrichment files.
* `copy_enrichment` – Copy CSV enrichment files for processing.
* `check_apps` – Compare app versions local vs. remote.

### 13.3 General Options

* `--dst_host=<host or IP>,...` *(required for copy)*
* `--dst_stop_svc=true|false` *(default: true)*
* `--dst_restart_svc=true|false` *(default: true)*

### 13.4 Repo Options

* `--include_date="<YYYY/MM/DD filter>"` with wildcards or lists
  e.g., `20*/{10,11}/*` *(default example: "2021/03/05")*
* `--exclude_date="<YYYY/MM/DD filter>"`
  e.g., `20*/10/*,2020/10/02`
* `--include_repo="<filter>"` e.g., `lp_syslog,lp_*`
* `--exclude_repo="<filter>"` e.g., `lp_,syslog`
* `--dst_purge=true|false` *(default: false)*
* `--copy_headers=true|false` *(default: false)*
* `--regen_headers=true|false` *(default: false)*

### 13.5 Enrichment Options

* `--include_csv="<filter>"` e.g., `prod_servers,uat_servers`
* `--exclude_csv="<filter>"` *(default excludes: `UEBA_.* HANA_.*`)*

## 14) Operational Tips

* The tool uses **rsync** (not scp) to copy with `loginspect` user, avoiding permission issues and providing progress indicators.
* Use `--include_date` / `--exclude_date` aggressively to **chunk large migrations**.
* After editing repo definitions on the target, **restart services** to ensure active configs.
* **Backups first, then templates, then enrichment, then repos** is a safe sequence.

## 15) Change Log (Documentation v3.0.1 — Apr 2023)

* **v3.0.1 (04/2023):** Fixed regression affecting enrichment/backup/report copy after switching to rsync.
* **v3.0.0 (09/2022):** Renamed 3.0.0.3 → 3.0.0 to satisfy Director plugin asset filename rules (≤3-digit versions).
* **v3.0.0.3 (03/2022):** Signed app; version > v3.0 to comply with LogPoint 7.0.
* **v0.0.9.1 (11/2021):** Removed SSH key load check broken by Ubuntu 20.04 change in LP 6.11.x.
* **v0.0.9.0 (08/2021):** Switched to rsync; removed `--grant_permission`; added stricter date filter checks.

---

### Quick Commands (copy/paste)

* App parity:

  ```bash
  lp_tool check_apps --dst_host=<TARGET_IP>
  ```

* Copy backups:

  ```bash
  lp_tool copy_backup --dst_host=<TARGET_IP>
  ```

* Copy reports and alerts:

  ```bash
  lp_tool copy_report --dst_host=<TARGET_IP>
  lp_tool copy_alert  --dst_host=<TARGET_IP>
  ```

* Check and copy enrichment:

  ```bash
  lp_tool check_enrichment --dst_host=<TARGET_IP> --exclude_csv=''
  lp_tool copy_enrichment --dst_host=<TARGET_IP> --include_csv='<LIST_OR_PATTERN>'
  ```

* Cutover (today only, with header regen):

  ```bash
  lp_tool copy_repo --dst_host=<TARGET_IP> \
    --regen_headers=true --include_date="YYYY/MM/DD" \
    --include_repo="*" --exclude_repo="_*"
  ```

* Historical backfill (keep services running):

  ```bash
  lp_tool copy_repo --dst_host=<TARGET_IP> \
    --regen_headers=true --dst_stop_svc=false \
    --include_date="*/*/*" --exclude_date="YYYY/MM/DD" \
    --include_repo="*" --exclude_repo="_*"
  ```
