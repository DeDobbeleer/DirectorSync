# DirectorSync Delivery — Context and Instructions

> **Single deliverable:** `DirectorSync_migration_source.zip`  
> **Last generated:** see the file date of the `.zip` in `dist_client/`.

This document explains what the delivery contains, the context in which it is provided, and how the customer should use it.

---

## 1. Business context

The **DirectorSync** project synchronizes LogPoint entities (repos, devices, policies, alerts, etc.) across multiple tenants and nodes of a **LogPoint Director / Fleet / SIEM** estate.

It consists of two components:

| Component | Role | Input | Output |
|---|---|---|---|
| **lp_tenant_exporter_v2** | Exporter / splitter | Full LogPoint JSON configuration dump | Sanitized `.xlsx` workbooks per tenant |
| **lp_tenant_importer_v2** | Importer | Per-tenant `.xlsx` workbook + `tenants.yml` + `.env` | Director API calls to create / update entities |

The delivery contains the **Python source code** for both components, plus the documentation required to run them in the customer's target environment.

---

## 2. Delivery model change: from binary to source

Previously the importer was delivered as a pre-built Windows executable: `LPImporter.exe`.

In the customer's current context (air-gapped SOC, Windows stations with no Internet, no Office suite available), this model is no longer viable:

- A binary cannot be re-downloaded or updated from a network with no Internet access.
- The customer cannot inspect, patch or adapt a closed executable.
- Rebuilding an `.exe` requires a Windows build chain that is hard to maintain inside a SOC.

**The new delivery is therefore the source code.** The customer installs it on their Windows stations, creates their Python virtual environments, and runs the exporter and importer directly from source.

> **Benefit:** the customer becomes self-sufficient for operations, maintenance and evolution of the Fleet/SIEM estate. They can patch, add resource types and audit the code.

---

## 3. Target environment constraints

| Constraint | Impact on the delivery |
|---|---|
| **Windows-only workstations** | All documented tooling is Windows-native (PowerShell, CMD, Windows Terminal, VS Code, offline `.exe`/`.msi` installers). |
| **VS Code as the standard IDE** | Required extensions are listed; example `.vscode/settings.json` and `.vscode/launch.json` are provided. |
| **SOC has no Internet access** | All installers, `.vsix` extensions and Python wheels must be downloaded on the corporate office zone and transferred manually into the SOC. |
| **No Office suite on SOC stations** | `.xlsx` files cannot be opened inside the SOC. They are prepared on the office zone and transferred into the SOC for ingestion only. |
| **Office zone ↔ SOC file transfer** | XLSX files, installers and updates travel through approved channels (USB/SD/secure file gateway/whitelist). |
| **No cloud / sync** | No VS Code Settings Sync, Copilot, Postman Cloud or online Marketplace from inside the SOC. |

---

## 4. What is inside the zip

The `DirectorSync_migration_source.zip` file contains only:

- The **Python source code** of `lp_tenant_exporter_v2` and `lp_tenant_importer_v2`.
- The **root documentation** Markdown files:
  - `README_HANDOVER.md` — Overview and getting started.
  - `CONCEPT_AND_USAGE_GUIDE.md` — Concepts and usage guide.
  - `TOOLS_AND_IDE_RECOMMENDATIONS.md` — Tools, IDE and offline installation procedures.
  - `DELIVERY.md` — This document.
- **Configuration templates** (`.example` / `.sample` files):
  - `lp_tenant_importer_v2/tenants.example.yml`
  - `lp_tenant_importer_v2/.env.example`
  - `lp_tenant_exporter_v2/config/splitter.json.example`
  - `lp_tenant_exporter_v2/config/logpoint_config_splitter-config.json.example`
- **README files** in empty folders (`data/`, `split/`, `samples/`, `logs/`) to preserve the directory structure.

The zip does **not** contain:

- Real `.env`, `tenants.yml`, `pools.json` files.
- Customer XLSX/JSON data files.
- Logs, `.pyc` files or `__pycache__` directories.
- A pre-built `LPImporter.exe` (the customer rebuilds it themselves if needed).

---

## 5. What the customer must recreate

The delivered source code is generic. The customer must create **their own configuration files** from the provided templates:

| File | Create from | Contains |
|---|---|---|
| `tenants.yml` | `tenants.example.yml` | Tenant / node / pool / backend IP mapping |
| `.env` | `.env.example` | Director URL and API token |
| `pools.json` | `pools.json.example` | Pool and node reference data |
| Per-tenant XLSX files | Produced by the exporter | Tenant configuration data |
| `splitter.json` (optional) | `splitter.json.example` | Advanced splitter configuration |

> **Important:** these files contain UUIDs, IP addresses, tokens and other sensitive information. They must never be version-controlled or transferred outside the SOC.

---

## 6. Recommended workflow

```text
Office zone zone (Internet / Office allowed)
  ├─ Download VS Code, Python, Git, .vsix extensions, Python wheels
  ├─ Download / prepare the LogPoint JSON configuration dump
  ├─ Run the splitter (from source) to generate per-tenant .xlsx files
  └─ Review the .xlsx files with Excel or LibreOffice Calc

Approved transfer → SOC (no Internet / no Office)
  ├─ Install Python, VS Code, Git, extensions and wheels
  ├─ Create tenants.yml, .env, pools.json from the templates
  ├─ Run the importer with --dry-run
  ├─ Review the diff in the console output
  └─ Run the importer without --dry-run to apply the changes
```

---

## 7. Essential commands

### Install dependencies (offline)

On the office zone:

```powershell
python -m pip download -r lp_tenant_importer_v2\requirements.txt -d importer_wheels
python -m pip download -r lp_tenant_exporter_v2\requirements.txt -d exporter_wheels
```

Inside the SOC:

```powershell
python -m venv venv_importer
.\venv_importer\Scripts\activate
pip install --no-index --find-links importer_wheels -r lp_tenant_importer_v2\requirements.txt
```

### Run the exporter

```powershell
.\venv_exporter\Scripts\activate
python -m lp_tenant_exporter_v2.splitter.split_cli `
  --input "C:\DirectorSync\source_dumps\logpoint_full_config.json" `
  --output-dir "C:\DirectorSync\exports"
```

### Run the importer (dry-run)

```powershell
.\venv_importer\Scripts\activate
$env:LP_DIRECTOR_URL = "https://director.example.com"
$env:LP_DIRECTOR_API_TOKEN = "your-token"
python -m lp_tenant_importer_v2.main `
  --tenant tenant_a `
  --tenants-file lp_tenant_importer_v2\tenants.yml `
  --xlsx C:\DirectorSync\exports\tenant_a\tenant_a_config.xlsx `
  --dry-run `
  import-repos
```

### Run the importer (real application)

Remove `--dry-run` from the command above.

---

## 8. Pre-delivery checks

Before sending the zip, ensure that:

- [ ] No real `.env`, `tenants.yml`, `pools.json` files are present.
- [ ] No customer `.xlsx` or `.json` data files are present.
- [ ] No `.log`, `.pyc` or `__pycache__` artifacts are present.
- [ ] Real UUIDs and IP addresses have been replaced with placeholders (`EXAMPLE_*`).
- [ ] Documentation is consistent with the delivered code.
- [ ] The zip opens and extracts correctly.

---

## 9. Zip structure after extraction

```text
source_export/
├── DELIVERY.md                       ← This document
├── README_HANDOVER.md
├── CONCEPT_AND_USAGE_GUIDE.md
├── TOOLS_AND_IDE_RECOMMENDATIONS.md
├── lp_tenant_exporter_v2/            ← Exporter / splitter
│   ├── splitter/
│   ├── config/                       ← .example templates
│   ├── docs/                         ← Concept and design documentation
│   ├── data/                         ← Empty (README only)
│   ├── split/                        ← Empty (README only)
│   └── requirements.txt
└── lp_tenant_importer_v2/            ← Importer
    ├── core/
    ├── importers/
    ├── utils/
    ├── docs/
    ├── samples/                      ← .example templates
    ├── logs/                         ← Empty (README only)
    ├── tenants.example.yml
    ├── .env.example
    ├── build.spec                    ← PyInstaller spec
    └── requirements.txt
```

---

## 10. Contact and support

This deliverable is designed to be self-contained. If questions arise:

1. Read the Markdown files at the root of the archive first.
2. Refer to the specific documents under `lp_tenant_importer_v2/docs/` and `lp_tenant_exporter_v2/docs/`.
3. Verify that configuration files have been created from the `.example` templates.

---

**One-sentence summary:** the delivery is the Python source code of the exporter and importer, ready to run on offline Windows SOC workstations using VS Code, with full documentation so the customer can operate and maintain their Fleet/SIEM estate without depending on an external executable.
