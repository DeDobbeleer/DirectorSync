# Tools and IDE Recommendations for Director/Fleet API Operations

> **Constraint:** Windows-only workstations inside a **restricted SOC with no Internet access**. Microsoft Office / LibreOffice Calc cannot be installed on SOC stations. XLSX files are prepared and reviewed on a separate corporate office zone and transferred into the SOC through approved channels.
>
> **Delivery model change:** you no longer receive a pre-built `LPImporter.exe`. The handover is the **sanitized Python source code** so you can run the exporter and importer directly from source, adapt them to your Fleet/SIEM estate, and maintain them over time.

This guide lists the practical Windows-native, **offline-capable** toolkit you need to operate and maintain the LogPoint Director / Fleet / SIEM estate, and to run the DirectorSync exporter and importer from source.

## 1. Why source code instead of an executable?

Previously the importer was delivered as a pre-built Windows executable (`LPImporter.exe`). In an air-gapped SOC this model is fragile:

- You cannot easily download or re-download a new binary from the Internet.
- You cannot inspect, patch or extend a black-box executable.
- Rebuilding an `.exe` requires a Windows build machine with the same toolchain; inside the SOC this is usually impossible.

The new delivery model gives you the **Python source code**. With the toolchain below you can:

- Run the **importer** directly from source against your Director/Fleet nodes.
- Run the **exporter / splitter** from source to produce per-tenant XLSX workbooks.
- Patch bugs, add new resource types, or adapt the logic to your environment without waiting for a new binary.
- Build your own `LPImporter.exe` later with PyInstaller if your internal process requires it.

## 2. SOC constraints and the office zone/SOC split

- **No Internet from the SOC.** All installers, VSIX extensions, Python wheels and packages must be downloaded on the corporate office zone and transferred through the approved import process (USB/SD/secure file gateway/whitelist).
- **No Office suite on SOC stations.** Per-tenant `.xlsx` workbooks cannot be opened inside the SOC. They must be:
  1. produced by the splitter on the office zone,
  2. reviewed/modified there with Excel/LibreOffice,
  3. transferred **back** into the SOC as the final input for the importer.
- **No cloud sync / marketplace access from the SOC.** VS Code, extensions, Postman collections and Python packages are installed from offline packages only.

Recommended zone map:

| Activity | Zone | Tooling |
|---|---|---|
| Install media download | Office zone | Browser, pip, VS Code marketplace |
| Review / edit XLSX | Office zone | Microsoft Excel or LibreOffice Calc |
| Split source JSON into per-tenant XLSX | Office zone or SOC | `logpoint_config_splitter.py` |
| Run importer / exporter from source | SOC only | VS Code terminal, Python venv |
| Store secrets | SOC only | `.env` files, Windows ACLs |

## 3. IDE — Visual Studio Code (mandatory baseline)

Install VS Code from an offline installer obtained on the office zone ([code.visualstudio.com](https://code.visualstudio.com/) or the corporate software catalog).

### Required VS Code extensions (offline install)

1. On the office zone, download the `.vsix` files from the VS Code Marketplace (use "Download Extension" on each extension page).
2. Transfer the `.vsix` files into the SOC through the approved channel.
3. In VS Code on the SOC, open the Extensions view (`Ctrl+Shift+X`) → `...` → **Install from VSIX...**.

| Extension | Publisher | Why |
|---|---|---|
| **Python** | Microsoft | IntelliSense, linting, debugging, test discovery |
| **Pylance** | Microsoft | Fast type-checking and rich Python language support |
| **YAML** | Red Hat | Validation and autocomplete for `tenants.yml` / `profiles.yml` |
| **Markdown All in One** | Yu Zhang | TOC, preview, shortcuts for the documentation files |
| **Even Better TOML** | tamasfe | If you later add `pyproject.toml` |
| **JSON** | built-in | Format/validate `*.example` templates and API payloads |

Pin these in a workspace recommendations file (`.vscode/extensions.json`) so every operator knows the expected baseline.

### Suggested VS Code workspace settings

Create `.vscode/settings.json` at the project root:

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/venv_importer/Scripts/python.exe",
  "python.terminal.activateEnvironment": true,
  "python.analysis.extraPaths": ["${workspaceFolder}"],
  "files.exclude": {
    "**/__pycache__": true,
    "**/*.pyc": true,
    "**/venv_*": true
  },
  "yaml.schemas": {
    "": "*.yml"
  }
}
```

Create `.vscode/launch.json` for debugging an importer subcommand:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: import-repos dry-run",
      "type": "debugpy",
      "request": "launch",
      "module": "lp_tenant_importer_v2.main",
      "args": [
        "--tenant", "tenant_a",
        "--xlsx", "${workspaceFolder}/lp_tenant_importer_v2/samples/tenant_a_config.xlsx",
        "--dry-run",
        "import-repos"
      ],
      "console": "integratedTerminal",
      "cwd": "${workspaceFolder}"
    }
  ]
}
```

## 4. Python on Windows (offline)

- Install **Python 3.10+** from an offline `python-3.x.x-amd64.exe` installer obtained on the office zone.
- During setup, check **"Add Python to PATH"**.
- Prepare the Python dependencies on the office zone:

```powershell
# On the office zone (Internet allowed)
python -m pip download -r lp_tenant_importer_v2\requirements.txt -d importer_wheels
python -m pip download -r lp_tenant_exporter_v2\requirements.txt -d exporter_wheels
python -m pip download pyinstaller -d importer_wheels
```

Transfer the `*_wheels/` folders into the SOC and install from the local cache:

```powershell
# Inside the SOC (no Internet)
python -m venv venv_importer
.\venv_importer\Scripts\activate
pip install --no-index --find-links importer_wheels -r lp_tenant_importer_v2\requirements.txt

python -m venv venv_exporter
.\venv_exporter\Scripts\activate
pip install --no-index --find-links exporter_wheels -r lp_tenant_exporter_v2\requirements.txt
```

Then select the relevant interpreter in VS Code (`Ctrl+Shift+P` → `Python: Select Interpreter`).

## 5. Running the exporter from source

The exporter reads a LogPoint configuration JSON dump and splits it into sanitized, per-tenant XLSX workbooks.

From the VS Code PowerShell terminal:

```powershell
.\venv_exporter\Scripts\activate
python -m lp_tenant_exporter_v2.splitter.split_cli `
  --input "C:\DirectorSync\source_dumps\logpoint_full_config.json" `
  --output-dir "C:\DirectorSync\exports"
```

If you have a separate Search-Head export for alerts:

```powershell
python -m lp_tenant_exporter_v2.splitter.split_cli `
  --input "C:\DirectorSync\source_dumps\logpoint_full_config.json" `
  --input-sh "C:\DirectorSync\source_dumps\search_head_alerts.json" `
  --config-dir "C:\DirectorSync\source_dumps" `
  --output-dir "C:\DirectorSync\exports"
```

Result: one folder per tenant under `C:\DirectorSync\exports\`, each containing an `.xlsx` workbook.

## 6. Running the importer from source

The importer applies per-tenant XLSX workbooks to a LogPoint Director / Fleet node through the Config API.

From the VS Code PowerShell terminal:

```powershell
.\venv_importer\Scripts\activate
$env:LP_DIRECTOR_URL = "https://director.example.com"
$env:LP_DIRECTOR_API_TOKEN = "your-api-token"
python -m lp_tenant_importer_v2.main `
  --tenant tenant_a `
  --tenants-file lp_tenant_importer_v2\tenants.yml `
  --xlsx C:\DirectorSync\exports\tenant_a\tenant_a_config.xlsx `
  --dry-run `
  import-repos
```

Remove `--dry-run` once the preview looks correct. Other subcommands include `import-devices`, `import-device-groups`, `import-routing-policies`, `import-processing-policies`, `import-normalization-policies`, `import-enrichment-policies`, `import-syslog-collectors`, `import-user-defined-lists`, `import-alert-rules`.

See `lp_tenant_importer_v2/docs/running_the_importer.md` and `lp_tenant_importer_v2/docs/alert_rules_*.md` for detailed subcommand options.

## 7. Building your own executable (optional)

If your internal runbook still requires a single `.exe`, build it from source inside the SOC using PyInstaller:

```powershell
.\venv_importer\Scripts\activate
pyinstaller lp_tenant_importer_v2\build.spec --clean
```

This produces `dist\LPImporter.exe`. You can wrap it with a `run.cmd` shortcut:

```bat
@echo off
setlocal
cd /d "%~dp0"
.\LPImporter.exe --tenant core --tenants-file .\tenants.yml --xlsx .\samples\core_config.xlsx import-repos
pause
```

## 8. API exploration and testing tools

| Tool | Offline install | Use case |
|---|---|---|
| **Postman** (desktop) | Download the Windows x64 installer on the office zone. Postman runs offline once installed, but the account/sign-in step must be done during installation or skipped with the Scratch Pad / lightweight API client mode. | Graphical collections for Config API and Monitor API; save requests per tenant, share collections, use environments/variables |
| **curl** | Built into Windows 10/11; no install needed. | Command-line API calls in runbooks |
| **jq** | Download `jq-windows-amd64.exe` on the office zone, rename to `jq.exe` and add to a folder on PATH. | Parse and filter JSON responses |
| **PowerShell / Windows Terminal** | Built-in / Microsoft Store offline package. | Preferred shell for Windows operators |

> **Important:** any Postman collection that contains tokens, UUIDs or IPs must be exported to JSON, reviewed for secrets, and transferred into the SOC through the approved import channel. Do **not** use Postman Cloud / Workspaces.

Example PowerShell API health check:

```powershell
$headers = @{ Authorization = "Bearer $env:LP_DIRECTOR_API_TOKEN" }
Invoke-RestMethod -Uri "$env:LP_DIRECTOR_URL/configapi/$env:POOL_UUID/$env:NODE_ID/Users" -Headers $headers -SkipCertificateCheck
```

## 9. Handling XLSX without Microsoft Office

Since Excel/LibreOffice cannot be installed on SOC stations, choose one of the following workflows:

### Option A — Prepare and freeze XLSX on the office zone (recommended)

1. Run the splitter or create the workbook on the office zone.
2. Review and edit with Excel/LibreOffice.
3. Transfer the finalized `.xlsx` into the SOC.
4. Inside the SOC, run the importer from source against that file without opening it.

### Option B — Validate XLSX content with Python scripts (no Office needed)

If you need to inspect an `.xlsx` inside the SOC without installing Office, use the already-installed Python stack:

```powershell
.\venv_importer\Scripts\activate
python - << 'PY'
import pandas as pd
xlsx = pd.ExcelFile("lp_tenant_importer_v2/samples/tenant_a_config.xlsx")
print(xlsx.sheet_names)
df = xlsx.parse("Repos")
print(df.head())
PY
```

You can also create small helper scripts under `scripts/` to dump sheet names, row counts and column headers for quick verification.

### Option C — Convert to CSV for diffing (advanced)

For version control or comparison, convert each XLSX sheet to CSV on the office zone before transferring. Inside the SOC, store CSV copies next to the XLSX and diff them with standard tools:

```powershell
# Office zone
python -m venv venv_tools
.\venv_tools\Scripts\activate
pip install pandas openpyxl
python - << 'PY'
import pandas as pd
xlsx = pd.ExcelFile("tenant_a_config.xlsx")
for sheet in xlsx.sheet_names:
    xlsx.parse(sheet).to_csv(f"tenant_a_{sheet}.csv", index=False)
PY
```

> **Caution:** CSV loses formatting, formulas and multi-sheet structure. It is useful only for review and diffing, not as an import input.

## 10. Data and configuration helpers

| Tool | Use case |
|---|---|
| **Microsoft Excel / LibreOffice Calc** | Only on the office zone for viewing and editing per-tenant `.xlsx` workbooks |
| **VS Code + YAML extension** | Edit and validate `tenants.yml` and `profiles.yml` inside the SOC |
| **VS Code + JSON support** | Validate `.example` templates and API payloads |
| **Git for Windows** | Version-control the sanitized source and runbooks. Use the VS Code source-control view or Git Bash. Install from an offline installer obtained on the office zone. |
| **Python + pandas/openpyxl** | Read, validate and optionally transform XLSX files inside the SOC without Office |

## 11. SIEM operations and monitoring

| Tool / Source | Use case |
|---|---|
| **LogPoint Director UI** | Day-to-day management of tenants, pools, nodes, repos, policies and alert rules. Use it to validate imports and compare expected vs actual state |
| **LogPoint Search / Dashboard** | Verify ingestion, alert triggering and repo health after migration |
| **PowerShell + `Get-Content -Tail`** | Tail importer logs: `Get-Content logs\importer_20260526_094733.log -Wait` |
| **Director API Monitor endpoints** | The importer polls `/monitorapi/.../orders/{job_id}`; learn to read these responses manually when debugging stuck jobs |
| **rsyslog tooling** | For syslog collector troubleshooting on Linux backends: `logger`, `tcpdump`, `nc`, `rsyslogd -N1`. The exporter docs under `lp_tenant_exporter_v2\Docs\Procedures\` contain detailed runbooks |

## 12. Suggested SOC workflow for Fleet/SIEM operations

1. **Explore** the endpoint on a lab tenant using Postman in the SOC (offline collections).
2. **Export** the source configuration from LogPoint and run the splitter from source to produce per-tenant XLSX files.
3. **Review** the XLSX on the office zone with Excel/LibreOffice, then transfer the finalized file into the SOC.
4. **Dry-run** the importer from source with `--dry-run` before any mutating import.
5. **Apply** the import once the dry-run diff is acceptable.
6. **Validate** in the Director UI and via API list calls.
7. **Commit** the sanitized script/config change to **Git**.

## 13. Security reminders for an air-gapped SOC

- Store tokens in `.env` files; restrict permissions with Windows ACLs (right-click → Properties → Security).
- Rotate Director API tokens after onboarding or offboarding operators.
- Never commit customer data, tokens, `tenants.yml`, `pools.json` or customer XLSX/JSON.
- Do **not** enable VS Code settings sync, GitHub Copilot, Postman Cloud or any cloud-backed extension.
- Scan every file entering the SOC for malware and secrets.
- Keep a signed hash or manifest of approved packages/wheels to detect tampering.
- Use `--no-verify` only in lab environments.

## 14. Minimal Windows SOC workstation install checklist

1. Windows 10/11 with latest updates
2. Python 3.10+ offline installer (added to PATH)
3. Visual Studio Code offline installer + `.vsix` extensions from §3
4. Git for Windows offline installer
5. Postman offline installer (or use PowerShell/curl only)
6. jq Windows binary (optional but recommended)
7. Python wheel caches (`importer_wheels/` and `exporter_wheels/`) from §4
