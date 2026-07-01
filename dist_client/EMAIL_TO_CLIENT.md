# Email to client — DirectorSync migration source handover

**Subject:** DirectorSync Migration Source Handover — Source Code, Documentation and Windows Workstation Guidelines

---

Dear [Client Team],

Please find attached the final delivery package for the DirectorSync migration tooling:

**`DirectorSync_migration_source.zip`**

This archive contains the sanitized Python source code, configuration templates and documentation required to operate, maintain and extend the exporter and importer in your environment.

## What is included

The package is organized as follows:

- **`lp_tenant_exporter_v2/`** — Source code of the LogPoint configuration splitter.
  - Reads a monolithic LogPoint JSON configuration dump.
  - Produces one sanitized Excel workbook per tenant.
  - See `lp_tenant_exporter_v2/docs/CONCEPT_AND_DESIGN.md` for architecture, components and usage.

- **`lp_tenant_importer_v2/`** — Source code of the LogPoint Director API importer.
  - Consumes the per-tenant Excel workbooks produced by the exporter.
  - Synchronizes configuration entities into LogPoint Director / Fleet / SIEM nodes via the Config API.
  - See `lp_tenant_importer_v2/docs/running_the_importer.md` and `lp_tenant_importer_v2/docs/developer_guide.md` for usage and internals.

- **Root documentation**
  - `README_HANDOVER.md` — Package overview and getting started.
  - `CONCEPT_AND_USAGE_GUIDE.md` — End-to-end concept and workflow.
  - `TOOLS_AND_IDE_RECOMMENDATIONS.md` — Recommended Windows-only, VS Code-based development workstation setup, including offline installation procedures for an air-gapped SOC.
  - `DELIVERY.md` — Delivery context, contents and pre-flight checklist.

## Delivery model

We have moved away from providing a pre-built `LPImporter.exe`. The handover is now the **full source code** so that your team can:

- Run the exporter and importer directly from source.
- Maintain, patch and extend the tools to match your Fleet/SIEM estate.
- Build your own executable with PyInstaller later if your internal process requires it.

This approach is better suited to an air-gapped SOC where downloading or updating a pre-built binary is not practical.

## Target environment constraints

The documentation assumes the following constraints:

- Windows-only workstations.
- Visual Studio Code as the standard IDE.
- SOC has no Internet access — all installers, VSIX extensions and Python packages must be downloaded on the corporate office zone and transferred through your approved channels.
- No Microsoft Office / LibreOffice Calc on SOC stations — XLSX files are prepared on the office zone and transferred into the SOC for ingestion only.

## What you need to recreate

The source code is generic. You must create your own environment-specific files from the provided `.example` / `.sample` templates:

- `lp_tenant_importer_v2/tenants.yml` (from `tenants.example.yml`)
- `lp_tenant_importer_v2/.env` (from `.env.example`)
- Per-tenant Excel workbooks produced by the exporter
- Optional: `lp_tenant_exporter_v2/config/logpoint_config_splitter-config.json` and `splitter.json`

These files contain sensitive data (UUIDs, IP addresses, API tokens) and must never leave the SOC.

## Recommended first steps

1. Install Python 3.10+, Visual Studio Code and Git for Windows from offline installers.
2. Install the Python dependencies from a local wheel cache (`pip install --no-index --find-links`).
3. Create `tenants.yml` and `.env` from the templates.
4. Prepare a source LogPoint JSON dump and run the exporter to generate per-tenant XLSX files.
5. Review the XLSX files on the office zone, then transfer them into the SOC.
6. Run the importer with `--dry-run` first, review the diff, then run without `--dry-run`.

## Security reminders

- Store API tokens in `.env` files with restricted Windows ACLs.
- Rotate Director API tokens after onboarding or offboarding operators.
- Do not enable cloud sync, Copilot, Postman Cloud or any online extension in the SOC.
- Scan every file entering the SOC for malware and secrets.

If you have any questions, start with the Markdown files at the root of the archive, then refer to the specific documents under `lp_tenant_importer_v2/docs/` and `lp_tenant_exporter_v2/docs/`.

Best regards,

[Your name]
[Your title]
[Your contact information]
