# Developer Guidelines – DirectorSyncV3

## 1. Purpose

These guidelines define how to work on the **DirectorSyncV3** project in a
consistent, maintainable, and collaboration-friendly way.

They apply to all contributors, including human developers and AI-assisted
changes.

---

## 2. Project Overview (Short)

DirectorSyncV3 is a generic synchronization engine for **Logpoint Director**,
implemented as a Python package called `lp_sync`.

Key concepts:

- **SQL database** as the source of truth for desired configuration,
- **YAML resource profiles** describing how to sync each configuration type,
- **transformers** providing composable logic,
- **one universal sync pipeline**.

---

## 3. Repository Structure (Simplified)

Typical layout:

```text
DirectorSyncV3/
  lp_sync/
    core/
    transformers/
    profiles/
    utils/
    cli.py
  docs/
  db/
  scripts/
  tests/
  pyproject.toml
  README.md
