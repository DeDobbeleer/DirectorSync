# DirectorSync v3 — Developer Conventions

**Status:** Draft v0.9  
**Date:** 2025‑10‑07 (Europe/Paris)  
**Audience:** Engineering, QA, DevOps, Reviewers  
**Scope:** Language, style, logging, errors, testing, workflow, CI/CD, and security conventions for DSv3.

---

## 1) Language & Versions
- **Language:** All code, comments, and docs are **English only**.
- **Python:** 3.12 (primary); CI also runs 3.11 for compatibility.
- **Encoding:** UTF‑8; files end with a newline.

---

## 2) Code Style (PEP‑8 / PEP‑257)
- Follow **PEP‑8** for layout and naming (snake_case for functions/vars, CapWords for classes).
- **Max line length:** 100 chars (hard limit). Prefer multi‑line constructs over long lines.
- **Imports order:** stdlib → third‑party → local; one import per line; no wildcard imports.
- **Docstrings:** **PEP‑257** + **Google style** for parameters/returns/raises. Public modules/classes/functions **must** have docstrings; internal helpers **should**.
- **Type hints:** required on all public APIs; prefer explicit `typing` over `Any`. Use `from __future__ import annotations`.
- **Immutability:** favor pure functions and dataclasses with explicit fields; avoid hidden global state.
- **Naming:** clear, descriptive; avoid abbreviations unless industry‑standard (e.g., `UUID`).

---

## 3) Error Handling
- Never use bare `except:`; catch specific exceptions.
- Fail **per row** (isolated) in importers; never abort the entire run due to a single row.
- Use typed exceptions: `ProfileValidationError`, `TransformError`, `DependencyResolutionError`, `HttpError`, `UnexpectedError`.
- Include actionable messages; avoid leaking sensitive data in exception text.
- Do not suppress exceptions silently; log at appropriate level and propagate when needed.

---

## 4) Logging & Observability
- Use the central logging setup only; **no `print()`**.
- Console: **INFO→CRITICAL**; file logs: **DEBUG** with both **action‑based** and **time‑rotated** sinks.
- Always enrich logs with context: `run_id`, `action` (importer/profile), `tenant`, `pool`, `profile`.
- **Redaction:** never log secrets (tokens, passwords, API keys); redaction filter must be enabled on all handlers.
- Log levels guidance:
  - **DEBUG**: inputs after normalization, decision details, HTTP request summaries, diff results.
  - **INFO**: high‑level steps (listing, create/update), row status changes.
  - **WARNING**: recoverable anomalies (skips, missing optional data).
  - **ERROR**: profile/validation failures; HTTP 4xx.
  - **CRITICAL**: process‑level failures (startup/config fatal issues).

---

## 5) Configuration
- Single **config loader** source of truth; precedence: **CLI > ENV `DSYNC_` > YAML > defaults**.
- Support `${ENV_VAR}` interpolation in YAML for secrets.
- Do not hardcode endpoints or credentials in code; consume from config.
- Validate required values for non‑dry runs: `director.base_url`, `context.tenant`, `context.pool_uuid`.

---

## 6) Profiles (DSL) Usage
- Prefer pure declarative profiles; avoid hooks unless strictly necessary.
- Keep profile transforms whitelisted and deterministic.
- Use `diff.list_as_sets` and `diff.ignore_fields` to ensure idempotence.
- Document any intentional deviation from v2 behavior in the profile header comments and CHANGELOG.

---

## 7) Testing
- **Unit tests**: cover config precedence, transforms, mapping, prechecks, diff, importer decisions, logging redaction. Target ≥85% coverage on core.
- **Contract tests (v2↔v3)**: per importer with golden datasets; require 100% status parity and idempotence.
- **Integration tests**: fake Director API/VCR; cover retries, timeouts, pagination, monitor.
- **Smoke (E2E)**: minimal profiles + sheet; ensure artifacts and exit codes.
- Tests must be deterministic: fixed seeds, mocked time, stable comparators.

---

## 8) Performance & Caching
- List remote resources **once** per run where safe; cache inventories for `resolve` per `{pool_uuid, node}`.
- Avoid O(n²) loops on rows; pre‑index remote state by natural key.
- Stream large files when feasible; avoid holding excessive data in memory.

---

## 9) Security & Compliance
- TLS verification is **enabled by default**; allow explicit opt‑out with justification.
- Never commit secrets; `.env` files are ignored. Use environment variables in CI.
- Apply redaction filters in all logging sinks; include unit tests for masking.
- No PII in logs or artifacts; anonymize any sample datasets.

---

## 10) CLI & UX
- Keep CLI flags **backward‑compatible** with v2 where user‑visible; add `--engine=v2|v3` for migration.
- Provide helpful `--help` texts; group options logically.
- Exit code policy: `0` if no `ERROR/EXCEPTION`; non‑zero otherwise (configurable only via spec).

---

## 11) Dependencies & Packaging
- Minimal dependencies; justify each new library.
- Prefer **`pyproject.toml` (PEP 621)** for metadata; pin runtime dependencies with reasonable bounds.
- Use `ruff` for lint and format (`ruff check`, `ruff format`); consider `mypy` as informative typing gate.
- Provide **pre‑commit** hooks for lint/format/test where feasible.

---

## 12) Git Workflow & Reviews
- Branch naming: `feat/…`, `fix/…`, `refactor/…`, `docs/…`, `test/…`.
- **Conventional Commits**: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- PRs must include: scope description, test evidence (screenshots or logs), risk notes, and link to specs.
- **Review checklist** (reviewers):
  - Code follows this document (style, logging, errors, security).
  - Tests cover changes; contract tests updated if behavior changes.
  - No secrets or endpoints leaked; redaction verified.
  - Clear migration notes if user‑visible behavior changes.

---

## 13) Release & Versioning
- Use **SemVer** for DSv3 package and tools.
- Maintain a **CHANGELOG** with sections: Added, Changed, Fixed, Deprecated, Removed.
- Tag releases; attach artifacts and release notes summarizing importer status and parity.

---

## 14) Time, Locale, and Timezones
- Use **UTC** timestamps in logs and artifacts; include timezone offsets when printing local times.
- Be explicit with date formats (ISO‑8601).

---

## 15) Documentation
- Keep code examples small and focused; no production secrets or real endpoints.
- Update **docs/README** when new spec files are added or moved.
- Align terminology with the **Glossary**.

---

## 16) Deviation Policy
- Any deviation from these conventions must be documented in the PR and justified (e.g., performance constraint, external API contract).
- Deviations should be temporary and tracked via TODO with an issue reference.

---

**End of Developer Conventions**