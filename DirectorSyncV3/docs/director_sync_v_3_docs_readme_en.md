# DirectorSync v3 — Documentation README

**Status:** Draft v0.9  
**Date:** 2025‑10‑07 (Europe/Paris)  
**Audience:** Engineering, QA, Product, DevOps  
**Scope:** Index and conventions for DSv3 documentation.

---

## 1) What this folder contains
This folder centralizes all **DSv3** specifications and review artifacts. Documents are written in **English** and are implementation‑agnostic (no code inside). Each file has a clear ownership and acceptance criteria.

### Quick links
- **Functional Specification** → *functional-spec.md*  
- **Profile DSL Specification** → *profile-dsl-spec.md*  
- **Test Plan** → *test-plan.md*  
- **Profile Linter Specification** → *profile-linter-spec.md*  
- **Importer Acceptance Checklist (template)** → *importer-acceptance-checklist.md*  
- **Migration Plan** → *migration-plan.md*

> File names above are the **canonical** names to use when committing to the repo.

---

## 2) How to navigate (suggested reading order)
1. **Functional Specification** — product scope, high‑level requirements, constraints.  
2. **Profile DSL Specification** — declarative language for importers.  
3. **Test Plan** — quality strategy (unit, contract, integration, E2E).  
4. **Profile Linter Specification** — static validation rules and error codes.  
5. **Migration Plan** — v2→v3 rollout approach.  
6. **Importer Acceptance Checklist** — per‑importer go/no‑go gate.

---

## 3) Conventions
- **Language:** English only for documents and code comments.  
- **Style:** concise, actionable, avoid ambiguity; prefer MUST/SHOULD/MAY wording.  
- **Change markers:** each document starts with **Status** and **Date**; bump on edits.  
- **Versioning:** DSv3 follows **SemVer**; documents refer to DSv3 versions when relevant.  
- **Diagrams:** use simple ASCII or link to source files (Mermaid/Draw.io) under `docs/diagrams/`.

---

## 4) Contribution guidelines
1. **Propose changes** via pull request that updates the relevant doc(s) and this README if links change.  
2. **Label your PR** with `docs` and the impacted area (e.g., `profiles`, `testing`, `migration`).  
3. **Reviews required:** at least one reviewer from Engineering; QA reviews for Test Plan or Acceptance Checklist; Product reviews for Functional Spec changes.  
4. **Changelog:** summarize significant doc changes in the repo CHANGELOG under a **Docs** section.  
5. **No secrets**: never include tokens, endpoints with credentials, or customer data.

---

## 5) Folder structure (recommended)
```
directorSyncV3/
  docs/
    README.md
    functional-spec.md
    profile-dsl-spec.md
    test-plan.md
    profile-linter-spec.md
    importer-acceptance-checklist.md
    migration-plan.md
    diagrams/
      <optional .md/.mmd/.drawio sources>
```

---

## 6) Quality gates for documents
- Docs are **self‑consistent** (no contradictions across files).  
- Acceptance criteria are **testable** and **measurable**.  
- Examples are **runnable or realistic** (no placeholders that cannot be resolved).  
- Terminology is aligned with the **Glossary** (see below).

---

## 7) Glossary (short)
- **Profile** — YAML descriptor for one Director resource importer.  
- **Generic Importer** — engine that executes a profile end‑to‑end.  
- **Natural Key** — fields used to identify a remote resource uniquely.  
- **Shadow Run** — v3 computes, v2 applies; results are compared off‑line.  
- **Parity** — same statuses and comparable payloads between v2 and v3.

---

## 8) FAQ
**Q: Why English only?**  
A: To keep code, specs, and tests aligned and accessible to all contributors.  

**Q: Where are examples and datasets?**  
A: Contract (golden) datasets belong under `tests/contract/<importer>/golden/` in the project root; this folder only documents the rules.

**Q: How are secrets handled in docs?**  
A: Never include secrets. Use environment variables (`${VAR}`) in examples.

---

## 9) Next steps
- Keep this README updated when adding/modifying spec files.  
- Link CI artifacts (coverage, test reports) in the Test Plan once available.  
- Add a **CHANGELOG** excerpt in releases summarizing spec changes.

---

**Maintainers:** (TBD)  
**Contact:** (TBD)

---

**End of README**

