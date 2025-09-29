# Processing Policies Importer (DirectorSync v2)

## Purpose
Imports **Processing Policies** from an Excel workbook into Logpoint Director (API 2.x), in an idempotent and auditable way, following the v2 framework (BaseImporter pipeline, DirectorClient generic CRUD, full logging).

## Excel Contract
**Sheets required**: `ProcessingPolicy`, `EnrichmentPolicy`, `RoutingPolicy`.

**ProcessingPolicy** (columns, case-insensitive):
- `cleaned_policy_name` (preferred) or `original_policy_name` (fallback)
- `norm_policy` — NormalizationPolicy **name** (must exist on the target node)
- `enrich_policy` — **source** EnrichmentPolicy `policy_id` (empty ⇒ no enrichment)
- `routing_policy_id` — **source** RoutingPolicy `policy_id` (**required**)

**EnrichmentPolicy**:
- `policy_id`, `policy_name` (used to resolve the enrichment policy **name** from the source id)

**RoutingPolicy**:
- `policy_id`, `cleaned_policy_name` (used to resolve the routing policy **name** from the source id)

> Tip: This importer uses **names** for diff and resolves **IDs per node** at apply-time. If a dependency does not exist on the node, the item is **SKIPPED** with an explicit reason.

## Diff Model
The importer compares a canonical subset (node-agnostic):

```json
{
  "norm_policy": "<str>",
  "enrich_policy_name": "<str|''>",
  "routing_policy_name": "<str>"
}
