# DirectorSync V3 – Transformer Specification

Transformers provide composable and declarative behaviour in the V3 sync pipeline.

---

## 1. Overview

A transformer:

- runs during preprocess or postprocess,
- receives an item dict + context + params,
- returns a modified item or an instruction to skip/fail,
- must be idempotent,
- must not perform external API writes (except postprocess subresource transformers).

---

## 2. Transformer Interface

All transformers share this conceptual interface:

```python
class BaseTransformer:
    def run(self, item: dict, context: dict, params: dict) -> dict | None:
        """
        Return:
          dict  -> modified item
          None  -> skip item
        Raise:
          TransformerError  -> fail item
        """
````

---

## 3. Transformer Types

### 3.1 Generic Transformers

Used by all resources.

| Name                    | Description                              |
| ----------------------- | ---------------------------------------- |
| `validate_required`     | Ensure required fields exist.            |
| `normalize_lists`       | Convert strings → lists.                 |
| `coerce_types`          | Ensure fields are int/bool/str.          |
| `jinja_render`          | Template fields with Jinja2.             |
| `resolve_references`    | Convert names → Director IDs via lookup. |
| `metadata_from_columns` | Build metadata structures.               |

---

### 3.2 Resource-Specific Transformers

Implement domain logic.

#### Alert Rules

* `alert_rules_business_rules`
* `alert_rules_build_notifications`
* `alert_rules_apply_rbac`

#### Repos

* `normalize_hiddenrepopath`
* `normalize_repoha`
* `verify_repo_paths`

#### Routing Policies

* `routing_policies_classify_lines`
* `routing_policies_build_routing_criteria`
* `apply_repo_aliases`

---

## 4. Error Handling

Transformers may define:

```yaml
on_error: fail_item | skip_item | ignore
```

* `fail_item` → item counted as error, syncing continues.
* `skip_item` → item ignored with reason.
* `ignore` → log warning, continue processing.

---

## 5. Ordering

Transformers are executed **in the order listed**.
Transformers must behave deterministically.

---

## 6. Testing

Every transformer must have:

* unit tests,
* snapshot examples (input → output),
* negative cases (missing fields, type errors).
