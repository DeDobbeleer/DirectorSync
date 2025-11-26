
---

## 3️⃣ `coding_standards.md`

```markdown
# Coding Standards – DirectorSyncV3

## 1. Purpose

These standards define **how code must be written** in the DirectorSyncV3
project. They complement the architecture and developer guidelines and are
intended to:

- enforce consistency,
- improve readability,
- reduce bugs,
- support long-term maintenance.

---

## 2. Languages and Formats

- **Programming language**: Python 3.11+
- **Package name**: `lp_sync`
- **Code / comments / docstrings**: **English only**
- **Configuration**: YAML
- **Documentation**: Markdown (`.md`)
- **SQL**: Standard, vendor-agnostic where possible (PostgreSQL-friendly).

---

## 3. Python Style (PEP-8)

Follow [PEP 8](https://peps.python.org/pep-0008/) as a baseline:

- 4 spaces per indentation level.
- `snake_case` for functions, methods, and variables.
- `PascalCase` for classes.
- UPPER_CASE for module-level constants.
- Keep lines at or below 88 characters when possible.

Imports:

- Standard library first,
- then third-party,
- then internal (`lp_sync`),
- grouped and separated by blank lines.

Example:

```python
from __future__ import annotations

import logging
from typing import Any, Dict

from lp_sync.utils.logging import get_logger
