#!/usr/bin/env python3
"""
Collectors from <backend>.json — Majority Rule by Device Name
------------------------------------------------------------

Goal
====
Derive **collector → tenant** mapping from a mutualized backend export (e.g. `sync_config_ESA.json`).

Business rule (as specified):
1) The **tenant is encoded in the device name**. We detect it using a list of tenant slugs.
2) Some devices **may not** contain a tenant in their name. In that case, the **collector belongs to the
   tenant for which it has the **highest number of devices** (majority vote across devices that DO have a tenant in name).

Outputs
=======
- **Markdown** tables by default (use `--format csv` to get CSV instead):
  - `collector_majority_mapping.md` → columns: `collector_id | tenant | votes | tie | breakdown_json`
  - `tenant_collectors_summary.md` → columns: `tenant | collector_ids`
- If `--format csv` is chosen, the files are `collector_majority_mapping.csv` and `tenant_collectors_summary.csv`.

Usage
=====
```bash
python collectors_from_backend_json.py /path/to/backend.json \
  --tenants core,esrin,esait,moi,sccoe,tia \
  --out /path/to/out -v
```

Options
=======
- `--tenants` (required): comma-separated tenant slugs used to detect the tenant in `Device.name`.
- `--collector-field` (default: `distributed_collector`): field holding collector ids per device.
- `--name-field` (default: `name`): field used to find the tenant slug.
- `--left-of-colon`: if collector cell looks like `collectorId:extra`, keep only `collectorId`.
- `--tie-policy {first,unassigned}` (default: `first`): how to resolve ties in top votes per collector:
  - `first`: pick the first tenant (by order in `--tenants`) among the tied tenants.
  - `unassigned`: mark tenant as `Unassigned` when there is a tie.
- `--format {md,csv}` (default: `md`): choose Markdown or CSV outputs.
- `-v/--verbose`: verbose logging.

No external deps required (pure Python). Tested on Python 3.10+.

"""
from __future__ import annotations
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SEPARATORS_REGEX = re.compile(r"[;,\n\r\t\s]+")

@dataclass
class Options:
    backend_json: Path
    out_dir: Path
    tenants: List[str]
    collector_field: str = "distributed_collector"
    name_field: str = "name"
    left_of_colon: bool = False
    tie_policy: str = "first"  # or "unassigned"
    out_format: str = "md"      # or "csv"
    verbose: bool = False


def load_backend(path: Path, verbose: bool = False) -> Dict:
    if not path.exists():
        raise FileNotFoundError(f"Backend JSON not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "Sync" not in data or "Device" not in data["Sync"]:
        raise ValueError("Unexpected backend JSON. Expected dict with Sync.Device list.")
    if verbose:
        print(f"[INFO] Loaded backend with {len(data['Sync']['Device'])} devices")
    return data


def parse_collectors(value) -> List[str]:
    """Parse a distributed_collector value into a list of clean IDs."""
    if value is None:
        return []
    # Try JSON array embedded as string
    if isinstance(value, str):
        s = value.strip()
        if not s or s.lower() in {"none", "null", "nan"}:
            return []
        if s.startswith("[") and s.endswith("]"):
            try:
                arr = json.loads(s)
                return [str(x).strip() for x in arr if str(x).strip()]
            except Exception:
                pass
        # Otherwise split on common separators
        parts = [p.strip() for p in SEPARATORS_REGEX.split(s) if p.strip()]
        return parts

    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]

    # Fallback scalar
    s = str(value).strip()
    return [s] if s else []


def normalize_collectors(parts: List[str], left_of_colon: bool) -> List[str]:
    clean: List[str] = []
    seen = set()
    for p in parts:
        if left_of_colon and ":" in p:
            p = p.split(":", 1)[0]
        p = p.strip()
        if p and p not in seen:
            clean.append(p)
            seen.add(p)
    return clean


def match_tenant_by_name(device_name: str, tenants: List[str]) -> Optional[str]:
    name_l = (device_name or "").lower()
    # Longest slug first to avoid partial collisions
    for slug in sorted(tenants, key=len, reverse=True):
        if slug.lower() in name_l:
            return slug
    return None


def top_vote(tenant_counts: Dict[str, int], tenants_order: List[str], tie_policy: str) -> Tuple[str, int, bool]:
    """Return (tenant, votes, tie) from counts for a collector."""
    if not tenant_counts:
        return ("Unassigned", 0, False)
    max_votes = max(tenant_counts.values())
    winners = [t for t, v in tenant_counts.items() if v == max_votes]
    tie = len(winners) > 1
    if tie:
        if tie_policy == "unassigned":
            return ("Unassigned", max_votes, True)
        # 'first' policy: pick first by tenants_order
        for t in tenants_order:
            if t in winners:
                return (t, max_votes, True)
        # fallback if none match order (shouldn't happen)
        return (sorted(winners)[0], max_votes, True)
    else:
        return (winners[0], max_votes, False)


def aggregate_majority(backend: Dict, opts: Options) -> Tuple[List[Tuple[str, str, int, bool, Dict[str,int]]], Dict[str, List[str]]]:
    devices = backend["Sync"]["Device"]

    # 1) Count votes per collector from devices that DO have tenant in name
    per_collector_counts: Dict[str, Counter] = defaultdict(Counter)

    for dev in devices:
        name = str(dev.get(opts.name_field, ""))
        tenant = match_tenant_by_name(name, opts.tenants)
        if not tenant:
            continue  # devices without tenant in name do not vote
        parts = parse_collectors(dev.get(opts.collector_field))
        parts = normalize_collectors(parts, left_of_colon=opts.left_of_colon)
        if not parts:
            continue
        for cid in parts:
            per_collector_counts[cid][tenant] += 1

    # 2) Build majority mapping per collector
    mapping_rows: List[Tuple[str, str, int, bool, Dict[str,int]]] = []  # (collector_id, tenant, votes, tie, breakdown)
    tenant_to_collectors: Dict[str, List[str]] = defaultdict(list)

    for cid, counts in sorted(per_collector_counts.items()):
        # convert Counter to regular dict for JSON
        counts_dict = dict(counts)
        tenant, votes, tie = top_vote(counts_dict, opts.tenants, opts.tie_policy)
        mapping_rows.append((cid, tenant, votes, tie, counts_dict))
        if tenant != "Unassigned":
            tenant_to_collectors[tenant].append(cid)

    # 3) Sort collectors lists
    for t in list(tenant_to_collectors.keys()):
        tenant_to_collectors[t] = sorted(set(tenant_to_collectors[t]))

    return mapping_rows, tenant_to_collectors


# -------------------- Writers (CSV and Markdown) --------------------

def write_csv_mapping(rows: List[Tuple[str, str, int, bool, Dict[str,int]]], out_path: Path) -> None:
    import csv, json
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["collector_id", "tenant", "votes", "tie", "breakdown_json"])
        for cid, tenant, votes, tie, breakdown in rows:
            w.writerow([cid, tenant, votes, str(tie).lower(), json.dumps(breakdown, ensure_ascii=False)])


def write_csv_summary(tenant_to_collectors: Dict[str, List[str]], out_path: Path) -> None:
    import csv
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["tenant", "collector_ids"])
        for tenant in sorted(tenant_to_collectors.keys()):
            w.writerow([tenant, ", ".join(tenant_to_collectors[tenant])])


def write_md_table(headers: List[str], rows: List[List[str]], out_path: Path) -> None:
    # Build Markdown table content
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for r in rows:
        lines.append("| " + " | ".join(r) + " |")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_md_mapping(rows: List[Tuple[str, str, int, bool, Dict[str,int]]], out_path: Path) -> None:
    import json
    headers = ["collector_id", "tenant", "votes", "tie", "breakdown_json"]
    md_rows: List[List[str]] = []
    for cid, tenant, votes, tie, breakdown in rows:
        md_rows.append([
            str(cid),
            str(tenant),
            str(votes),
            "true" if tie else "false",
            f"`{json.dumps(breakdown, ensure_ascii=False)}`",
        ])
    write_md_table(headers, md_rows, out_path)


def write_md_summary(tenant_to_collectors: Dict[str, List[str]], out_path: Path) -> None:
    headers = ["tenant", "collector_ids"]
    rows: List[List[str]] = []
    for tenant in sorted(tenant_to_collectors.keys()):
        rows.append([tenant, ", ".join(tenant_to_collectors[tenant])])
    write_md_table(headers, rows, out_path)


# ------------------------------ CLI ------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description="Majority-vote collector→tenant mapping from <backend>.json using tenant slugs in device names")
    p.add_argument("backend_json", type=Path, help="Path to <backend>.json (e.g., sync_config_ESA.json)")
    p.add_argument("--tenants", type=str, required=True, help="Comma-separated tenant slugs present in device names (e.g., core,esrin,esait,moi,sccoe,tia)")
    p.add_argument("--out", dest="out_dir", type=Path, default=Path.cwd(), help="Output directory for files")
    p.add_argument("--collector-field", default="distributed_collector", help="Field name holding collectors (default: distributed_collector)")
    p.add_argument("--name-field", default="name", help="Device name field (default: name)")
    p.add_argument("--left-of-colon", action="store_true", help="When collector value contains 'id:extra', keep only the part before ':'")
    p.add_argument("--tie-policy", choices=["first", "unassigned"], default="first", help="Tie breaker for top votes per collector (default: first)")
    p.add_argument("--format", choices=["md", "csv"], default="md", help="Output format: markdown tables (md) or CSV")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = p.parse_args()

    tenants_list: List[str] = [s.strip() for s in args.tenants.split(",") if s.strip()]
    opts = Options(
        backend_json=args.backend_json,
        out_dir=args.out_dir,
        tenants=tenants_list,
        collector_field=args.collector_field,
        name_field=args.name_field,
        left_of_colon=args.left_of_colon,
        tie_policy=args.tie_policy,
        out_format=args.format,
        verbose=args.verbose,
    )

    try:
        backend = load_backend(opts.backend_json, verbose=opts.verbose)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2

    mapping_rows, tenant_to_collectors = aggregate_majority(backend, opts)

    opts.out_dir.mkdir(parents=True, exist_ok=True)

    if opts.out_format == "csv":
        mapping_path = opts.out_dir / "collector_majority_mapping.csv"
        summary_path = opts.out_dir / "tenant_collectors_summary.csv"
        write_csv_mapping(mapping_rows, mapping_path)
        write_csv_summary(tenant_to_collectors, summary_path)
    else:
        mapping_path = opts.out_dir / "collector_majority_mapping.md"
        summary_path = opts.out_dir / "tenant_collectors_summary.md"
        write_md_mapping(mapping_rows, mapping_path)
        write_md_summary(tenant_to_collectors, summary_path)

    if opts.verbose:
        print("Collector → Tenant (majority) summary:")
        for tenant, collectors in sorted(tenant_to_collectors.items()):
            print(f"- {tenant}: {', '.join(collectors)}")
        print(f"\nWrote: {mapping_path}")
        print(f"Wrote: {summary_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
