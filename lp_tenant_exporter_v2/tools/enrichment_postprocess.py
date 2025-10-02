from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd

ENRICH_SHEETS = ["EnrichmentPolicy", "EnrichmentRules", "EnrichmentCriteria"]
GROUP_COL = "source"  # adjust if your XLSX uses a different header

def split_file(xlsx_path: Path, keep_original: bool = False):
    xls = pd.ExcelFile(xlsx_path, engine="openpyxl")
    writer = pd.ExcelWriter(xlsx_path, engine="openpyxl", mode="w")

    # 1) Copy non-enrichment sheets as-is
    for s in xls.sheet_names:
        if s not in ENRICH_SHEETS:
            df = xls.parse(s)
            df.to_excel(writer, sheet_name=s, index=False)

    # 2) Split enrichment sheets by GROUP_COL
    for s in ENRICH_SHEETS:
        if s not in xls.sheet_names:
            continue
        df = xls.parse(s)
        if GROUP_COL not in df.columns:
            # If no source column, optionally keep original
            if keep_original:
                df.to_excel(writer, sheet_name=s, index=False)
            continue
        for table, part in df.groupby(GROUP_COL):
            safe = str(table)[:20].replace("/", "_").replace("\\", "_").replace(" ", "_")
            sheet_name = f"{s}_{safe}"[:31]  # Excel sheet name limit
            part.to_excel(writer, sheet_name=sheet_name, index=False)

        if keep_original:
            df.to_excel(writer, sheet_name=s, index=False)

    writer.close()

def main():
    ap = argparse.ArgumentParser(description="Split enrichment sheets into multiple per table.")
    ap.add_argument("--file", help="One XLSX file to process")
    ap.add_argument("--dir", help="Process all XLSX in a directory")
    ap.add_argument("--keep-original", action="store_true", help="Keep original enrichment sheets")
    args = ap.parse_args()

    if args.file:
        split_file(Path(args.file), keep_original=args.keep_original)
    elif args.dir:
        for p in Path(args.dir).glob("*.xlsx"):
            split_file(p, keep_original=args.keep_original)
    else:
        ap.error("Specify --file or --dir")

if __name__ == "__main__":
    main()
