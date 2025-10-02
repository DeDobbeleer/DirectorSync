# Splitter (unchanged)

- Place your original `logpoint_config_splitter.py` here **without modifications**.
- The wrapper `split_cli.py` reads `config/splitter.json` and invokes your script with:
  `--input <json> --config-dir config --output-dir <dir> [--log-file ...]`.

**Contract (confirmed):** one XLSX per tenant; multiple sheets per element; for *Enrichment*, many sheets (one per enrichment table).
