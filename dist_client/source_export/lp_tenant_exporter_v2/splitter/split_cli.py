# splitter/split_cli.py
"""
Wrapper CLI to run the split via a JSON command template.
Adds the --input-sh parameter: if provided, it is available in the template as {input_sh}.

Template example (config/splitter.json):
{
  "cmd": "\"{python}\" \"{script}\" --input \"{input}\" --input-sh \"{input_sh}\" --config-dir \"{config_dir}\" --output-dir \"{out_dir}\""
}
- Unused placeholders are silently ignored if missing from the template.
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description="Split wrapper (template-driven)")
    ap.add_argument("--input", required=True, help="Shared JSON file (or AIO).")
    ap.add_argument("--input-sh", default="", help="Search-Head JSON file for alerts (optional).")
    ap.add_argument("--out-dir", required=True, help="Output folder for split XLSX files.")
    ap.add_argument("--template", required=True, help="Path to the JSON template containing the command to run.")
    ap.add_argument("--config-dir", default="config", help="Configuration directory (default: config).")
    ap.add_argument("--python", default=sys.executable, help="Python binary to use (default: current python).")
    ap.add_argument("--script", default=str(Path(__file__).with_name("logpoint_config_splitter.py")),
                    help="Actual splitter script to invoke (default: logpoint_config_splitter.py in the same folder).")
    args, unknown = ap.parse_known_args()

    template_path = Path(args.template)
    template = json.loads(template_path.read_text(encoding="utf-8"))
    cmd_tpl = template.get("cmd") or template.get("command")
    if not cmd_tpl:
        print(f"[ERROR] Template {template_path} does not contain 'cmd' or 'command'.", file=sys.stderr)
        sys.exit(2)

    # Build token map
    tokens = {
        "python": args.python,
        "script": args.script,
        "input": args.input,
        "input_sh": args.input_sh,
        "out_dir": args.out_dir,
        "config_dir": args.config_dir,
    }

    # Expand placeholders safely
    try:
        cmd_str = cmd_tpl.format(**tokens)
    except KeyError as ke:
        print(f"[WARN] Missing placeholder in tokens: {ke}. Trying anyway.", file=sys.stderr)
        cmd_str = cmd_tpl

    # Add any unknown args transparently at the end
    if unknown:
        if os.name == "nt":
            # On Windows, no shlex.quote -> pass through as-is (user already quoted if needed)
            cmd_str = cmd_str.strip() + " " + " ".join(unknown)
        else:
            cmd_str = cmd_str.strip() + " " + " ".join(shlex.quote(x) for x in unknown)

    print(f"[INFO] Running: {cmd_str}")
    rc = subprocess.call(cmd_str, shell=True)
    sys.exit(rc)

if __name__ == "__main__":
    main()
