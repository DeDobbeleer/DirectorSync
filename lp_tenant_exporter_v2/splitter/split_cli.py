# splitter/split_cli.py
# -*- coding: utf-8 -*-
"""
Wrapper CLI pour lancer le split via un template de commande JSON.
Ajoute le paramètre --input-sh : si fourni, il sera accessible dans le template via {input_sh}.

Exemple de template (config/splitter.json) :
{
  "cmd": "\"{python}\" \"{script}\" --input \"{input}\" --input-sh \"{input_sh}\" --config-dir \"{config_dir}\" --output-dir \"{out_dir}\""
}
- Tous les placeholders non utilisés seront simplement ignorés si absents du template.
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
    ap.add_argument("--input", required=True, help="Fichier JSON mutualisé (ou AIO).")
    ap.add_argument("--input-sh", default="", help="Fichier JSON Search-Head pour les alertes (optionnel).")
    ap.add_argument("--out-dir", required=True, help="Dossier de sortie pour les XLSX split.")
    ap.add_argument("--template", required=True, help="Chemin du template JSON contenant la commande à exécuter.")
    ap.add_argument("--config-dir", default="config", help="Répertoire de configuration (par défaut: config).")
    ap.add_argument("--python", default=sys.executable, help="Binaire Python à utiliser (par défaut: python courant).")
    ap.add_argument("--script", default=str(Path(__file__).with_name("logpoint_config_splitter.py")),
                    help="Script splitter réel à invoquer (par défaut: logpoint_config_splitter.py du même dossier).")
    args, unknown = ap.parse_known_args()

    template_path = Path(args.template)
    template = json.loads(template_path.read_text(encoding="utf-8"))
    cmd_tpl = template.get("cmd") or template.get("command")
    if not cmd_tpl:
        print(f"[ERROR] Le template {template_path} ne contient pas 'cmd' ou 'command'.", file=sys.stderr)
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
        print(f"[WARN] Placeholder manquant dans tokens: {ke}. On essaie quand même.", file=sys.stderr)
        cmd_str = cmd_tpl

    # Add any unknown args transparently at the end
    if unknown:
        if os.name == "nt":
            # Sous Windows, pas de shlex.quote -> on laisse tel quel (tu as déjà mis les " " si besoin)
            cmd_str = cmd_str.strip() + " " + " ".join(unknown)
        else:
            cmd_str = cmd_str.strip() + " " + " ".join(shlex.quote(x) for x in unknown)

    print(f"[INFO] Running: {cmd_str}")
    rc = subprocess.call(cmd_str, shell=True)
    sys.exit(rc)

if __name__ == "__main__":
    main()
