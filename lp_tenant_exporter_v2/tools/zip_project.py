#!/usr/bin/env python3
import argparse
import os
import sys
import zipfile
from pathlib import Path
from datetime import datetime

# pathspec est optionnel (pip install pathspec). Si absent, on degrade en fnmatch.
try:
    import pathspec  # type: ignore
    HAS_PATHSPEC = True
except Exception:
    import fnmatch
    HAS_PATHSPEC = False

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "dist"

# Exclusions par défaut (toujours exclues)
DEFAULT_EXCLUDES = [
    ".git/",
    ".github/",
    ".vscode/",
    "dist/",
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.py.class",
    ".venv/",
    "venv/",
    "ENV/",
    "Thumbs.db",
    ".DS_Store",
    # s'auto-exclure :
    "tools/zip_project.py",
    "tools/",
]

def load_ignore_patterns(use_gitignore: bool, zipignore_path: Path) -> list[str]:
    patterns: list[str] = []

    # .zipignore d'abord (priorité locale au packager)
    if zipignore_path.exists():
        patterns += zipignore_path.read_text(encoding="utf-8").splitlines()

    # éventuellement réutiliser .gitignore
    if use_gitignore:
        gi = PROJECT_ROOT / ".gitignore"
        if gi.exists():
            patterns += gi.read_text(encoding="utf-8").splitlines()

    # + exclusions par défaut
    patterns += DEFAULT_EXCLUDES
    # Nettoie les lignes vides / commentaires
    cleaned = []
    for p in patterns:
        p = p.strip()
        if not p or p.startswith("#"):
            continue
        # normalise pour un matching relatif depuis la racine
        cleaned.append(p)
    return cleaned

def build_matcher(patterns: list[str]):
    """
    Retourne une fonction should_exclude(rel_path: str) -> bool
    rel_path est un chemin POSIX relatif à PROJECT_ROOT (ex: 'src/app.py' ou 'dist/pkg.zip')
    """
    if HAS_PATHSPEC:
        spec = pathspec.PathSpec.from_lines("gitwildmatch", patterns)
        def should_exclude(rel_path: str) -> bool:
            return spec.match_file(rel_path)
        return should_exclude
    else:
        # Degrade simple avec fnmatch
        norm_patterns = patterns[:]
        def should_exclude(rel_path: str) -> bool:
            rp = rel_path
            # essayer patterns tels quels + variante "dossier/"
            for pat in norm_patterns:
                # si pattern répertoire, s'assurer qu'on matche les descendants
                if pat.endswith("/"):
                    if rp == pat[:-1] or rp.startswith(pat):
                        return True
                # match glob
                if fnmatch.fnmatch(rp, pat):
                    return True
            return False
        return should_exclude

def iter_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file():
            yield p

def make_zip_name(name: str | None) -> Path:
    DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    if not name:
        name = PROJECT_ROOT.name
    return DEFAULT_OUTPUT_DIR / f"{name}-{ts}.zip"

def main():
    parser = argparse.ArgumentParser(description="Package project into a zip with ignore rules.")
    parser.add_argument("--name", help="Nom de l'archive (sans extension). Par défaut: nom du dossier projet + timestamp.")
    parser.add_argument("--use-gitignore", action="store_true", help="Inclure les règles .gitignore.")
    parser.add_argument("--zipignore", default=str(PROJECT_ROOT / ".zipignore"), help="Chemin vers le .zipignore (optionnel).")
    parser.add_argument("--dry-run", action="store_true", help="N'écrit pas le zip, affiche seulement ce qui serait inclus.")
    args = parser.parse_args()

    zipignore_path = Path(args.zipignore)
    patterns = load_ignore_patterns(args.use_gitignore, zipignore_path)
    should_exclude = build_matcher(patterns)

    out_path = make_zip_name(args.name)
    included: list[Path] = []
    for f in iter_files(PROJECT_ROOT):
        rel = f.relative_to(PROJECT_ROOT).as_posix()
        if should_exclude(rel):
            continue
        included.append(f)

    if args.dry_run:
        print("FICHIERS INCLUS (dry-run):")
        for f in included:
            print(f"  {f.relative_to(PROJECT_ROOT).as_posix()}")
        print(f"\nArchive qui serait créée: {out_path}")
        print("\nRappels d'exclusion :")
        for p in patterns:
            print(f"  - {p}")
        return

    # Création du zip
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # option: injecter un MANIFEST pour transparence
        manifest_lines = [
            f"project: {PROJECT_ROOT.name}",
            f"created_at: {datetime.now().isoformat()}",
            f"tool: zip_project.py",
            "excluded_rules:",
            *[f"  - {p}" for p in patterns],
            "files:",
        ]
        for f in included:
            arc = f.relative_to(PROJECT_ROOT).as_posix()
            zf.write(f, arc)
            manifest_lines.append(f"  - {arc}")

        # écrire le manifest dans l’archive (ne pollue pas ton repo)
        zf.writestr("MANIFEST.txt", "\n".join(manifest_lines))

    print(f"Archive créée : {out_path}")

if __name__ == "__main__":
    # sécurité: exécuter depuis n'importe où
    os.chdir(PROJECT_ROOT)
    sys.exit(main())
