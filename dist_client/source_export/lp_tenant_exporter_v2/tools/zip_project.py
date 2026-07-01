#!/usr/bin/env python3
import argparse
import os
import sys
import zipfile
from datetime import datetime
from pathlib import Path

# pathspec is optional (pip install pathspec). If missing, fall back to fnmatch.
try:
    import pathspec  # type: ignore
    HAS_PATHSPEC = True
except Exception:
    import fnmatch
    HAS_PATHSPEC = False

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "dist"

# Default exclusions (always excluded)
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
    # exclude self:
    "tools/zip_project.py",
    "tools/",
]

def load_ignore_patterns(use_gitignore: bool, zipignore_path: Path) -> list[str]:
    patterns: list[str] = []

    # .zipignore first (local priority for packager)
    if zipignore_path.exists():
        patterns += zipignore_path.read_text(encoding="utf-8").splitlines()

    # optionally reuse .gitignore
    if use_gitignore:
        gi = PROJECT_ROOT / ".gitignore"
        if gi.exists():
            patterns += gi.read_text(encoding="utf-8").splitlines()

    # + default exclusions
    patterns += DEFAULT_EXCLUDES
    # Clean empty lines / comments
    cleaned = []
    for p in patterns:
        p = p.strip()
        if not p or p.startswith("#"):
            continue
        # normalize for matching relative to project root
        cleaned.append(p)
    return cleaned

def build_matcher(patterns: list[str]):
    """
    Return a should_exclude(rel_path: str) -> bool function.
    rel_path is a POSIX path relative to PROJECT_ROOT (e.g. 'src/app.py' or 'dist/pkg.zip')
    """
    if HAS_PATHSPEC:
        spec = pathspec.PathSpec.from_lines("gitwildmatch", patterns)
        def should_exclude(rel_path: str) -> bool:
            return spec.match_file(rel_path)
        return should_exclude
    else:
        # Simple fallback with fnmatch
        norm_patterns = patterns[:]
        def should_exclude(rel_path: str) -> bool:
            rp = rel_path
            # try patterns as-is + "folder/" variant
            for pat in norm_patterns:
                # if directory pattern, ensure descendants match
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
    parser.add_argument("--name", help="Archive name (without extension). Default: project folder name + timestamp.")
    parser.add_argument("--use-gitignore", action="store_true", help="Include .gitignore rules.")
    parser.add_argument("--zipignore", default=str(PROJECT_ROOT / ".zipignore"), help="Path to .zipignore (optional).")
    parser.add_argument("--dry-run", action="store_true", help="Do not write the zip, only list what would be included.")
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
        print("INCLUDED FILES (dry-run):")
        for f in included:
            print(f"  {f.relative_to(PROJECT_ROOT).as_posix()}")
        print(f"\nArchive that would be created: {out_path}")
        print("\nExclusion reminders:")
        for p in patterns:
            print(f"  - {p}")
        return

    # Create the zip
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # optional: inject a MANIFEST for transparency
        manifest_lines = [
            f"project: {PROJECT_ROOT.name}",
            f"created_at: {datetime.now().isoformat()}",
            "tool: zip_project.py",
            "excluded_rules:",
            *[f"  - {p}" for p in patterns],
            "files:",
        ]
        for f in included:
            arc = f.relative_to(PROJECT_ROOT).as_posix()
            zf.write(f, arc)
            manifest_lines.append(f"  - {arc}")

        # write manifest inside the archive (does not pollute your repo)
        zf.writestr("MANIFEST.txt", "\n".join(manifest_lines))

    print(f"Archive created: {out_path}")

if __name__ == "__main__":
    # safety: run from anywhere
    os.chdir(PROJECT_ROOT)
    sys.exit(main())
