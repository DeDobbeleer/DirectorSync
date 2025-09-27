#!/usr/bin/env python3
"""
Collect all GitHub 'raw' file URLs from a repository tree into a text file.

Features:
- Loads GITHUB_TOKEN from .env (if python-dotenv is installed) or from environment.
- Auto-detects default branch unless --branch is provided.
- Traverses the repo tree recursively via GitHub Trees API.
- Optional filtering by subdirectory prefix and file extensions.
- Robust HTTP session with retries and timeouts.
- Redacts token from error messages/logs.

Examples:
    python collect_raw_links.py \
        --repo-url https://github.com/DeDobbeleer/DirectorSync \
        --prefix lp_tenant_importer \
        --ext .py .yml .yaml .toml \
        --out raw_links.txt
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# Optional .env support
try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover
    load_dotenv = None  # fallback later

# HTTP client
try:
    import requests
    from requests.adapters import HTTPAdapter
    try:
        # Retry may come from urllib3 packaged with requests
        from urllib3.util.retry import Retry  # type: ignore
    except Exception:  # pragma: no cover
        Retry = None  # type: ignore
except ImportError as exc:  # pragma: no cover
    print("[error] Missing dependency: requests. Install with `pip install requests`.", file=sys.stderr)
    raise

GITHUB_API = "https://api.github.com"


class GitHubError(RuntimeError):
    """Raised when GitHub API returns an unexpected error."""


def load_env_token() -> Optional[str]:
    """
    Load GITHUB_TOKEN from .env or environment.
    - If python-dotenv is installed, it loads .env automatically.
    - Otherwise, it only reads the current environment.
    """
    if load_dotenv:
        try:
            load_dotenv()  # searches upward for a .env file
        except Exception:
            # Non-fatal: continue without .env
            pass
    return os.getenv("GITHUB_TOKEN")


def redact_token(text: str) -> str:
    """Replace the token in text with *** if present."""
    tok = os.getenv("GITHUB_TOKEN") or ""
    if tok and tok in text:
        return text.replace(tok, "***")
    return text


def parse_repo_url(url: str) -> Tuple[str, str]:
    """
    Parse a GitHub repo URL and return (owner, repo).
    Accepts forms like:
      - https://github.com/owner/repo
      - https://github.com/owner/repo/
      - git@github.com:owner/repo.git
      - https://github.com/owner/repo.git
    """
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    if "github.com:" in url:
        # git@github.com:owner/repo
        part = url.split("github.com:")[-1]
        owner, repo = part.split("/", 1)
        return owner, repo

    if "github.com/" in url:
        part = url.split("github.com/")[-1]
        owner, repo = part.split("/", 1)
        return owner, repo

    raise ValueError(f"Unrecognized GitHub URL: {url}")


def make_session(timeout_s: int = 20) -> requests.Session:
    """
    Create a robust HTTP session with optional Authorization header,
    sensible retries, and default timeouts.
    """
    token = load_env_token()  # populates environment if .env exists
    session = requests.Session()

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "raw-link-collector/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    session.headers.update(headers)

    # Timeouts via wrapper
    original_request = session.request

    def request_with_timeout(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout_s)
        return original_request(method, url, **kwargs)

    session.request = request_with_timeout  # type: ignore

    # Retries (if urllib3 Retry is available)
    if 'HTTPAdapter' in globals() and 'Retry' in globals() and Retry:
        retry = Retry(
            total=5,
            connect=3,
            read=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

    return session


def get_default_branch(session: requests.Session, owner: str, repo: str) -> str:
    """Fetch the repository default branch."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}"
    resp = session.get(url)
    if resp.status_code != 200:
        raise GitHubError(f"Failed to get repo info: {resp.status_code} {redact_token(resp.text)}")
    data = resp.json()
    default_branch = data.get("default_branch")
    if not default_branch:
        raise GitHubError("Could not determine default branch.")
    return default_branch


def get_tree_recursive(session: requests.Session, owner: str, repo: str, ref: str) -> List[dict]:
    """
    List the entire repository tree (files and directories) at a given ref (branch/commit),
    using the Git Trees API with recursive=1.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{ref}"
    resp = session.get(url, params={"recursive": "1"})
    if resp.status_code != 200:
        # Some repos require passing the branch SHA; try a second-chance fetch
        # but here we just raise for simplicity.
        raise GitHubError(f"Failed to get tree: {resp.status_code} {redact_token(resp.text)}")
    data = resp.json()
    tree = data.get("tree", [])
    if not isinstance(tree, list):
        raise GitHubError("Unexpected tree format from GitHub API.")
    return tree


def matches_filters(path: str, prefix: Optional[str], exts: Optional[Iterable[str]]) -> bool:
    """Return True if the given path matches the optional prefix and extension filters."""
    if prefix:
        norm_prefix = prefix.strip("/").lower()
        p = path.lower()
        if not (p == norm_prefix or p.startswith(norm_prefix + "/")):
            return False
    if exts:
        lower = path.lower()
        if not any(lower.endswith(e.lower()) for e in exts):
            return False
    return True


def build_raw_url(owner: str, repo: str, branch: str, path: str) -> str:
    """Construct a raw.githubusercontent.com URL for a given path."""
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def write_lines(paths: Iterable[str], out_file: Path) -> None:
    """Write each string from `paths` into `out_file`, one per line (UTF-8)."""
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w", encoding="utf-8") as fh:
        for item in paths:
            fh.write(item)
            if not item.endswith("\n"):
                fh.write("\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect GitHub 'raw' URLs into a text file."
    )
    parser.add_argument(
        "--repo-url",
        required=True,
        help="GitHub repository URL (e.g., https://github.com/owner/repo)",
    )
    parser.add_argument(
        "--branch",
        help="Branch (ref) to scan; default is the repository default branch.",
    )
    parser.add_argument(
        "--prefix",
        help="Optional subdirectory to restrict, e.g., lp_tenant_importer",
    )
    parser.add_argument(
        "--ext",
        nargs="*",
        help="Optional list of file extensions to include (e.g., .py .yml .yaml .toml)",
    )
    parser.add_argument(
        "--out",
        default="raw_links.txt",
        help="Output text file (one URL per line). Default: raw_links.txt",
    )
    args = parser.parse_args(argv)

    # Prepare session
    session = make_session(timeout_s=20)

    # Parse repo
    try:
        owner, repo = parse_repo_url(args.repo_url)
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    # Resolve branch
    try:
        branch = args.branch or get_default_branch(session, owner, repo)
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 3

    # Fetch tree
    try:
        tree = get_tree_recursive(session, owner, repo, branch)
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 4

    # Keep only files (blobs)
    blobs = [t for t in tree if t.get("type") == "blob" and t.get("path")]
    if args.prefix or args.ext:
        blobs = [b for b in blobs if matches_filters(b["path"], args.prefix, args.ext)]

    raw_links = [build_raw_url(owner, repo, branch, b["path"]) for b in blobs]

    # Write output
    out_path = Path(args.out)
    try:
        write_lines(raw_links, out_path)
    except OSError as exc:
        print(f"[error] Could not write output file '{out_path}': {exc}", file=sys.stderr)
        return 5

    print(f"[ok] Wrote {len(raw_links)} raw links to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
