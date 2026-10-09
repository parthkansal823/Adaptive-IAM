"""Fast local checks; staged mode reads index bytes, never unstaged secrets."""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".toml", ".json", ".ts", ".tsx", ".js", ".jsx", ".md", ".yaml", ".yml", ".ps1", ".sh", ".txt", ".html", ".css"}
IGNORE_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", ".pytest_cache", ".ruff_cache", "data", "models", "artifacts", ".cache"}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "OpenAI-style key": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b"),
    "GitHub token": re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]{30,}\b"),
}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.PIPE)


def staged_files() -> list[tuple[str, bytes]]:
    paths = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").decode().split("\0")
    return [(path, git("show", f":{path}")) for path in paths if path]


def working_files() -> list[tuple[str, bytes]]:
    files = []
    # os.walk prunes ignored directories before recursion; dependencies stay out of the scan.
    import os
    for directory, dirs, names in os.walk(ROOT):
        dirs[:] = [name for name in dirs if name not in IGNORE_PARTS]
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or (name.startswith(".env") and not name.endswith(".example")):
                continue  # Never read local credentials; staged mode rejects their filenames.
            if path.suffix.lower() in TEXT_SUFFIXES or name.startswith(".env"):
                if path.stat().st_size <= 2 * 1024 * 1024:
                    files.append((path.relative_to(ROOT).as_posix(), path.read_bytes()))
    return files


def check_file(path: str, data: bytes) -> list[str]:
    relative = PurePosixPath(path)
    errors: list[str] = []
    if relative.name.startswith(".env") and not relative.name.endswith(".example"):
        errors.append(f"{path}: local environment file must not be committed")
    if relative.suffix in {".pem", ".key"} or relative.name in {"id_rsa", "id_ed25519"}:
        errors.append(f"{path}: private-key file must not be committed")
    if relative.suffix not in TEXT_SUFFIXES and not relative.name.startswith(".env"):
        return errors
    if len(data) > 2 * 1024 * 1024:
        return errors
    try:
        source = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return errors
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(source):
            errors.append(f"{path}: potential {label}; value intentionally omitted")
    try:
        if relative.suffix == ".py":
            ast.parse(source, filename=path)
        elif relative.suffix == ".json":
            json.loads(source)
        elif relative.suffix == ".toml":
            tomllib.loads(source)
    except (SyntaxError, ValueError) as exc:
        # Do not echo source/secret-bearing line contents from parser errors.
        errors.append(f"{path}: invalid {relative.suffix} syntax ({type(exc).__name__})")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="Inspect Git index only (pre-commit default).")
    mode.add_argument("--all", action="store_true", help="Inspect project source, excluding dependencies/artifacts.")
    args = parser.parse_args()
    try:
        files = working_files() if args.all else staged_files()
    except (OSError, subprocess.CalledProcessError):
        print("Checks could not inspect the repository; run from a Git checkout.", file=sys.stderr)
        return 1
    failures = [failure for path, data in files for failure in check_file(path, data)]
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Lightweight checks: {len(files)} source files inspected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
