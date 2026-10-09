"""Run meaningful project checks without installing dependencies or starting services."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def changed_paths() -> set[str] | None:
    """Read pre-push refs when available; otherwise use worktree diff or full checks."""
    paths = set()
    if not sys.stdin.isatty():
        for line in sys.stdin.read().splitlines():
            parts = line.split()
            if len(parts) != 4:
                continue
            _, local_sha, _, remote_sha = parts
            if set(local_sha) == {"0"}:  # A deleted remote ref has no source to test.
                continue
            if set(remote_sha) == {"0"}:  # New remote branches require all checks.
                return None
            try:
                output = subprocess.check_output(["git", "diff", "--name-only", remote_sha, local_sha], cwd=ROOT, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                return None
            paths.update(output.decode().splitlines())
    if paths:
        return paths
    try:
        tracked = subprocess.check_output(["git", "diff", "--name-only", "HEAD"], cwd=ROOT, stderr=subprocess.PIPE)
        untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, stderr=subprocess.PIPE)
        paths.update((tracked + untracked).decode().splitlines())
    except subprocess.CalledProcessError:
        return None
    return paths or None


def run(label: str, command: list[str]) -> bool:
    print(f"Running {label}...", flush=True)
    return subprocess.run(command, cwd=ROOT, check=False).returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changed", action="store_true", help="Scope checks by changed/pushed files; full checks if uncertain.")
    args = parser.parse_args()
    paths = changed_paths() if args.changed else None
    if not run("syntax and secret checks", [sys.executable, "scripts/check.py", "--all"]):
        return 1
    backend_needed = paths is None or any(path.startswith(("backend/", "experiments/", "scripts/")) for path in paths)
    frontend_needed = paths is None or any(path.startswith(("frontend/", "backend/app/", "package", "scripts/")) for path in paths)
    if backend_needed and not run("backend state-transition/security tests", [sys.executable, "-m", "unittest", "discover", "-s", "backend/tests", "-v"]):
        return 1
    if backend_needed and (ROOT / "scripts/tests").exists():
        if not run("experiment adapter tests", [sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-v"]):
            return 1
    if frontend_needed:
        npm = "npm.cmd" if os.name == "nt" else "npm"
        if not run("frontend typecheck and production build", [npm, "--prefix", "frontend", "run", "build"]):
            return 1
    print("Project verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

