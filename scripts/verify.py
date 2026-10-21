"""Run meaningful project checks without installing dependencies or starting services."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


SOURCE_PATHS = ("backend/", "frontend/", "integrations/", "blockchain/", "deployment/", "compose.yaml", ".dockerignore", "experiments/", "scripts/", ".githooks/", "package.json", "package-lock.json")


def check_pushed_snapshot(refs: list[list[str]]) -> bool:
    """Test the pushed code only when it matches the working source used by checks."""
    if not refs:
        print("Pre-push verification requires Git's pushed-ref input.", file=sys.stderr)
        return False
    try:
        untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT)
        untracked_sources = {p for p in untracked.decode().split("\0") if p.startswith(SOURCE_PATHS)}
        for _, local_sha, _, _ in refs:
            if set(local_sha) == {"0"}:
                continue
            difference = subprocess.check_output(["git", "diff", "--name-only", "-z", local_sha, "--", *SOURCE_PATHS], cwd=ROOT)
            mismatches = {p for p in difference.decode().split("\0") if p} | untracked_sources
            if mismatches:
                print("Pushed commit differs from the source available to the checks. Review and commit the complete intended changes, then push again.", file=sys.stderr)
                print("Differing source paths: " + ", ".join(sorted(mismatches)[:12]), file=sys.stderr)
                return False
    except (OSError, subprocess.CalledProcessError):
        print("Cannot establish that the pushed commit matches the checked source.", file=sys.stderr)
        return False
    return True


def pushed_refs() -> list[list[str]]:
    if sys.stdin.isatty():
        return []
    return [parts for line in sys.stdin.read().splitlines() if len(parts := line.split()) == 4]


def changed_paths(refs: list[list[str]]) -> set[str] | None:
    """Read pre-push refs when available; otherwise use worktree diff or full checks."""
    paths = set()
    if refs:
        for parts in refs:
            _, local_sha, _, remote_sha = parts
            if set(local_sha) == {"0"}:  # A deleted remote ref has no source to test.
                continue
            if set(remote_sha) == {"0"}:  # New remote branches require all checks.
                return None
            try:
                output = subprocess.check_output(["git", "diff", "--name-only", remote_sha, local_sha], cwd=ROOT, stderr=subprocess.PIPE)
            except (OSError, subprocess.CalledProcessError):
                return None
            paths.update(output.decode().splitlines())
    if paths:
        return paths
    try:
        tracked = subprocess.check_output(["git", "diff", "--name-only", "HEAD"], cwd=ROOT, stderr=subprocess.PIPE)
        untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, stderr=subprocess.PIPE)
        paths.update((tracked + untracked).decode().splitlines())
    except (OSError, subprocess.CalledProcessError):
        return None
    return paths or None


def run(label: str, command: list[str]) -> bool:
    print(f"Running {label}...", flush=True)
    try:
        return subprocess.run(command, cwd=ROOT, check=False).returncode == 0
    except OSError:
        print(f"Could not start {label}. Check that {command[0]} is installed and available. Run python scripts/doctor.py for prerequisite diagnostics.", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changed", action="store_true", help="Scope checks by changed/pushed files; full checks if uncertain.")
    parser.add_argument("--pre-push", action="store_true", help="Require working source to match the actual pushed commits.")
    parser.add_argument("--browser", action="store_true", help="Build the console and run isolated Chromium browser regressions.")
    parser.add_argument("--live-web3", action="store_true", help="Run API tests against a new ephemeral loopback Ganache chain.")
    args = parser.parse_args()
    refs = pushed_refs() if args.pre_push else []
    if args.pre_push and not check_pushed_snapshot(refs):
        return 1
    paths = changed_paths(refs) if args.changed else None
    if not run("syntax and secret checks", [sys.executable, "scripts/check.py", "--all"]):
        return 1
    backend_needed = paths is None or any(path.startswith(("backend/", "experiments/", "scripts/")) for path in paths)
    frontend_needed = paths is None or any(path.startswith(("frontend/", "backend/app/", "package", "scripts/")) for path in paths)
    integration_needed = paths is None or any(path.startswith(("integrations/", "backend/app/", "scripts/")) for path in paths)
    blockchain_needed = paths is None or any(path.startswith(("blockchain/", "backend/app/", "deployment/", "compose", "scripts/")) for path in paths)
    if backend_needed and not run("backend state-transition/security tests", [sys.executable, "scripts/run_tests.py", "-s", "backend/tests"]):
        return 1
    if backend_needed and (ROOT / "scripts/tests").exists():
        if not run("experiment adapter tests", [sys.executable, "scripts/run_tests.py", "-s", "scripts/tests"]):
            return 1
    if backend_needed and (ROOT / "experiments/tests").exists():
        if not run("research protocol invariants", [sys.executable, "scripts/run_tests.py", "-s", "experiments/tests"]):
            return 1
    npm = "npm.cmd" if os.name == "nt" else "npm"
    if integration_needed:
        if not run("Python OIDC relying-party security tests", [sys.executable, "scripts/run_tests.py", "-s", "integrations/python/tests"]):
            return 1
        if not run("Node OIDC relying-party security tests", [npm, "--prefix", "integrations/node", "test"]):
            return 1
    if blockchain_needed and not run("local Solidity/EVM contract security tests", [npm, "--prefix", "blockchain", "test"]):
        return 1
    if args.live_web3 and not run("isolated live-chain API security tests", ["node", "blockchain/scripts/verify-api.mjs"]):
        return 1
    if frontend_needed or args.browser:
        if not run("frontend typecheck and production build", [npm, "--prefix", "frontend", "run", "build"]):
            return 1
    if args.browser and not run("console browser regressions", ["node", "frontend/tests/console-regression.mjs"]):
        return 1
    print("Project verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
