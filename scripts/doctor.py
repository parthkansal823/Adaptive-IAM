"""Check local prerequisites without installing packages or reading runtime secrets."""
from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

try:
    from .node_runtime import NodeRuntimeMissing, find_node_runtime
except ImportError:
    from node_runtime import NodeRuntimeMissing, find_node_runtime

ROOT = Path(__file__).resolve().parents[1]


def inspect_environment() -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    def report(level: str, message: str) -> None:
        findings.append((level, message))

    if sys.version_info < (3, 11):
        report("FAIL", "Python 3.11 or newer is required; use Python 3.13 to match CI.")
    elif sys.version_info[:2] != (3, 13):
        report("WARN", f"Python {sys.version_info.major}.{sys.version_info.minor} is active; CI uses Python 3.13.")
    else:
        report("OK", "Python 3.13 matches CI.")
    if sys.prefix == sys.base_prefix:
        report("WARN", "No virtual environment is active. Run this check with .venv's Python after setup.")

    for line in (ROOT / "backend/requirements-dev.txt").read_text(encoding="utf-8").splitlines() + (ROOT / "backend/requirements.txt").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([\w-]+)(?:\[[\w,.-]+\])?==([^\s;]+)", line.strip())
        if not match:
            continue
        name, expected = match.groups()
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            report("FAIL", f"Missing Python package {name}; install backend/requirements-dev.txt with this interpreter.")
        else:
            report("OK" if installed == expected else "FAIL", f"{name}: {installed} (required {expected}).")

    try:
        runtime = find_node_runtime(ROOT)
    except NodeRuntimeMissing as exc:
        report("FAIL", str(exc))
        runtime = None
    for command in ("node", "npm", "git"):
        if command in ("node", "npm"):
            if runtime is None:
                continue
            invocation, env = runtime.command([command, "--version"]), runtime.environment()
        else:
            executable = shutil.which(command)
            if not executable:
                report("FAIL", f"{command} is missing from PATH. Install it, then open a new terminal.")
                continue
            invocation, env = [executable, "--version"], None
        try:
            result = subprocess.run(invocation, env=env, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            report("FAIL", f"{command} could not run. Check its installation and execution permissions.")
            continue
        if result.returncode:
            report("FAIL", f"{command} --version failed. Check its installation and execution permissions.")
        elif command == "node":
            match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", result.stdout.strip())
            version = tuple(map(int, match.groups())) if match else (0, 0, 0)
            if version < (22, 12, 0):
                report("FAIL", "Use Node.js 24 LTS for the frontend build and project checks.")
            else:
                report("OK" if version[0] == 24 else "WARN", f"Node.js {'.'.join(map(str, version))}; CI uses Node.js 24 LTS.")
        else:
            report("OK", f"{command} is available.")

    for directory in ("frontend", "integrations/node", "blockchain"):
        manifest = json.loads((ROOT / directory / "package.json").read_text(encoding="utf-8"))
        missing, mismatched = [], []
        for name, expected in (manifest.get("dependencies", {}) | manifest.get("devDependencies", {})).items():
            try:
                installed = json.loads((ROOT / directory / "node_modules" / name / "package.json").read_text(encoding="utf-8"))["version"]
            except (OSError, ValueError, KeyError):
                missing.append(name)
                continue
            if re.fullmatch(r"\d+\.\d+\.\d+", expected) and installed != expected:
                mismatched.append(name)
        if missing or mismatched:
            report("FAIL", f"{directory}: missing or mismatched packages ({', '.join(missing + mismatched)}). Run npm --prefix {directory} ci.")
        else:
            report("OK", f"{directory}: direct dependency versions match the manifest.")
    return findings


def main() -> int:
    try:
        findings = inspect_environment()
    except (OSError, ValueError, KeyError):
        print("FAIL: Cannot read project manifests. Run from a complete checkout.", file=sys.stderr)
        return 1
    for level, message in findings:
        print(f"{level}: {message}")
    failures = sum(level == "FAIL" for level, _ in findings)
    print(f"Prerequisite check: {failures} failure(s). No packages or configuration were changed.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
