"""Find an installed Node/npm pair without changing global machine settings."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import re
import shutil
import sys


class NodeRuntimeMissing(RuntimeError):
    pass


@dataclass(frozen=True)
class NodeRuntime:
    node: Path
    npm: Path
    npm_cli: Path | None = None

    def command(self, command: list[str]) -> list[str]:
        if Path(command[0]).name.lower() in ("npm", "npm.cmd"):
            prefix = [str(self.node), str(self.npm_cli)] if self.npm_cli else [str(self.npm)]
            return [*prefix, *command[1:]]
        return [str(self.node), *command[1:]]

    def environment(self, source: dict[str, str] | None = None) -> dict[str, str]:
        env = dict(os.environ if source is None else source)
        key = next((key for key in env if key.lower() == "path"), "PATH")
        env[key] = str(self.node.parent) + os.pathsep + env.get(key, "")
        return env


def _pair(node: Path, npm: Path | None = None) -> NodeRuntime | None:
    if not node.is_file():
        return None
    # Official Windows archives/installers and Unix archives use these layouts.
    for cli in (node.parent / "node_modules/npm/bin/npm-cli.js", node.parent.parent / "lib/node_modules/npm/bin/npm-cli.js"):
        if cli.is_file():
            return NodeRuntime(node, npm or cli, cli)
    if npm is not None and npm.is_file():
        return NodeRuntime(node, npm)
    return None


def find_node_runtime(root: Path, env: dict[str, str] | None = None) -> NodeRuntime:
    source = os.environ if env is None else env
    search_path = next((value for key, value in source.items() if key.lower() == "path"), "")
    node = shutil.which("node.exe" if sys.platform == "win32" else "node", path=search_path)
    npm = shutil.which("npm.cmd" if sys.platform == "win32" else "npm", path=search_path)
    if node:
        installed = _pair(Path(node).resolve(), Path(npm).resolve() if npm else None)
        if installed:
            return installed

    system = {"win32": "win", "linux": "linux", "darwin": "darwin"}.get(sys.platform)
    machine = platform.machine().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    cache = root / ".cache/runtime"
    candidates: list[tuple[tuple[int, int, int], Path]] = []
    if system and arch and cache.is_dir():
        pattern = re.compile(rf"node-v(\d+)\.(\d+)\.(\d+)-{system}-{arch}")
        for directory in cache.iterdir():
            match = pattern.fullmatch(directory.name)
            if not match or not directory.is_dir():
                continue
            version = tuple(map(int, match.groups()))
            if version >= (22, 12, 0):
                candidates.append((version, directory))
    # Prefer the CI LTS major, then the newest compatible distribution.
    for version, directory in sorted(candidates, key=lambda item: (item[0][0] == 24, item[0]), reverse=True):
        executable = directory / "node.exe" if sys.platform == "win32" else directory / "bin/node"
        portable = _pair(executable)
        if portable:
            return portable
    raise NodeRuntimeMissing(
        "Node.js/npm could not be found together. Install Node.js 24 LTS and reopen the terminal or editor, "
        "or extract a trusted official Node distribution under .cache/runtime/node-v<VERSION>-<PLATFORM>-<ARCH>. "
        "Run python scripts/doctor.py for prerequisite diagnostics."
    )
