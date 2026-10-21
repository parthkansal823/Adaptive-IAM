"""Verification must fail clearly when local tools cannot be started."""
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify
from scripts import node_runtime


class VerificationTests(unittest.TestCase):
    def test_missing_git_falls_back_to_full_checks(self):
        with patch.object(verify.subprocess, "check_output", side_effect=FileNotFoundError):
            self.assertIsNone(verify.changed_paths([]))
            self.assertIsNone(verify.changed_paths([["refs/heads/test", "a" * 40, "refs/heads/test", "b" * 40]]))

    def test_unlaunchable_check_fails_with_actionable_message(self):
        output = StringIO()
        with patch.object(verify.subprocess, "run", side_effect=PermissionError("private diagnostic detail")), redirect_stderr(output):
            self.assertFalse(verify.run("frontend build", ["npm", "run", "build"]))
        self.assertIn("doctor.py", output.getvalue())
        self.assertNotIn("private diagnostic detail", output.getvalue())

    def test_child_failure_cannot_be_reported_as_success(self):
        with patch.object(verify.subprocess, "run", return_value=verify.subprocess.CompletedProcess(["check"], 7)):
            self.assertFalse(verify.run("fixture check", ["check"]))

    def test_missing_node_reports_remedy_without_starting_a_check(self):
        output = StringIO()
        with patch.object(verify, "find_node_runtime", side_effect=node_runtime.NodeRuntimeMissing("Install Node.js 24 LTS; run python scripts/doctor.py.")), patch.object(verify.subprocess, "run") as child, redirect_stderr(output):
            self.assertFalse(verify.run("Node checks", ["npm.cmd", "test"]))
        child.assert_not_called()
        self.assertIn("Node.js 24 LTS", output.getvalue())
        self.assertIn("doctor.py", output.getvalue())

    def test_node_checks_use_resolved_pair_and_prepend_child_path(self):
        runtime = node_runtime.NodeRuntime(Path("fixture/node.exe"), Path("fixture/npm.cmd"), Path("fixture/npm-cli.js"))
        with patch.object(verify, "find_node_runtime", return_value=runtime), patch.object(verify.subprocess, "run", return_value=verify.subprocess.CompletedProcess([], 0)) as child:
            self.assertTrue(verify.run("Node checks", ["npm.cmd", "--prefix", "integrations/node", "test"]))
        args, kwargs = child.call_args
        self.assertEqual(args[0], [str(runtime.node), str(runtime.npm_cli), "--prefix", "integrations/node", "test"])
        path_value = next(value for key, value in kwargs["env"].items() if key.lower() == "path")
        self.assertEqual(path_value.split(os.pathsep)[0], str(runtime.node.parent))


class NodeRuntimeTests(unittest.TestCase):
    def distribution(self, root: Path, version: str, *, complete: bool = True) -> Path:
        directory = root / ".cache/runtime" / f"node-v{version}-win-x64"
        directory.mkdir(parents=True)
        (directory / "node.exe").touch()
        if complete:
            cli = directory / "node_modules/npm/bin/npm-cli.js"
            cli.parent.mkdir(parents=True)
            cli.touch()
        return directory

    def test_portable_runtime_selected_numerically_with_ci_lts_preference(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(node_runtime.shutil, "which", return_value=None), patch.object(node_runtime.sys, "platform", "win32"), patch.object(node_runtime.platform, "machine", return_value="AMD64"):
            root = Path(temporary)
            self.distribution(root, "24.9.0")
            chosen = self.distribution(root, "24.22.0")
            self.distribution(root, "25.1.0")
            self.distribution(root, "24.99.0", complete=False)
            runtime = node_runtime.find_node_runtime(root, {"PATH": ""})
        self.assertEqual(runtime.node, chosen / "node.exe")

    def test_path_installation_takes_precedence_over_cached_distribution(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(node_runtime.sys, "platform", "win32"), patch.object(node_runtime.platform, "machine", return_value="AMD64"):
            root = Path(temporary)
            self.distribution(root, "24.22.0")
            installed = root / "installed"
            installed.mkdir()
            node, npm = installed / "node.exe", installed / "npm.cmd"
            node.touch()
            npm.touch()
            with patch.object(node_runtime.shutil, "which", side_effect=[str(node), str(npm)]):
                runtime = node_runtime.find_node_runtime(root, {"PATH": str(installed)})
        self.assertEqual(runtime.node, node.resolve())
        self.assertEqual(runtime.command(["npm.cmd", "test"]), [str(npm.resolve()), "test"])

    def test_incomplete_or_unsupported_cache_is_not_a_runtime(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(node_runtime.shutil, "which", return_value=None), patch.object(node_runtime.sys, "platform", "win32"), patch.object(node_runtime.platform, "machine", return_value="AMD64"):
            root = Path(temporary)
            self.distribution(root, "24.22.0", complete=False)
            self.distribution(root, "20.1.0")
            with self.assertRaisesRegex(node_runtime.NodeRuntimeMissing, "doctor.py"):
                node_runtime.find_node_runtime(root, {"PATH": ""})

    def test_child_path_preserves_windows_key_and_does_not_mutate_parent(self):
        runtime = node_runtime.NodeRuntime(Path("fixture/node.exe"), Path("fixture/npm.cmd"))
        original = {"Path": "original-tools", "KEEP": "fixture"}
        env = runtime.environment(original)
        self.assertNotIn("PATH", env)
        self.assertTrue(env["Path"].endswith(os.pathsep + "original-tools"))
        self.assertEqual(original, {"Path": "original-tools", "KEEP": "fixture"})


if __name__ == "__main__":
    unittest.main()
