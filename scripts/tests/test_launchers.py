"""Exercise hook input boundaries and development child-process exit handling."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from scripts import context
from scripts.node_runtime import NodeRuntimeMissing, find_node_runtime

ROOT = Path(__file__).resolve().parents[2]


class ContextHookTests(unittest.TestCase):
    def run_hook(self, payload):
        output = StringIO()
        with patch.object(context.sys, "argv", ["context.py", "--hook"]), patch.object(context.sys, "stdin", StringIO(payload)), redirect_stdout(output):
            context.main()
        return json.loads(output.getvalue())

    def test_non_object_and_invalid_json_produce_bounded_session_context(self):
        for payload in ("null", "[]", '"private prompt"', "42", "true", "{"):
            with self.subTest(payload=payload):
                result = self.run_hook(payload)
                self.assertEqual(result["hookSpecificOutput"]["hookEventName"], "SessionStart")
                self.assertLessEqual(len(result["hookSpecificOutput"]["additionalContext"]), 4000)
                self.assertNotIn("private prompt", json.dumps(result))

    def test_other_events_do_not_emit_session_context(self):
        self.assertEqual(self.run_hook('{"hook_event_name":"Stop"}'), {"continue": True})


class DevelopmentLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.runtime = find_node_runtime(ROOT)
        except NodeRuntimeMissing as exc:
            raise unittest.SkipTest(str(exc)) from exc

    def launcher_exit(self, code, signal):
        # Execute the real launcher in an isolated process. Replacing builtin
        # exports prevents actual services and tests sibling cleanup on exit.
        source = """
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import { pathToFileURL } from 'node:url';
const children = [];
childProcess.spawn = () => {
  const child = new EventEmitter();
  child.exitCode = null;
  child.kills = [];
  child.kill = signal => child.kills.push(signal);
  children.push(child);
  return child;
};
fs.existsSync = () => true;
syncBuiltinESMExports();
await import(pathToFileURL(process.argv[1]).href);
assert.equal(children.length, 2);
const [code, signal] = JSON.parse(process.argv[2]);
children[0].exitCode = code;
children[0].emit('exit', code, signal);
assert.deepEqual(children[1].kills, ['SIGTERM']);
"""
        return subprocess.run([str(self.runtime.node), "--input-type=module", "-e", source,
                               str(ROOT / "scripts/dev.mjs"), json.dumps([code, signal])],
                              cwd=ROOT, env=self.runtime.environment(), capture_output=True, text=True, timeout=15)

    def test_signaled_child_fails_and_stops_sibling(self):
        result = self.launcher_exit(None, "SIGTERM")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_normal_child_exit_preserves_status_and_stops_sibling(self):
        for code in (0, 7):
            with self.subTest(code=code):
                result = self.launcher_exit(code, None)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
