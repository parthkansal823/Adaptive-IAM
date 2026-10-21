"""Verification must fail clearly when local tools cannot be started."""
from contextlib import redirect_stderr
from io import StringIO
import unittest
from unittest.mock import patch

from scripts import verify


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


if __name__ == "__main__":
    unittest.main()
