"""Reject credential archives by filename without opening their secret contents."""
import unittest
from scripts.check import check_file


class BackupGuardTests(unittest.TestCase):
    def test_credential_archives_are_rejected_even_with_no_text_content(self):
        for name in ("local.iam-backup.zip", "nested/STATE.IAM-BACKUP.ZIP"):
            self.assertTrue(any("credential backups" in error for error in check_file(name, b"")))

    def test_private_staging_files_are_rejected_when_force_staged(self):
        for name in (".iam-backup-private/manifest.json", "nested/.iam-restore-private/metadata.json"):
            self.assertTrue(any("staging state" in error for error in check_file(name, b"{}")))

    def test_ordinary_evidence_json_remains_allowed(self):
        self.assertEqual(check_file("experiments/study.json", b'{"synthetic":true}'), [])
