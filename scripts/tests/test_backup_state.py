"""Offline backups preserve identity keys and reject unsafe or corrupt archives."""
from contextlib import closing, redirect_stderr
import ctypes
import errno
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import warnings
import zipfile

from scripts import backup_state as backup
from backend.app.identity import IdentitySecurity
from backend.app.oauth import OAuthProvider
from backend.app.store import Store


class BackupStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template_temp = tempfile.TemporaryDirectory()
        cls.template = Path(cls.template_temp.name)
        # Never inspect or mutate workspace credentials/databases.
        with patch.dict(os.environ, {"IAM_FACTOR_KEY_FILE": "", "IAM_DEMO_MODE": "true"}):
            # Empty override is intentionally removed: runtime interprets it as a path.
            del os.environ["IAM_FACTOR_KEY_FILE"]
            store = Store(cls.template / "iam.sqlite3")
            cls.provider = OAuthProvider(store, cls.template)
            identity = IdentitySecurity(store, cls.template)
            cls.encrypted = identity.context.cipher.encrypt(b"SYNTHETIC-TEST-FACTOR").decode()
            with store.connection(write=True) as db:
                db.execute("INSERT INTO totp_factors VALUES (?,?,?,?)", ("aisha", cls.encrypted, -1, "2026-10-20T00:00:00+00:00"))
                db.execute("PRAGMA user_version=17")
                db.execute("PRAGMA application_id=31337")

    @classmethod
    def tearDownClass(cls):
        cls.template_temp.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        shutil.copytree(self.template, self.source)
        self.archive = self.root / "state.iam-backup.zip"
        self.destination = self.root / "restored"
        self.environment = patch.dict(os.environ, {"IAM_FACTOR_KEY_FILE": ""})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def create(self, **kwargs):
        backup.create_backup(self.source, self.archive, offline=True, **kwargs)

    def restore(self, **kwargs):
        backup.restore_backup(self.archive, self.destination, offline=True, **kwargs)

    def rewrite(self, transform):
        with zipfile.ZipFile(self.archive) as zipped:
            contents = {item.filename: zipped.read(item) for item in zipped.infolist()}
        transform(contents)
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            for name, content in contents.items():
                zipped.writestr(name, content)

    def edit_file(self, name, content):
        def transform(contents):
            contents[name] = content
            manifest = json.loads(contents["manifest.json"])
            manifest["files"][name] = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            contents["manifest.json"] = json.dumps(manifest).encode()
        self.rewrite(transform)

    def assert_no_restore_artifacts(self):
        self.assertFalse(self.destination.exists())
        self.assertEqual([], list(self.root.glob(".iam-restore-*")))

    def assert_windows_private_acl(self, paths):
        # Read metadata only, including while an empty output is still open.
        script = r"""
$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$items = foreach ($path in (ConvertFrom-Json -InputObject $env:IAM_BACKUP_ACL_TEST_PATHS)) {
    $acl = if ([System.IO.Directory]::Exists($path)) {
        [System.IO.Directory]::GetAccessControl($path)
    } else { [System.IO.File]::GetAccessControl($path) }
    $rules = foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        @{ Sid = $rule.IdentityReference.Value; Kind = $rule.AccessControlType.ToString();
           Inherited = $rule.IsInherited;
           FullControl = ($rule.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl) }
    }
    @{ Protected = $acl.AreAccessRulesProtected;
       Owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; Rules = @($rules) }
}
@{ Identity = $identity; Items = @($items) } | ConvertTo-Json -Compress -Depth 6
"""
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env=dict(os.environ, IAM_BACKUP_ACL_TEST_PATHS=json.dumps([str(path) for path in paths])),
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        metadata = json.loads(result.stdout)
        self.assertEqual(len(paths), len(metadata["Items"]))
        for item in metadata["Items"]:
            self.assertTrue(item["Protected"])
            self.assertEqual(metadata["Identity"], item["Owner"])
            self.assertEqual({metadata["Identity"], "S-1-5-18"}, {rule["Sid"] for rule in item["Rules"]})
            self.assertTrue(all(rule["Kind"] == "Allow" and rule["FullControl"] and not rule["Inherited"]
                                for rule in item["Rules"]))

    def test_round_trip_preserves_oidc_signing_identity_factors_and_sqlite_metadata(self):
        (self.source / "deployment.json").write_text('{"chain_id":31337,"contract_address":"synthetic-test-address"}')
        self.create()
        self.restore()
        provider = OAuthProvider(Store(self.destination / "iam.sqlite3"), self.destination)
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        signature = self.provider.key.sign(b"oidc-signing-continuity", padding.PKCS1v15(), hashes.SHA256())
        provider.key.public_key().verify(signature, b"oidc-signing-continuity", padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(self.provider.kid, provider.kid)
        cipher = Fernet((self.destination / "factor-encryption.key").read_bytes())
        with closing(sqlite3.connect(self.destination / "iam.sqlite3")) as db:
            encrypted = db.execute("SELECT encrypted_secret FROM totp_factors WHERE user_id='aisha'").fetchone()[0]
            self.assertEqual(b"SYNTHETIC-TEST-FACTOR", cipher.decrypt(encrypted.encode()))
            self.assertEqual(17, db.execute("PRAGMA user_version").fetchone()[0])
            self.assertEqual(31337, db.execute("PRAGMA application_id").fetchone()[0])
            self.assertEqual([("ok",)], db.execute("PRAGMA integrity_check").fetchall())
        self.assertEqual((self.source / "deployment.json").read_bytes(), (self.destination / "deployment.json").read_bytes())
        if os.name != "nt":
            self.assertEqual(0o600, stat.S_IMODE(self.archive.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(self.destination.stat().st_mode))
            for path in self.destination.iterdir():
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_sqlite_backup_includes_committed_wal_and_leaves_source_journal_mode(self):
        with closing(sqlite3.connect(self.source / "iam.sqlite3")) as db:
            self.assertEqual("wal", db.execute("PRAGMA journal_mode=WAL").fetchone()[0])
            db.execute("PRAGMA wal_autocheckpoint=0")
            db.execute("CREATE TABLE backup_wal_marker(value TEXT)")
            db.execute("INSERT INTO backup_wal_marker VALUES ('committed')")
            db.commit()
            self.assertTrue(Path(str(self.source / "iam.sqlite3") + "-wal").exists())
            self.create()
            self.assertEqual("wal", db.execute("PRAGMA journal_mode").fetchone()[0])
        self.restore()
        with closing(sqlite3.connect(self.destination / "iam.sqlite3")) as restored:
            self.assertEqual("committed", restored.execute("SELECT value FROM backup_wal_marker").fetchone()[0])
        with zipfile.ZipFile(self.archive) as zipped:
            self.assertFalse(any(name.endswith(("-wal", "-shm")) for name in zipped.namelist()))

    def test_offline_acknowledgement_is_required_before_files_are_created(self):
        with self.assertRaises(backup.BackupError):
            backup.create_backup(self.source, self.archive)
        self.assertFalse(self.archive.exists())
        self.create()
        with self.assertRaises(backup.BackupError):
            backup.restore_backup(self.archive, self.destination)
        self.assert_no_restore_artifacts()

    def test_existing_outputs_and_even_empty_restore_destinations_are_preserved(self):
        self.create()
        original = self.archive.read_bytes()
        with self.assertRaises(backup.BackupError):
            self.create()
        self.assertEqual(original, self.archive.read_bytes())
        self.destination.mkdir()
        with self.assertRaises(backup.BackupError):
            self.restore()
        marker = self.destination / "keep.txt"
        marker.write_text("keep")
        with self.assertRaises(backup.BackupError):
            self.restore()
        self.assertEqual("keep", marker.read_text())

    def test_destination_created_at_atomic_publication_is_preserved_even_when_empty(self):
        self.create()
        publish = backup._publish_directory
        claimed = []
        def race(stage, target):
            target.mkdir()
            claimed.append(target.stat().st_ino)
            return publish(stage, target)
        with patch.object(backup, "_publish_directory", side_effect=race):
            with self.assertRaises(FileExistsError):
                self.restore()
        self.assertEqual(claimed[0], self.destination.stat().st_ino)
        self.assertEqual([], list(self.destination.iterdir()))
        self.assertEqual([], list(self.root.glob(".iam-restore-*")))

    def test_concurrent_backup_publication_preserves_the_existing_archive(self):
        publish = backup.os.link
        def race(payload, target):
            target.write_bytes(b"concurrently-created-output")
            return publish(payload, target)
        with patch.object(backup.os, "link", side_effect=race):
            with self.assertRaises(FileExistsError):
                self.create()
        self.assertEqual(b"concurrently-created-output", self.archive.read_bytes())
        self.assertEqual([], list(self.root.glob(".iam-backup-*")))

    def test_successful_install_does_not_delete_a_recreated_temporary_path(self):
        self.create()
        publish = backup._publish_directory
        recreated = []
        def race(stage, target):
            publish(stage, target)
            stage.mkdir()
            marker = stage / "keep.txt"
            marker.write_text("a different directory now owns this pathname")
            recreated.append(marker)
        with patch.object(backup, "_publish_directory", side_effect=race):
            self.restore()
        self.assertTrue((self.destination / "iam.sqlite3").is_file())
        self.assertEqual("a different directory now owns this pathname", recreated[0].read_text())

    @unittest.skipUnless(os.name == "nt", "Windows DACL verification")
    def test_windows_dacls_protect_stages_and_files_before_first_secret_byte(self):
        private_file = backup._private_file
        checked = []
        def inspect_empty_output(path):
            stream = private_file(path)
            try:
                self.assertEqual(0, path.stat().st_size)
                self.assert_windows_private_acl([path, path.parent])
            except BaseException:
                stream.close()
                raise
            checked.append(path.name)
            return stream
        with patch.object(backup, "_private_file", side_effect=inspect_empty_output):
            self.create()
            self.restore()
        self.assertGreaterEqual(len(checked), 7)
        self.assert_windows_private_acl([self.archive, self.destination, *self.destination.iterdir()])

    @unittest.skipUnless(os.name == "nt", "Windows filesystem ACL guard")
    def test_windows_filesystems_without_acl_support_fail_before_creation(self):
        kernel, security = Mock(), Mock()
        kernel.GetVolumePathNameW.return_value = 1
        kernel.GetVolumeInformationW.return_value = 1  # Leaves FILE_PERSISTENT_ACLS unset.
        with patch.object(backup.ctypes, "WinDLL", side_effect=[kernel, security]):
            with self.assertRaisesRegex(backup.BackupError, "persistent access-control"):
                backup._windows_create_private(self.destination, directory=True)
        kernel.CreateDirectoryW.assert_not_called()
        kernel.CreateFileW.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_unsupported_platform_fails_before_staging_or_publication(self):
        simulated_os = SimpleNamespace(name="posix")
        with patch.object(backup, "os", simulated_os), patch.object(backup.sys, "platform", "darwin"):
            with self.assertRaisesRegex(backup.BackupError, "Windows and Linux"):
                self.create()
        self.assertFalse(self.archive.exists())
        self.assertEqual([], list(self.root.glob(".iam-backup-*")))

    def test_linux_publication_uses_kernel_noreplace_flag(self):
        rename = Mock(return_value=0)
        libc = SimpleNamespace(renameat2=rename)
        simulated_os = SimpleNamespace(name="posix", fsencode=os.fsencode, strerror=os.strerror)
        with patch.object(backup, "os", simulated_os), patch.object(backup.sys, "platform", "linux"), \
                patch.object(backup.ctypes, "CDLL", return_value=libc):
            backup._publish_directory(self.source, self.destination)
        rename.assert_called_once_with(-100, os.fsencode(self.source), -100, os.fsencode(self.destination), 1)

    def test_linux_missing_renameat2_fails_without_fallback_or_mutation(self):
        simulated_os = SimpleNamespace(name="posix")
        with patch.object(backup, "os", simulated_os), patch.object(backup.sys, "platform", "linux"), \
                patch.object(backup.ctypes, "CDLL", return_value=SimpleNamespace()):
            with self.assertRaisesRegex(backup.BackupError, "renameat2"):
                backup._publish_directory(self.source, self.destination)
        self.assertTrue(self.source.is_dir())
        self.assertFalse(self.destination.exists())

    def test_linux_unsupported_kernel_or_filesystem_fails_without_unsafe_fallback(self):
        simulated_os = SimpleNamespace(name="posix", fsencode=os.fsencode, strerror=os.strerror)
        for error in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.EEXIST):
            with self.subTest(error=error):
                def fail(*args):
                    ctypes.set_errno(error)
                    return -1
                libc = SimpleNamespace(renameat2=Mock(side_effect=fail))
                expected = FileExistsError if error == errno.EEXIST else backup.BackupError
                with patch.object(backup, "os", simulated_os), patch.object(backup.sys, "platform", "linux"), \
                        patch.object(backup.ctypes, "CDLL", return_value=libc):
                    with self.assertRaises(expected):
                        backup._publish_directory(self.source, self.destination)
                self.assertTrue(self.source.is_dir())
                self.assertFalse(self.destination.exists())

    def test_unrecognized_archive_suffix_is_rejected_before_writing_credentials(self):
        with self.assertRaisesRegex(backup.BackupError, "iam-backup.zip"):
            backup.create_backup(self.source, self.root / "accidental-source-file.zip", offline=True)
        self.assertEqual([self.source], list(self.root.iterdir()))

    def test_external_factor_override_is_included_under_canonical_name(self):
        external = self.root / "separate-factor.key"
        (self.source / "factor-encryption.key").rename(external)
        with patch.dict(os.environ, {"IAM_FACTOR_KEY_FILE": str(external)}):
            self.create()
        self.restore()
        self.assertEqual(external.read_bytes(), (self.destination / "factor-encryption.key").read_bytes())

    def test_missing_or_wrong_factor_key_fails_without_publishing(self):
        from cryptography.fernet import Fernet
        (self.source / "factor-encryption.key").unlink()
        with self.assertRaises(backup.BackupError):
            self.create()
        (self.source / "factor-encryption.key").write_bytes(Fernet.generate_key())
        with self.assertRaises(backup.BackupError):
            self.create()
        self.assertFalse(self.archive.exists())
        self.assertEqual([], list(self.root.glob(".iam-backup-*")))

    def test_foreign_key_violation_in_source_prevents_backup(self):
        with closing(sqlite3.connect(self.source / "iam.sqlite3")) as db:
            db.execute("UPDATE resources SET owner_id='missing-user'")
            db.commit()
        with self.assertRaisesRegex(backup.BackupError, "foreign-key"):
            self.create()
        self.assertFalse(self.archive.exists())

    def test_checksum_corruption_is_rejected_before_installation(self):
        self.create()
        self.rewrite(lambda contents: contents.__setitem__("factor-encryption.key", b"bad"))
        with self.assertRaises(backup.BackupError):
            self.restore()
        self.assert_no_restore_artifacts()

    def test_corrupt_sqlite_even_with_matching_checksum_is_rejected(self):
        self.create()
        self.edit_file("iam.sqlite3", b"not a SQLite database")
        with self.assertRaises(sqlite3.DatabaseError):
            self.restore()
        self.assert_no_restore_artifacts()

    def test_invalid_signing_key_even_with_matching_checksum_is_rejected(self):
        self.create()
        self.edit_file("oidc-signing-key.pem", b"invalid test key")
        with self.assertRaises(backup.BackupError):
            self.restore()
        self.assert_no_restore_artifacts()

    def test_sqlite_metadata_mismatch_is_rejected(self):
        self.create()
        def transform(contents):
            manifest = json.loads(contents["manifest.json"])
            manifest["sqlite"]["user_version"] += 1
            contents["manifest.json"] = json.dumps(manifest).encode()
        self.rewrite(transform)
        with self.assertRaisesRegex(backup.BackupError, "metadata"):
            self.restore()
        self.assert_no_restore_artifacts()

    def test_traversal_absolute_windows_and_unknown_members_are_rejected(self):
        for member in ("../escape", "/absolute", "C:/escape", "..\\escape", "extra.txt", "nested/iam.sqlite3"):
            with self.subTest(member=member):
                self.archive.unlink(missing_ok=True)
                self.create()
                with zipfile.ZipFile(self.archive, "a") as zipped:
                    zipped.writestr(member, "test")
                with self.assertRaises(backup.BackupError):
                    self.restore()
                self.assert_no_restore_artifacts()

    def test_duplicate_archive_members_are_rejected(self):
        self.create()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "a") as zipped:
                zipped.writestr("manifest.json", "{}")
        with self.assertRaisesRegex(backup.BackupError, "duplicate"):
            self.restore()
        self.assert_no_restore_artifacts()

    def test_duplicate_manifest_fields_are_rejected(self):
        self.create()
        self.rewrite(lambda contents: contents.__setitem__("manifest.json", b'{"version":1,"version":1}'))
        with self.assertRaisesRegex(backup.BackupError, "Duplicate JSON"):
            self.restore()
        self.assert_no_restore_artifacts()

    def test_archive_symlink_entries_are_rejected(self):
        self.create()
        with zipfile.ZipFile(self.archive) as zipped:
            members = [(entry.filename, zipped.read(entry)) for entry in zipped.infolist()]
        with zipfile.ZipFile(self.archive, "w") as zipped:
            for name, payload in members:
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = ((stat.S_IFLNK if name == "iam.sqlite3" else stat.S_IFREG) | 0o600) << 16
                zipped.writestr(entry, payload)
        with self.assertRaisesRegex(backup.BackupError, "type"):
            self.restore()
        self.assert_no_restore_artifacts()

    def test_oversized_entry_is_rejected_before_extraction(self):
        self.create()
        with patch.dict(backup.LIMITS, {"iam.sqlite3": 1}):
            with self.assertRaisesRegex(backup.BackupError, "size"):
                self.restore()
        self.assert_no_restore_artifacts()

    def test_source_key_and_destination_parent_symlinks_are_rejected(self):
        key = self.source / "oidc-signing-key.pem"
        other = self.root / "actual.pem"
        key.rename(other)
        try:
            key.symlink_to(other)
        except (OSError, NotImplementedError):
            self.skipTest("Host does not permit test symlink creation")
        with self.assertRaisesRegex(backup.BackupError, "links"):
            self.create()
        key.unlink()
        other.rename(key)
        self.create()
        linked = self.root / "linked"
        linked.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(backup.BackupError, "links"):
            backup.restore_backup(self.archive, linked / "nested", offline=True)

    def test_windows_reparse_attribute_is_rejected_without_privileged_link_creation(self):
        info = type("ReparsePoint", (), {"st_mode": stat.S_IFDIR, "st_file_attributes": 0x400})()
        with patch.object(Path, "lstat", return_value=info):
            with self.assertRaisesRegex(backup.BackupError, "reparse"):
                backup.create_backup(self.source, self.archive, offline=True)
        self.assertFalse(self.archive.exists())

    def test_failed_atomic_install_cleans_only_its_staging_directory(self):
        self.create()
        with patch.object(backup, "_publish_directory", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                self.restore()
        self.assert_no_restore_artifacts()
        self.assertTrue(self.archive.is_file())
        self.assertTrue((self.source / "iam.sqlite3").is_file())

    def test_cli_sanitizes_crypto_and_database_errors(self):
        self.create()
        self.edit_file("oidc-signing-key.pem", b"secret-bearing-invalid-value")
        output = StringIO()
        with redirect_stderr(output):
            code = backup.main(["restore", "--offline", "--archive", str(self.archive), "--destination", str(self.destination)])
        self.assertEqual(1, code)
        self.assertNotIn("secret-bearing-invalid-value", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self.assert_no_restore_artifacts()


if __name__ == "__main__":
    unittest.main()
