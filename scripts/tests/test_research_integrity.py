"""Small invented assets exercise checksum/manifest failures without touching originals."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts.verify_research import MIN_ORIGINAL_ASSETS, verify_manifest


class ResearchIntegrityTests(unittest.TestCase):
    def fixture(self, root):
        directory = root / "research"
        directory.mkdir()
        entries = []
        for index in range(MIN_ORIGINAL_ASSETS):
            name, data = f"original-{index}.txt", f"fixture {index}".encode()
            (directory / name).write_bytes(data)
            entries.append({"original_path": name, "current_path": "research/" + name,
                            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        return entries

    def test_intact_assets_pass_and_missing_bytes_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.fixture(root)
            self.assertEqual(verify_manifest(root, manifest), [])
            (root / manifest[0]["current_path"]).write_bytes(b"changed")
            self.assertTrue(any("Checksum/size mismatch" in error for error in verify_manifest(root, manifest)))

    def test_empty_or_truncated_manifests_cannot_claim_preservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.fixture(root)
            for invalid in ([], {}, manifest[:-1]):
                with self.subTest(kind=type(invalid).__name__):
                    self.assertTrue(verify_manifest(root, invalid))

    def test_duplicate_paths_or_originals_cannot_hide_an_omitted_asset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.fixture(root)
            for key in ("original_path", "current_path"):
                duplicate = [dict(entry) for entry in manifest]
                duplicate[-1][key] = duplicate[0][key]
                self.assertTrue(any("Duplicate" in error for error in verify_manifest(root, duplicate)))

    def test_schema_and_paths_outside_research_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.fixture(root)
            for value in (None, {}, {**manifest[0], "bytes": True}, {**manifest[0], "sha256": "bad"}):
                changed = [value, *manifest[1:]]
                self.assertTrue(any("Invalid research manifest" in error for error in verify_manifest(root, changed)))
            outside = root / "outside.txt"
            outside.write_text("fixture 0", encoding="utf-8")
            manifest[0]["current_path"] = "outside.txt"
            self.assertTrue(any("Missing or invalid" in error for error in verify_manifest(root, manifest)))


if __name__ == "__main__":
    unittest.main()
