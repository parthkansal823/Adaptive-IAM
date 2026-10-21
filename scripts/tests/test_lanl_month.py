"""Invented records check acquisition mechanics, not empirical performance."""
import bz2
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.fetch_lanl_month import FILENAME, fetch, scan_prefix


class Response(io.BytesIO):
    status = 200
    headers = {}


class LanlMonthAcquisitionTests(unittest.TestCase):
    def fixture(self, directory, rows):
        path = Path(directory) / "fixture.bz2.prefix"
        path.write_bytes(bz2.compress(("\n".join(rows) + "\n").encode()))
        return path

    def test_scan_uses_release_offsets_and_drops_entire_last_group(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(directory, ["2592001,U1,C1", "2592002,U1,C2", "2592002,U2,C3"])
            scan = scan_prefix(path)
            self.assertEqual(scan["source_rows"], 3)
            self.assertEqual(scan["selected_rows"], 1)
            self.assertEqual(scan["selected_last_second"], 2592001)
            self.assertEqual(scan["source_last_second"], 2592002)
            self.assertEqual(scan["final_timestamp_rows_excluded"], 2)

    def test_rejects_invalid_or_nonchronological_source(self):
        for rows in (["2,U1,C1", "1,U1,C1"], ["1,U1,C1,0"], ["0,U1,C1"]):
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                scan_prefix(self.fixture(directory, rows))

    def test_download_prefix_provenance_and_no_identifiers(self):
        compressed = bz2.compress(b"2592001,U1,C1\n2592002,U1,C2\n2592003,U1,C3\n")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "raw"
            report_path = Path(directory) / "aggregate.json"
            with patch("scripts.fetch_lanl_month.urllib.request.urlopen", return_value=Response(compressed)) as opening:
                report = fetch(target, report_path, max_bytes=len(compressed) - 8)
            self.assertTrue(opening.call_args.args[0].full_url.endswith(FILENAME))
            self.assertFalse(report["labels"]["detection_metrics_eligible"])
            provenance = report["source"]["acquisition"]
            self.assertEqual(provenance["compressed_prefix_sha256"], hashlib.sha256(compressed[:-8]).hexdigest())
            self.assertEqual(provenance["compressed_bytes"], len(compressed) - 8)
            self.assertEqual(provenance["stop_reason"], "compressed_byte_cap")
            self.assertFalse(provenance["full_archive_sha256_verified"])
            self.assertFalse(provenance["full_bzip2_integrity_verified"])
            self.assertEqual(json.loads(report_path.read_text())["scan"], report["scan"])
            self.assertNotIn('"U1"', report_path.read_text())
            self.assertNotIn('"C1"', report_path.read_text())
            with patch("scripts.fetch_lanl_month.urllib.request.urlopen") as opening:
                with self.assertRaisesRegex(ValueError, "already exists"):
                    fetch(target, report_path)
                opening.assert_not_called()

    def test_existing_report_or_staging_rejected_before_network(self):
        for existing_name in ("aggregate.json", "aggregate.json.tmp"):
            with tempfile.TemporaryDirectory() as directory:
                report_path = Path(directory) / "aggregate.json"
                (Path(directory) / existing_name).write_text("preserve")
                with patch("scripts.fetch_lanl_month.urllib.request.urlopen") as opening:
                    with self.assertRaisesRegex(ValueError, "already exists"):
                        fetch(Path(directory) / "raw", report_path)
                    opening.assert_not_called()
                self.assertEqual((Path(directory) / existing_name).read_text(), "preserve")

    def test_output_preflight_fails_before_network(self):
        original = Path.open
        def fail_report_temporary(path, *args, **kwargs):
            if path.name == "aggregate.json.tmp":
                raise PermissionError("fixture output unavailable")
            return original(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(Path, "open", fail_report_temporary), patch("scripts.fetch_lanl_month.urllib.request.urlopen") as opening:
                with self.assertRaises(PermissionError):
                    fetch(Path(directory) / "raw", Path(directory) / "aggregate.json")
                opening.assert_not_called()
            self.assertEqual(list((Path(directory) / "raw").iterdir()), [])

    def test_failed_transfer_removes_only_owned_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "raw"
            raw.mkdir()
            preserved = raw / "unrelated.txt"
            preserved.write_text("keep")
            with patch("scripts.fetch_lanl_month.urllib.request.urlopen", side_effect=OSError("fixture network failure")):
                with self.assertRaises(OSError):
                    fetch(raw, Path(directory) / "aggregate.json")
            self.assertEqual(list(raw.iterdir()), [preserved])
            self.assertFalse((Path(directory) / "aggregate.json.tmp").exists())

    def test_invalid_bounds_and_nonfinite_deadline_rejected_before_network(self):
        for kwargs in ({"max_bytes": 0}, {"max_bytes": 16 * 1024**2 + 1}, {"max_bytes": True},
                       {"max_seconds": float("nan")}, {"max_seconds": float("inf")},
                       {"max_seconds": 301}, {"max_seconds": 0}):
            with tempfile.TemporaryDirectory() as directory:
                with patch("scripts.fetch_lanl_month.urllib.request.urlopen") as opening:
                    with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                        fetch(Path(directory) / "raw", Path(directory) / "aggregate.json", **kwargs)
                    opening.assert_not_called()


if __name__ == "__main__":
    unittest.main()
