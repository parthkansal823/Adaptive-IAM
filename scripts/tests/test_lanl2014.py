"""Invented fixtures verify mechanics; they are not measurement evidence."""
import bz2
import hashlib
import io
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from scripts.evaluate_lanl2014 import (
    AuthEvent, Novelty, auth_event, bzip_lines, budget_threshold, evaluate,
    event_groups, fetch, scan_auth,
)


class Lanl2014ProtocolTests(unittest.TestCase):
    def fixture(self, directory, rows=None):
        path = Path(directory) / "fixture.bz2"
        rows = rows if rows is not None else [f"{i},U1,C{2 if i in (60, 90) else 1}" for i in range(1, 101)]
        path.write_bytes(bz2.compress(("\n".join(rows) + "\n").encode()))
        return path

    def test_schema_rejects_extra_fields_bad_ids_and_nonpositive_time(self):
        self.assertEqual(auth_event("1,U12,C23"), AuthEvent(1, "U12", "C23"))
        for text in ("0,U1,C1", "1,C1,U1", "1,U1,C1,label", "1,U-1,C1", "1,U1,?"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                auth_event(text)

    def test_truncated_archive_requires_explicit_prefix(self):
        data = bz2.compress(b"1,U1,C1\n2,U1,C2\n")[:-8]
        self.assertTrue(list(bzip_lines([data], allow_prefix=True)))
        with self.assertRaisesRegex(ValueError, "Truncated"):
            list(bzip_lines([data]))

    def test_incomplete_last_line_never_emitted_in_prefix(self):
        compressed = bz2.compress(b"1,U1,C1\n2,U1,C2")
        self.assertEqual(list(bzip_lines([compressed[:-8]], allow_prefix=True)), ["1,U1,C1"])

    def test_decompression_and_line_bounds(self):
        with self.assertRaisesRegex(ValueError, "Decompressed byte limit"):
            list(bzip_lines([bz2.compress(b"a" * 1000)], max_output_bytes=100))
        with self.assertRaisesRegex(ValueError, "Oversized"):
            list(bzip_lines([bz2.compress(b"a" * 257 + b"\n")]))

    def test_trailing_bytes_rejected(self):
        for suffix in (b"junk", bz2.compress(b"another\n")):
            with self.subTest(suffix=suffix[:4]), self.assertRaisesRegex(ValueError, "Trailing"):
                list(bzip_lines([bz2.compress(b"1,U1,C1\n") + suffix]))

    def test_bad_block_checksum_not_waived_by_prefix(self):
        data = bytearray(bz2.compress(b"1,U1,C1\n2,U1,C2\n"))
        data[10] ^= 1
        with self.assertRaises(OSError):
            list(bzip_lines([bytes(data)], allow_prefix=True))

    def test_final_timestamp_group_excluded_as_whole(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(directory, ["1,U1,C1", "2,U2,C2", "2,U3,C3"])
            self.assertEqual([second for second, _ in event_groups(path, prefix=True)], [1])
            scan = scan_auth(path, prefix=True)
            self.assertEqual(scan["source_rows"], 3)
            self.assertEqual(scan["selected_rows"], 1)
            self.assertEqual(scan["final_timestamp_rows_excluded"], 2)

    def test_nonchronological_input_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(directory, ["2,U1,C1", "1,U1,C1"])
            with self.assertRaisesRegex(ValueError, "chronological"):
                list(event_groups(path))

    def test_current_second_never_updates_other_current_scores(self):
        model = Novelty()
        events = [AuthEvent(1, "U1", "C1")] * 2
        self.assertEqual([model.score(event) for event in events], [(1., 0.), (1., 0.)])
        model.update(events)
        self.assertEqual(model.score(AuthEvent(2, "U1", "C1")), (0., 0.))
        self.assertGreater(model.score(AuthEvent(2, "U1", "C2"))[1], 0)

    def test_budget_never_splits_top_score_tie(self):
        threshold = budget_threshold(Counter({1.: 2, 0.: 98}), .01)
        self.assertIsNone(threshold["minimum_score"])
        self.assertEqual(threshold["validation_alerts"], 0)
        threshold = budget_threshold(Counter({1.: 1, .5: 99}), .01)
        self.assertEqual(threshold["minimum_score"], 1.)

    def test_time_split_preserves_ties_and_metrics_withheld(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(directory, [f"{i},U1,C1" for i in range(1, 101) for _ in range(3)])
            report = evaluate(path)
            self.assertFalse(report["synthetic"])
            self.assertFalse(report["labels"]["detection_metrics_eligible"])
            parts = report["partitions"]
            self.assertEqual([parts[name]["events"] for name in parts], [150, 75, 75])
            self.assertLess(parts["warmup"]["last_second"], parts["validation"]["first_second"])
            self.assertLess(parts["validation"]["last_second"], parts["test"]["first_second"])
            for method in report["methods"].values():
                self.assertIsNone(method["accuracy"])
                self.assertIsNone(method["false_positive_rate"])
                self.assertIsNone(method["known_redteam_tuple_recall"])
            serialized = json.dumps(report)
            self.assertNotIn('"U1"', serialized)
            self.assertNotIn('"C1"', serialized)

    def test_test_data_changes_do_not_recalibrate_thresholds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(directory)
            first = evaluate(path)
            path = self.fixture(directory, [f"{i},U1,C{99 if i >= 76 else (2 if i == 60 else 1)}" for i in range(1, 101)])
            changed = evaluate(path)
            for name in first["methods"]:
                self.assertEqual(first["methods"][name]["threshold"], changed["methods"][name]["threshold"])

    def test_wrong_provenance_hash_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(directory)
            provenance = Path(directory) / "provenance.json"
            provenance.write_text(json.dumps({"compressed_prefix_sha256": "0" * 64}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Provenance hash"):
                evaluate(path, provenance=provenance)

    def test_download_cap_and_provenance_do_not_claim_full_archive(self):
        class Response(io.BytesIO):
            status = 200
            headers = {}
        compressed = bz2.compress(b"1,U1,C1\n2,U1,C2\n3,U1,C3\n")
        response = Response(compressed)
        with tempfile.TemporaryDirectory() as directory, patch(
                "scripts.evaluate_lanl2014.urllib.request.urlopen", return_value=response):
            report = fetch(Path(directory), max_bytes=len(compressed) - 8)
            self.assertEqual(report["compressed_bytes"], len(compressed) - 8)
            self.assertFalse(report["full_bzip2_integrity_verified"])
            self.assertFalse(report["full_archive_sha256_verified"])
            self.assertEqual(report["compressed_prefix_sha256"], hashlib.sha256(compressed[:-8]).hexdigest())
            with self.assertRaisesRegex(ValueError, "already exists"):
                fetch(Path(directory))


if __name__ == "__main__":
    unittest.main()
