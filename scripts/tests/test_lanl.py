"""Small invented fixtures verify protocol mechanics, never research outcomes."""
import gzip
import hashlib
import io
import json
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from scripts.evaluate_lanl import (
    Event, Novelty, auth_event, bounded_bytes, budget_threshold, evaluate,
    event_groups, fetch, gzip_lines, read_redteam, scan_auth,
)


def row(second, user="U1@DOM1", source="C1", destination="C2", outcome="Success", orientation="LogOn"):
    return f"{second},{user},{user},{source},{destination},NTLM,Network,{orientation},{outcome}"


class LanlProtocolTests(unittest.TestCase):
    def fixture(self, directory, rows=None, labels=None):
        root = Path(directory)
        auth, redteam = root / "auth.txt.gz", root / "redteam.txt.gz"
        rows = rows if rows is not None else [row(i, source="C3" if i in (60, 90) else "C1") for i in range(1, 101)]
        auth.write_bytes(gzip.compress(("\n".join(rows) + "\n").encode(), mtime=0))
        redteam.write_bytes(gzip.compress(("\n".join(labels or []) + "\n" if labels else "").encode(), mtime=0))
        return auth, redteam

    def test_current_outcome_never_changes_own_observables_or_score(self):
        _, success = auth_event(row(10, outcome="Success"))
        _, failure = auth_event(row(10, outcome="Fail"))
        self.assertEqual(success, failure)
        self.assertEqual(Novelty().score(success), Novelty().score(failure))

    def test_empty_and_question_mark_computers_are_excluded(self):
        for source, destination in (("", "C2"), ("C1", ""), ("?", "C2"), ("C1", "?")):
            with self.subTest(source=source, destination=destination):
                self.assertIsNone(auth_event(row(10, source=source, destination=destination))[1])
        self.assertIsNotNone(auth_event(row(10))[1])

    def test_past_only_history_and_future_cannot_change_previous_score(self):
        model = Novelty()
        event = Event(1, "U1@DOM1", "C1", "C2")
        self.assertEqual(model.score(event), (1., 1., 0.))
        model.update([event])
        self.assertEqual(model.score(Event(2, event.user, event.source, event.destination)), (0., 0., 0.))
        self.assertEqual(model.score(Event(2, event.user, "C3", "C4"))[:2], (1., 1.))

    def test_equal_seconds_are_scored_from_same_prior_history(self):
        with tempfile.TemporaryDirectory() as directory:
            auth, _ = self.fixture(directory, [row(1), row(1), row(2)])
            groups = list(event_groups(auth))
            self.assertEqual([len(events) for _, events in groups], [2, 1])
            model = Novelty()
            self.assertEqual([model.score(event)[0] for event in groups[0][1]], [1., 1.])
            model.update(groups[0][1])
            self.assertEqual(model.score(groups[1][1][0])[0], 0.)

    def test_globally_nonchronological_source_rejected_even_unselected_row(self):
        with tempfile.TemporaryDirectory() as directory:
            auth, _ = self.fixture(directory, [row(2), row(1, user="C1$@DOM1")])
            with self.assertRaisesRegex(ValueError, "chronological"):
                list(event_groups(auth))

    def test_prefix_drops_entire_final_second(self):
        with tempfile.TemporaryDirectory() as directory:
            auth, _ = self.fixture(directory, [row(1), row(2), row(2)])
            self.assertEqual([second for second, _ in event_groups(auth, prefix=True)], [1])
            self.assertEqual([second for second, _ in event_groups(auth)], [1, 2])

    def test_prefix_scan_selection_matches_evaluated_complete_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [row(i) for i in range(1, 101)] + [row(100), row(100, user="C1$@DOM1")]
            auth, labels = self.fixture(directory, rows)
            scan = scan_auth(auth, prefix=True)
            self.assertEqual(scan["source_rows"], 102)
            self.assertEqual(scan["selected_rows"], 99)
            self.assertEqual(scan["selected_last_second"], 99)
            self.assertEqual(scan["final_timestamp_rows_excluded"], 3)
            self.assertEqual(scan["final_timestamp_selected_rows_excluded"], 2)
            report = evaluate(auth, labels, prefix=True)
            self.assertEqual(sum(part["events"] for part in report["partitions"].values()), scan["selected_rows"])

    def test_prefix_with_only_one_timestamp_has_no_selected_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            auth, _ = self.fixture(directory, [row(1), row(1)])
            scan = scan_auth(auth, prefix=True)
            self.assertEqual(scan["selected_rows"], 0)
            self.assertIsNone(scan["selected_first_second"])
            self.assertIsNone(scan["selected_last_second"])

    def test_sparse_labels_match_exact_four_tuple_and_duplicates_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            auth, labels = self.fixture(directory, labels=["90,U1@DOM1,C3,C2", "90,U1@OTHER,C3,C2"])
            report = evaluate(auth, labels, budget=.1)
            self.assertEqual(report["labels"]["unique_redteam_tuples_in_reference"], 2)
            self.assertEqual(report["labels"]["matched_unique_tuples_across_partitions"], 1)
            self.assertTrue(report["labels"]["detection_metrics_eligible"])
            self.assertEqual(report["partitions"]["test"]["known_redteam_unique_tuples"], 1)
            self.assertEqual(report["partitions"]["test"]["unlabeled_events"], 24)
            self.assertEqual(report["schema_version"], "lanl-study-v1")

    def test_no_test_positive_withholds_detection_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            auth, labels = self.fixture(directory, labels=["5,U1@DOM1,C1,C2"])
            report = evaluate(auth, labels)
            self.assertFalse(report["labels"]["detection_metrics_eligible"])
            for method in report["methods"].values():
                self.assertIsNone(method["known_redteam_tuple_recall"])
                self.assertIsNone(method["known_redteam_recalled_unique_tuples"])
                self.assertNotIn("precision", method)
                self.assertNotIn("accuracy", method)

    def test_duplicate_auth_rows_count_once_for_reference_tuple_recall(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [row(i, source="C3" if i == 90 else "C1") for i in range(1, 101)]
            rows.insert(90, row(90, source="C3", outcome="Fail"))
            auth, labels = self.fixture(directory, rows, ["90,U1@DOM1,C3,C2"])
            report = evaluate(auth, labels, budget=.1)
            self.assertEqual(report["partitions"]["test"]["matched_auth_rows"], 2)
            self.assertEqual(report["partitions"]["test"]["known_redteam_unique_tuples"], 1)
            self.assertEqual(report["partitions"]["test"]["unlabeled_events"], 24)

    def test_label_changes_cannot_change_scores_thresholds_or_alert_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            auth, labels = self.fixture(directory)
            a = evaluate(auth, labels, budget=.1)
            labels.write_bytes(gzip.compress(b"90,U1@DOM1,C3,C2\n", mtime=0))
            b = evaluate(auth, labels, budget=.1)
            for name in a["methods"]:
                self.assertEqual(a["methods"][name]["threshold"], b["methods"][name]["threshold"])
                self.assertEqual(a["methods"][name]["test_alerts"], b["methods"][name]["test_alerts"])

    def test_time_windows_do_not_split_ties(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [row(i) for i in range(1, 101) for _ in range(3)]
            auth, labels = self.fixture(directory, rows)
            report = evaluate(auth, labels)
            parts = report["partitions"]
            self.assertEqual(parts["warmup"]["events"], 150)
            self.assertEqual(parts["validation"]["events"], 75)
            self.assertEqual(parts["test"]["events"], 75)
            self.assertLess(parts["warmup"]["last_second"], parts["validation"]["first_second"])
            self.assertLess(parts["validation"]["last_second"], parts["test"]["first_second"])

    def test_budget_never_splits_top_score_tie(self):
        from collections import Counter
        no_alerts = budget_threshold(Counter({1.: 10, 0.: 90}), .01)
        self.assertIsNone(no_alerts["minimum_score"])
        self.assertEqual(no_alerts["validation_alerts"], 0)
        threshold = budget_threshold(Counter({1.: 1, .5: 5, 0.: 94}), .01)
        self.assertEqual(threshold["minimum_score"], 1.)
        self.assertEqual(threshold["validation_alerts"], 1)

    def test_bounded_reads_never_cross_cap(self):
        response = io.BytesIO(b"a" * 100)
        result = b"".join(bounded_bytes(response, 13, time.monotonic() + 1))
        self.assertEqual(result, b"a" * 13)
        self.assertEqual(response.tell(), 13)

    def test_truncated_gzip_requires_explicit_prefix_mode(self):
        compressed = gzip.compress(b"one\ntwo\n", mtime=0)
        self.assertEqual(list(gzip_lines([compressed[:-8]], allow_prefix=True)), ["one", "two"])
        with self.assertRaisesRegex(ValueError, "Truncated"):
            list(gzip_lines([compressed[:-8]]))

    def test_incomplete_text_line_is_not_yielded(self):
        compressed = gzip.compress(b"complete\nincomplete", mtime=0)
        self.assertEqual(list(gzip_lines([compressed[:-8]], allow_prefix=True)), ["complete"])

    def test_bad_gzip_crc_is_rejected_even_in_prefix_mode(self):
        compressed = bytearray(gzip.compress(b"record\n", mtime=0))
        compressed[-8] ^= 1
        with self.assertRaises(zlib.error):
            list(gzip_lines([bytes(compressed)], allow_prefix=True))

    def test_decompression_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "Decompressed byte limit"):
            list(gzip_lines([gzip.compress(b"a\n" * 100)], max_output_bytes=10))

    def test_concatenated_members_and_trailing_bytes_rejected(self):
        first, second = gzip.compress(b"first\n"), gzip.compress(b"second\n")
        for chunks in ([first + second], [first, second], [first + b"garbage"], [first, b"garbage"]):
            with self.subTest(chunk_count=len(chunks)):
                with self.assertRaisesRegex(ValueError, "Concatenated gzip members or trailing bytes"):
                    list(gzip_lines(chunks))

    def test_known_reference_not_inferred_from_user_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            _, labels = self.fixture(directory, labels=["90,U1@DOM1,C3,C2"])
            known = read_redteam(labels)
            self.assertIn((90, "U1@DOM1", "C3", "C2"), known)
            for key in [(91, "U1@DOM1", "C3", "C2"), (90, "U1@OTHER", "C3", "C2"), (90, "U1@DOM1", "C4", "C2")]:
                self.assertNotIn(key, known)

    def test_fetch_records_original_prefix_hash_and_explicit_integrity_limit(self):
        class Response(io.BytesIO):
            status = 200
            @property
            def headers(self):
                return {"Content-Length": str(len(self.getbuffer()))}
        auth = gzip.compress(("\n".join(row(i) for i in range(1, 501)) + "\n").encode(), mtime=0)
        redteam = gzip.compress(b"90,U1@DOM1,C1,C2\n", mtime=0)
        def open_fixture(request, timeout):
            return Response(redteam if "redteam" in request.full_url else auth)
        with tempfile.TemporaryDirectory() as directory, patch("scripts.evaluate_lanl.urllib.request.urlopen", side_effect=open_fixture):
            result = fetch(Path(directory), 200, 5)
            self.assertEqual(result["files"]["auth.txt.gz"]["compressed_bytes"], 200)
            self.assertEqual(result["files"]["auth.txt.gz"]["sha256"], hashlib.sha256(auth[:200]).hexdigest())
            self.assertFalse(result["files"]["auth.txt.gz"]["full_gzip_integrity_verified"])
            self.assertTrue(result["files"]["redteam.txt.gz"]["full_gzip_integrity_verified"])
            self.assertTrue((Path(directory) / "provenance.json").exists())

    def test_report_rejects_wrong_provenance_without_disclosing_records(self):
        with tempfile.TemporaryDirectory() as directory:
            auth, labels = self.fixture(directory)
            provenance = Path(directory) / "provenance.json"
            provenance.write_text(json.dumps({"files": {}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Provenance hashes"):
                evaluate(auth, labels, provenance=provenance)


if __name__ == "__main__":
    unittest.main()
