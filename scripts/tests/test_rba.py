import csv
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts.evaluate_rba import PROTOCOL_VERSION, read_events, timestamp, partitions, evaluate
from scripts.external_study import reusable_report


class HistoryFeaturesTests(unittest.TestCase):
    def write(self, folder, rows):
        path = Path(folder) / "fixture.csv"
        with path.open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        return path

    def row(self, time, successful="true", takeover="false"):
        return {"User ID": "u1", "Login Timestamp": time, "User Agent String": "device-a", "Country": "IN", "Login Successful": successful, "Is Account Takeover": takeover}

    def test_current_outcome_does_not_change_current_features(self):
        with tempfile.TemporaryDirectory() as directory:
            a, _, _ = read_events(self.write(directory, [self.row("2026-01-01T10:00:00Z")]), 10)
            b, _, _ = read_events(self.write(directory, [self.row("2026-01-01T10:00:00Z", "false", "true")]), 10)
            self.assertTrue((a == b).all())

    def test_prior_success_becomes_familiar_only_next_event(self):
        with tempfile.TemporaryDirectory() as directory:
            x, _, _ = read_events(self.write(directory, [self.row("2026-01-01T10:00:00Z"), self.row("2026-01-01T10:01:00Z")]), 10)
            self.assertEqual(x[0, 0], 1)
            self.assertEqual(x[1, 0], 0)
            self.assertEqual(x[1, 1], 0)

    def test_same_timestamp_outcomes_cannot_change_peer_features(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [self.row("1700000000", "false"), self.row("1700000000"), self.row("1700000001")]
            x, _, _ = read_events(self.write(directory, rows), 10)
            self.assertTrue((x[0] == x[1]).all())
            self.assertEqual(x[0, 3], 0)  # Same-second failure remains unavailable.
            self.assertEqual(x[1, 5], 0)  # Same-second velocity remains unavailable.
            self.assertAlmostEqual(x[2, 3], 1 / 20)
            self.assertAlmostEqual(x[2, 5], 2 / 30)
            self.assertEqual(x[2, 0], 0)

    def test_same_timestamp_permutation_cannot_change_scores(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = self.row("1700000000", "false"), self.row("1700000000")
            b["User Agent String"] = "device-b"
            following = self.row("1700000001")
            x, _, _ = read_events(self.write(directory, [a, b, following]), 10)
            swapped, _, _ = read_events(self.write(directory, [b, a, following]), 10)
            self.assertTrue((x[[1, 0, 2]] == swapped).all())

    def test_row_cap_excludes_whole_bisected_timestamp_group(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [self.row("1700000000"), self.row("1700000001"), self.row("1700000001")]
            x, _, times = read_events(self.write(directory, rows), 2)
            self.assertEqual(len(x), 1)
            self.assertEqual(times, [timestamp("1700000000").isoformat()])

    def test_row_cap_retains_complete_group_at_exact_boundary_and_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [self.row("1700000000"), self.row("1700000000"), self.row("1700000001")]
            path = self.write(directory, rows)
            self.assertEqual(len(read_events(path, 2)[0]), 2)
            self.assertEqual(len(read_events(path, 3)[0]), 3)

    def test_row_cap_cannot_invent_complete_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, [self.row("1700000000"), self.row("1700000000")])
            with self.assertRaisesRegex(ValueError, "complete timestamp"):
                read_events(path, 1)

    def test_future_row_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "chronological"):
                read_events(self.write(directory, [self.row("2026-01-02T10:00:00Z"), self.row("2026-01-01T10:01:00Z")]), 10)

    def test_seconds_milliseconds_iso_match(self):
        self.assertEqual(timestamp("1700000000"), timestamp("1700000000000"))
        self.assertEqual(timestamp("1700000000"), timestamp("2023-11-14T22:13:20Z"))

    def test_hash_cohorts_are_disjoint_and_stable_for_repeat_users(self):
        users=[f'user-{i%200}' for i in range(1000)]
        first=partitions(users,'user-disjoint')
        second=partitions(users,'user-disjoint')
        self.assertEqual(sorted(i for part in first for i in part),list(range(1000)))
        for i in range(4):
            self.assertTrue((first[i]==second[i]).all())
            self.assertGreater(len(first[i]),0)
            for j in range(i+1,4):
                self.assertFalse({users[k] for k in first[i]} & {users[k] for k in first[j]})

    def test_chronological_partitions_never_split_timestamp_groups(self):
        times = [str(1700000000 + offset) for offset in [0] * 5 + [1] * 3 + [2] + [3]]
        parts = partitions(["u"] * len(times), "chronological", times)
        self.assertEqual([len(part) for part in parts], [8, 0, 0, 2])
        for first in range(4):
            for second in range(first + 1, 4):
                self.assertFalse({times[i] for i in parts[first]} & {times[i] for i in parts[second]})

    def test_chronological_split_requires_ordered_aligned_times(self):
        for times in (None, ["1700000000"], ["1700000001", "1700000000"]):
            with self.subTest(times=times), self.assertRaises(ValueError):
                partitions(["u", "u"], "chronological", times)

    def test_ties_that_empty_partitions_fail_before_any_fit(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [self.row("1700000000", takeover="true" if i % 2 else "false") for i in range(100)]
            with patch("scripts.evaluate_rba.LogisticRegression.fit") as fit, self.assertRaisesRegex(ValueError, "partition needs both classes"):
                evaluate(self.write(directory, rows), 100)
            fit.assert_not_called()

    def test_cached_metrics_require_current_protocol_identity(self):
        report = {"dataset": {"sha256": "digest", "label": "Is Attack IP", "row_limit": 200},
                  "method": {"split": "chronological 60/10/10/20"}}
        self.assertFalse(reusable_report(report, "digest", "Is Attack IP", 200, "chronological"))
        report["method"]["protocol_version"] = PROTOCOL_VERSION
        self.assertTrue(reusable_report(report, "digest", "Is Attack IP", 200, "chronological"))
        self.assertFalse(reusable_report(report, "other", "Is Attack IP", 200, "chronological"))

    def test_proxy_label_is_explicit_and_never_a_feature(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.row('2026-01-01T10:00:00Z')
            row['Is Attack IP']='true'
            path=self.write(directory,[row])
            x,y,_=read_events(path,10)
            xp,yp,_=read_events(path,10,label='Is Attack IP')
            self.assertEqual(y.tolist(),[0])
            self.assertEqual(yp.tolist(),[1])
            self.assertTrue((x==xp).all())

    def test_missing_class_fails_before_training(self):
        with tempfile.TemporaryDirectory() as directory:
            rows=[self.row(str(1700000000+i)) for i in range(100)]
            with self.assertRaisesRegex(ValueError,'partition needs both classes'):
                evaluate(self.write(directory,rows),100)

    def test_fresh_report_binds_protocol_implementation_and_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [self.row(str(1700000000 + i), takeover="true" if i % 2 else "false") for i in range(100)]
            report = evaluate(self.write(directory, rows), 100)
            self.assertEqual(report["method"]["protocol_version"], PROTOCOL_VERSION)
            self.assertTrue(report["method"]["features_use_strictly_earlier_timestamps_only"])
            module = Path(__file__).resolve().parents[1] / "evaluate_rba.py"
            self.assertEqual(report["implementation"]["source_sha256"], hashlib.sha256(module.read_bytes()).hexdigest())
            self.assertEqual(set(report["environment"]), {"python", "platform", "numpy", "scikit-learn"})
            self.assertEqual(sum(part["rows"] for part in report["dataset"]["partitions"].values()), 100)


if __name__ == "__main__":
    unittest.main()
