import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import experiments.real_auth_models as real_auth_models

from experiments.real_auth_models import (
    AuthEvent, Counts, METHODS, NoveltyModel, csv_groups, evaluate_groups,
    fixed_protocol, freeze, protocol_hash, run_study, sha256_file,
)


class RealAuthModelTests(unittest.TestCase):
    def event(self, second, user="user", computer="host"):
        return AuthEvent(second, user, computer, "source", computer)

    def groups(self, count=100):
        return [(second, [self.event(second, "new" if second == 90 else "user", "rare" if second in (60, 90) else "host")]) for second in range(1, count + 1)]

    def scan(self):
        return {"source_first_second": 1, "source_last_second": 100, "source_rows": 100, "selected_rows": 100}

    def test_cold_system_and_user_do_not_have_forced_zero_score(self):
        first = self.event(1)
        baseline = NoveltyModel("lifetime_user_computer")
        self.assertEqual(baseline.score(first), 0.)
        for name in METHODS[1:]:
            model = NoveltyModel(name)
            self.assertGreater(model.score(first), 0.)
            model.update([first] * 5)
            self.assertGreater(model.score(self.event(2, "unseen-user", "unseen-host")), model.score(self.event(2, "unseen-user", "host")))

    def test_score_calls_do_not_mutate_history_or_observe_current_event(self):
        for name in METHODS:
            model = NoveltyModel(name)
            event = self.event(1)
            score = model.score(event)
            self.assertEqual(model.score(event), score)
            self.assertEqual(model.counts.values, {})

    def test_group_order_invariance(self):
        group = [self.event(10), self.event(10, "other", "different"), self.event(10)]
        for name in METHODS:
            a, b = NoveltyModel(name), NoveltyModel(name)
            self.assertEqual([a.score(e) for e in group], [b.score(e) for e in group])
            a.update(group)
            b.update(list(reversed(group)))
            self.assertEqual(a.counts.values, b.counts.values)
            self.assertEqual(a.score(self.event(11)), b.score(self.event(11)))

    def test_decay_halves_all_numerators_and_denominators_consistently(self):
        model = NoveltyModel("hierarchical_decay")
        model.update([self.event(1)] * 4 + [self.event(1, "other", "different")] * 2)
        later = 86401
        values = {key: model.counts.get(key, later) for key in model.counts.values}
        self.assertAlmostEqual(values[("global",)], 3.)
        self.assertAlmostEqual(values[("computer", "host")], 2.)
        self.assertAlmostEqual(values[("user", "user")], 2.)
        self.assertAlmostEqual(values[("pair", "user", "host")], 2.)
        self.assertLessEqual(values[("pair", "user", "host")], values[("user", "user")])
        self.assertLessEqual(values[("computer", "host")], values[("global",)])
        self.assertAlmostEqual(model.counts.get(("global",), later), 3.)

    def test_decay_forgets_old_familiarity_while_static_remembers(self):
        static, decay = NoveltyModel("hierarchical_static"), NoveltyModel("hierarchical_decay")
        for model in (static, decay):
            model.update([self.event(1)] * 100)
        event = self.event(1 + 86400 * 30)
        self.assertGreater(decay.score(event), static.score(event))

    def test_old_count_queries_and_mixed_timestamp_updates_rejected(self):
        counts = Counts(86400.)
        counts.add("key", 10, 1)
        with self.assertRaises(ValueError):
            counts.get("key", 9)
        with self.assertRaises(ValueError):
            NoveltyModel("hierarchical_static").update([self.event(1), self.event(2)])

    def test_labels_never_change_thresholds_or_total_alerts(self):
        unlabeled = evaluate_groups(iter(self.groups()), self.scan(), None, {})
        labeled = evaluate_groups(iter(self.groups()), self.scan(), {(90, "new", "source", "rare")}, {})
        for name in METHODS:
            self.assertEqual(unlabeled["methods"][name]["threshold"], labeled["methods"][name]["threshold"])
            self.assertEqual(unlabeled["methods"][name]["test_alerts"], labeled["methods"][name]["test_alerts"])
            self.assertIsNone(unlabeled["methods"][name]["known_redteam_tuple_recall"])
        self.assertTrue(labeled["labels"]["detection_metrics_eligible"])

    def test_strata_are_shared_lifetime_past_only_and_counts_add_up(self):
        report = evaluate_groups(iter(self.groups()), self.scan(), None, {})
        self.assertEqual(sum(entry["events"] for entry in report["test_strata"].values()), report["partitions"]["test"]["events"])
        cold = report["test_strata"]["cold_user"]
        self.assertEqual(cold["events"], 1)
        self.assertEqual(cold["methods"]["lifetime_user_computer"]["zero_scores"], 1)
        self.assertEqual(cold["methods"]["hierarchical_decay"]["zero_scores"], 0)

    def test_equal_second_groups_never_split_windows(self):
        groups = [(second, [self.event(second)] * 2) for second in range(1, 101)]
        scan = {**self.scan(), "selected_rows": 200}
        report = evaluate_groups(iter(groups), scan, None, {})
        self.assertEqual(report["partitions"]["warmup"]["events"], 100)
        self.assertEqual(report["partitions"]["validation"]["events"], 50)
        self.assertEqual(report["partitions"]["test"]["events"], 50)
        for method in report["methods"].values():
            self.assertLessEqual(method["threshold"]["validation_alert_fraction"], .01)

    def test_duplicate_labels_use_distinct_tuple_denominator(self):
        groups = self.groups()
        groups[89][1].append(self.event(90, "new", "rare"))
        report = evaluate_groups(iter(groups), {**self.scan(), "selected_rows": 101}, {(90, "new", "source", "rare")}, {})
        self.assertEqual(report["partitions"]["test"]["matched_auth_rows"], 2)
        self.assertEqual(report["partitions"]["test"]["known_redteam_unique_tuples"], 1)

    def test_parser_tail_and_no_raw_identifiers_in_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.csv"
            path.write_text("1,secret-user,secret-host\n2,secret-user,secret-host\n", encoding="ascii")
            self.assertEqual([second for second, _ in csv_groups(path)], [1])
        report = evaluate_groups(iter(self.groups()), self.scan(), None, {})
        text = json.dumps(report)
        self.assertNotIn("source\",", text)
        self.assertNotIn("different", text)

    def test_freeze_rejects_protocol_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            report = freeze(path)
            self.assertEqual(report["protocol_sha256"], protocol_hash(fixed_protocol()))
            self.assertEqual(report["implementation_sha256_at_freeze"], sha256_file(Path(real_auth_models.__file__)))
            report["protocol_sha256"] = "changed"
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different frozen protocol"):
                freeze(path)

    def test_freeze_rejects_content_tamper_even_with_unchanged_declared_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            report = freeze(path)
            report["protocol"]["backoff_strength"] = 100.
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "different frozen protocol"):
                freeze(path)

    def test_canonical_parser_rejects_oversized_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.csv"
            path.write_text("1," + "a" * 300 + ",host\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "Oversized"):
                list(csv_groups(path))

    def test_acquisition_count_mismatch_fails(self):
        with self.assertRaisesRegex(ValueError, "source selection metadata"):
            evaluate_groups(iter(self.groups()), {**self.scan(), "selected_rows": 101}, None, {})

    def test_existing_freeze_preserves_original_implementation_commitment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            original = freeze(path)
            with patch.object(real_auth_models, "sha256_file", side_effect=AssertionError("must not refresh freeze")):
                self.assertEqual(freeze(path), original)

    def source_fixture(self, directory):
        auth = directory / "auth.txt"
        auth.write_text("".join(f"{second},U1@DOMAIN,U1@DOMAIN,C1,C2,Kerberos,Network,LogOn,Success\n"
                                for second in range(1, 102)), encoding="ascii")
        redteam = directory / "redteam.txt"
        redteam.write_text("", encoding="ascii")
        source_report = directory / "source.json"
        source_report.write_text(json.dumps({"source": {"auth_sha256": sha256_file(auth),
                                                       "redteam_sha256": sha256_file(redteam), "landing_page": "fixture"},
                                            "scan": {"source_first_second": 1, "source_last_second": 101,
                                                     "source_rows": 101, "selected_rows": 100}}), encoding="utf-8")
        return auth, redteam, source_report

    def test_partial_rerun_keeps_retained_execution_hash_and_marks_mixed_implementations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "report.json"
            frozen = freeze(path)
            old_hash = "a" * 64
            frozen["implementation"] = {"sha256": old_hash, "python_version": "fixture-python", "platform": "fixture-platform"}
            frozen["datasets"] = {"lanl2014_unlabeled": {"measurement": "retained"}}
            path.write_text(json.dumps(frozen), encoding="utf-8")
            result = run_study(path, *self.source_fixture(root))
            retained = result["datasets"]["lanl2014_unlabeled"]
            measured = result["datasets"]["lanl2015_retrospective"]
            self.assertEqual(retained["measurement"], "retained")
            self.assertEqual(retained["implementation_sha256"], old_hash)
            self.assertEqual(retained["execution_environment"]["python_version"], "fixture-python")
            self.assertEqual(measured["implementation_sha256"], sha256_file(Path(real_auth_models.__file__)))
            self.assertEqual(measured["execution_commitment"]["datasets"], ["lanl2015_retrospective"])
            self.assertNotIn("pending_execution_commitment", result)
            self.assertIsNone(result["implementation"]["sha256"])
            self.assertTrue(result["implementation"]["mixed_dataset_implementations"])
            self.assertEqual(result["implementation"]["dataset_sha256"]["lanl2014_unlabeled"], old_hash)
            self.assertEqual(result["implementation_sha256_at_freeze"], frozen["implementation_sha256_at_freeze"])

    def test_retained_missing_identity_is_rejected_without_guessing_from_new_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "report.json"
            frozen = freeze(path)
            frozen["implementation"] = {"sha256": None, "mixed_dataset_implementations": True}
            frozen["datasets"] = {"lanl2014_unlabeled": {"measurement": "retained"}}
            path.write_text(json.dumps(frozen), encoding="utf-8")
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "execution implementation identity"):
                run_study(path, *self.source_fixture(root))
            self.assertEqual(path.read_bytes(), before)

    def test_evaluation_requires_inputs_even_when_report_already_has_results(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            freeze(path)
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, "actual dataset"):
                run_study(path)
            self.assertEqual(path.read_bytes(), before)

    def test_failed_evaluation_records_pending_identity_without_restamping_retained_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "report.json"
            frozen = freeze(path)
            old_hash = "b" * 64
            frozen["datasets"] = {"lanl2014_unlabeled": {"measurement": "retained", "implementation_sha256": old_hash}}
            frozen["implementation"] = {"sha256": old_hash}
            path.write_text(json.dumps(frozen), encoding="utf-8")
            auth, redteam, source_report = self.source_fixture(root)
            auth.write_text("changed", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "differ from frozen source"):
                run_study(path, auth, redteam, source_report)
            pending = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(pending["datasets"], frozen["datasets"])
            self.assertEqual(pending["implementation"], frozen["implementation"])
            self.assertEqual(pending["pending_execution_commitment"]["datasets"], ["lanl2015_retrospective"])
            self.assertEqual(pending["pending_execution_commitment"]["module_sha256"], sha256_file(Path(real_auth_models.__file__)))


if __name__ == "__main__":
    unittest.main()
