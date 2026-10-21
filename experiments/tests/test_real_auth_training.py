"""Small invented fixtures verify mechanics; measured reports use actual source rows."""
import copy
import json
import math
import tempfile
import unittest
import warnings
from collections import Counter
from pathlib import Path

import numpy as np

from experiments.real_auth_models import AuthEvent, evaluate_groups as evaluate_counts
from experiments.real_auth_training import (
    BASELINES, FEATURES, METHODS, FeatureHistory, Reservoir, candidate_configs,
    choose_candidate, evaluate_groups, fit_forest, fixed_protocol, forest_scores, freeze,
    protocol_hash, save_model,
)


class RealAuthTrainingTests(unittest.TestCase):
    def setUp(self):
        # Tiny mechanics fixtures intentionally have fewer rows than production
        # subsamples; sklearn's documented clamping warning is expected here.
        context = warnings.catch_warnings()
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        warnings.filterwarnings("ignore", message=r"max_samples \(\d+\) is greater than the total number of samples", category=UserWarning)

    def event(self, second, user="u", computer="c", source="source"):
        return AuthEvent(second, user, computer, source, computer)

    def groups(self):
        return [(second, [self.event(second, "u" + str(second % 5), "c" + str(second % 7))] * (second % 3 + 1)) for second in range(1, 101)]

    def scan(self, groups):
        return {"source_first_second": 1, "source_last_second": 100,
                "selected_rows": sum(len(events) for _, events in groups)}

    def test_features_are_past_only_and_have_no_identifier_or_label_values(self):
        history = FeatureHistory()
        event = self.event(1, "private-user", "private-computer")
        before = copy.deepcopy(history.__dict__)
        values = history.features(event)
        self.assertEqual(history.__dict__, before)
        self.assertEqual(len(values), len(FEATURES))
        self.assertTrue(all(math.isfinite(value) for value in values))
        self.assertEqual(values[5:], (1., 1., 1., 1.))
        self.assertEqual(values, history.features(self.event(1, "other", "else", "changed")))
        history.update(1, Counter({("private-user", "private-computer"): 5}))
        self.assertEqual(history.features(self.event(2, "private-user", "private-computer"))[5:7], (0., 0.))
        with self.assertRaises(ValueError):
            history.features(event)

    def test_relative_features_do_not_include_raw_global_counter(self):
        history = FeatureHistory()
        history.update(1, Counter({("u", "c"): 10}))
        actual = history.features(self.event(11))
        self.assertAlmostEqual(actual[0], -math.log(11 / 12))
        self.assertAlmostEqual(actual[1], -math.log(11 / 12))
        self.assertAlmostEqual(actual[2], -math.log(11 / 12))
        self.assertAlmostEqual(actual[3], math.log1p(1))
        self.assertAlmostEqual(actual[4], 2 / 12)
        self.assertNotIn("log1p_prior_global_count", FEATURES)

    def test_recency_is_capped_without_observing_future(self):
        history = FeatureHistory()
        history.update(1, Counter({("u", "c"): 1}))
        self.assertEqual(history.features(self.event(1000000))[-2:], (1., 1.))
        self.assertLess(history.features(self.event(2))[-1], 1.)
        with self.assertRaises(ValueError):
            history.update(1, Counter({("u", "c"): 1}))

    def test_reservoir_is_bounded_reproducible_and_counts_duplicates(self):
        a, b = Reservoir(7), Reservoir(7)
        for index in range(100):
            a.add((index,), 3)
            b.add((index,), 3)
        self.assertEqual(a.seen, 300)
        self.assertEqual(len(a.values), 7)
        self.assertEqual(a.values, b.values)
        self.assertTrue(any(value[0] > 7 for value in a.values))
        with self.assertRaises(ValueError):
            Reservoir(0)

    def test_fitted_estimator_uses_actual_feature_samples_and_roundtrips(self):
        reservoir = Reservoir(30)
        for index in range(30):
            reservoir.add(tuple(float(index + j) for j in range(len(FEATURES))))
        model, digest = fit_forest(reservoir)
        self.assertEqual(model.n_features_in_, 9)
        self.assertEqual(len(model.estimators_), 100)
        self.assertEqual(len(digest), 64)
        features = reservoir.values[:4]
        scores = forest_scores(model, features)
        self.assertTrue(np.isfinite(scores).all())
        with tempfile.TemporaryDirectory() as directory:
            import joblib
            path = Path(directory) / "trusted.joblib"
            self.assertEqual(len(save_model(path, model)), 64)
            restored = joblib.load(path)
            np.testing.assert_array_equal(scores, forest_scores(restored, features))

    def test_grid_is_fixed_six_and_tie_break_deterministic(self):
        self.assertEqual(len(candidate_configs()), 6)
        hist = {entry["id"]: {"calibration": Counter({.1: 990, .9: 10}),
                                   "selection": Counter({.1: 990, .9: 10}), "all": Counter()}
                for entry in candidate_configs()}
        selected, metrics, fallback = choose_candidate(hist)
        self.assertEqual(selected, "if_128_0p75")
        self.assertFalse(fallback)
        self.assertTrue(all(entry["eligible"] for entry in metrics))
        self.assertTrue(all(entry["objective_distance_to_budget"] == 0 for entry in metrics))

    def test_grid_excludes_unsupported_ties_and_discloses_fallback(self):
        hist = {entry["id"]: {"calibration": Counter({.9: 100}), "selection": Counter({.9: 100}), "all": Counter()}
                for entry in candidate_configs()}
        selected, metrics, fallback = choose_candidate(hist)
        self.assertEqual(selected, "if_256_1p0")
        self.assertTrue(fallback)
        self.assertTrue(all(not entry["eligible"] for entry in metrics))

    def test_empty_calibration_half_is_ineligible_and_falls_back(self):
        hist = {entry["id"]: {"calibration": Counter(), "selection": Counter({.1: 990, .9: 10}), "all": Counter()}
                for entry in candidate_configs()}
        selected, metrics, fallback = choose_candidate(hist)
        self.assertEqual(selected, "if_256_1p0")
        self.assertTrue(fallback)
        for entry in metrics:
            self.assertFalse(entry["eligible"])
            self.assertEqual(entry["calibration_events"], 0)
            self.assertIsNone(entry["calibration_threshold"]["minimum_score"])
            self.assertIsNone(entry["calibration_threshold"]["validation_alert_fraction"])
            self.assertIsNone(entry["objective_distance_to_budget"])

    def test_empty_selection_half_is_ineligible_and_falls_back(self):
        hist = {entry["id"]: {"calibration": Counter({.1: 990, .9: 10}), "selection": Counter(), "all": Counter()}
                for entry in candidate_configs()}
        selected, metrics, fallback = choose_candidate(hist)
        self.assertEqual(selected, "if_256_1p0")
        self.assertTrue(fallback)
        self.assertTrue(all(not entry["eligible"] for entry in metrics))
        self.assertTrue(all(entry["selection_alert_fraction"] is None for entry in metrics))

    def test_wholly_empty_validation_has_clear_failure(self):
        hist = {entry["id"]: {"calibration": Counter(), "selection": Counter(), "all": Counter()}
                for entry in candidate_configs()}
        with self.assertRaisesRegex(ValueError, "Validation window has no selected events"):
            choose_candidate(hist)

    def test_sparse_validation_first_half_runs_fallback_without_retraining(self):
        groups = [(second, events) for second, events in self.groups() if not 50 < second <= 62]
        report = evaluate_groups(iter(groups), self.scan(groups), None, {})
        self.assertTrue(report["training"]["tuning"]["fallback_used"])
        self.assertEqual(report["training"]["tuning"]["selected_candidate_id"], "if_256_1p0")
        self.assertEqual(report["methods"]["isolation_forest_tuned"], report["methods"]["isolation_forest"])

    def test_labels_never_change_weights_thresholds_or_selected_parameters(self):
        groups = self.groups()
        a = evaluate_groups(iter(groups), self.scan(groups), None, {}, batch_size=19)
        b = evaluate_groups(iter(groups), self.scan(groups), {groups[-1][1][0].label_key}, {}, batch_size=19)
        self.assertEqual(a["training"]["feature_tensor_sha256"], b["training"]["feature_tensor_sha256"])
        self.assertEqual(a["training"]["tuning"]["selected_candidate_id"], b["training"]["tuning"]["selected_candidate_id"])
        for method in METHODS:
            self.assertEqual(a["methods"][method]["threshold"], b["methods"][method]["threshold"])
            self.assertEqual(a["methods"][method]["test_alerts"], b["methods"][method]["test_alerts"])
            self.assertIsNone(a["methods"][method]["known_redteam_tuple_recall"])
        self.assertTrue(b["labels"]["detection_metrics_eligible"])

    def test_test_changes_cannot_change_fit_or_tuning_and_batches_are_invariant(self):
        groups = self.groups()
        a = evaluate_groups(iter(groups), self.scan(groups), None, {}, batch_size=17)
        b = evaluate_groups(iter(groups), self.scan(groups), None, {}, batch_size=1000)
        self.assertEqual(a["methods"], b["methods"])
        changed = [(second, [self.event(second, "different", "different")] * len(events) if second > 75 else events) for second, events in groups]
        c = evaluate_groups(iter(changed), self.scan(changed), None, {}, batch_size=17)
        self.assertEqual(a["training"]["feature_tensor_sha256"], c["training"]["feature_tensor_sha256"])
        self.assertEqual(a["training"]["tuning"], c["training"]["tuning"])
        self.assertEqual({name: entry["threshold"] for name, entry in a["methods"].items()},
                         {name: entry["threshold"] for name, entry in c["methods"].items()})

    def test_within_second_reordering_preserves_fit_and_all_metrics(self):
        groups = [(second, events + [self.event(second, "other", "other")]) for second, events in self.groups()]
        reverse = [(second, list(reversed(events))) for second, events in groups]
        a = evaluate_groups(iter(groups), self.scan(groups), None, {})
        b = evaluate_groups(iter(reverse), self.scan(reverse), None, {})
        self.assertEqual(a["methods"], b["methods"])
        self.assertEqual(a["training"]["feature_tensor_sha256"], b["training"]["feature_tensor_sha256"])
        self.assertEqual(a["partitions"], b["partitions"])

    def test_count_controls_match_frozen_existing_evaluator(self):
        groups = self.groups()
        trained = evaluate_groups(iter(groups), self.scan(groups), None, {})
        old = evaluate_counts(iter(groups), self.scan(groups), None, {})
        for method in BASELINES:
            self.assertEqual(trained["methods"][method], old["methods"][method])

    def test_partition_and_strata_denominators_and_timestamp_boundaries(self):
        groups = self.groups()
        report = evaluate_groups(iter(groups), self.scan(groups), None, {})
        self.assertEqual(report["partitions"]["warmup"]["last_second"], 50)
        self.assertEqual(report["partitions"]["validation"]["last_second"], 75)
        self.assertEqual(report["partitions"]["test"]["first_second"], 76)
        self.assertEqual(report["training"]["warmup_events_seen"], report["partitions"]["warmup"]["events"])
        self.assertEqual(sum(entry["events"] for entry in report["test_strata"].values()), report["partitions"]["test"]["events"])
        self.assertEqual(report["training"]["tuning"]["calibration_end_second"], 62)
        for method in METHODS:
            self.assertEqual(sum(entry["methods"][method]["alerts"] for entry in report["test_strata"].values()), report["methods"][method]["test_alerts"])

    def test_duplicate_rows_match_one_exercise_tuple_without_fake_negative_labels(self):
        groups = self.groups()
        label = groups[-1][1][0].label_key
        report = evaluate_groups(iter(groups), self.scan(groups), {label}, {})
        test = report["partitions"]["test"]
        self.assertEqual(test["matched_auth_rows"], len(groups[-1][1]))
        self.assertEqual(test["known_redteam_unique_tuples"], 1)
        self.assertEqual(test["unlabeled_events"], test["events"] - len(groups[-1][1]))
        for method in report["methods"].values():
            self.assertIn(method["known_redteam_tuple_recall"], (0., 1.))

    def test_invalid_order_and_source_count_mismatch_are_rejected(self):
        groups = self.groups()
        with self.assertRaises(ValueError):
            evaluate_groups(iter(list(reversed(groups))), self.scan(groups), None, {})
        with self.assertRaises(ValueError):
            evaluate_groups(iter(groups), {**self.scan(groups), "selected_rows": 1}, None, {})

    def test_protocol_freeze_rejects_changed_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            report = freeze(path)
            self.assertEqual(report["protocol_sha256"], protocol_hash(fixed_protocol()))
            report["protocol"]["reservoir_capacity"] = 12
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(ValueError):
                freeze(path)


if __name__ == "__main__":
    unittest.main()
