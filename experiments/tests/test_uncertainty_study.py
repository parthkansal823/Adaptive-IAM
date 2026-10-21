"""Finite-sample ranks, split isolation and conservative policy invariants."""
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import numpy as np

from experiments import uncertainty_study as study


class UncertaintyStudyTests(unittest.TestCase):
    def test_exact_finite_sample_rank_and_conservative_small_sample_fallback(self):
        self.assertEqual(.8, study.conformal_quantile(np.arange(10)/10, alpha=.2))
        self.assertEqual(.9, study.conformal_quantile(np.arange(1, 10)/10, alpha=.1))
        self.assertEqual(1., study.conformal_quantile([.2], alpha=.1))
        self.assertEqual(1., study.conformal_quantile([], alpha=.1))
        self.assertEqual(.4, study.conformal_quantile([.4, .4, .4], alpha=.5))

    def test_invalid_scores_labels_and_alpha_are_rejected(self):
        for scores, alpha in (([float("nan")], .1), ([1.1], .1), ([-.1], .1), ([.4], 0), ([.4], 1), ([.4], float("nan"))):
            with self.subTest(scores=scores, alpha=alpha), self.assertRaises(ValueError):
                study.conformal_quantile(scores, alpha)
        for labels, p in (([0, 1], [.2]), ([0, 2], [.2, .3]), ([0], [float("inf")]), ([], [])):
            with self.assertRaises(ValueError):
                study.fit_conformal(labels, p)

    def test_nonconformity_uses_true_labels_and_class_specific_quantiles(self):
        fitted = study.fit_conformal([0, 0, 1, 1], [.1, .4, .3, .9], alpha=.5)
        self.assertAlmostEqual(.4, fitted["marginal_quantile"])
        np.testing.assert_allclose([.4, .7], fitted["class_quantiles"])
        self.assertEqual({"legitimate": 2, "suspicious": 2}, fitted["class_counts"])
        missing = study.fit_conformal([0, 0], [.1, .4], alpha=.5)
        self.assertEqual(1., missing["class_quantiles"][1])

    def test_prediction_set_boundary_includes_ties_and_empty_both_are_retained(self):
        sets = study.prediction_sets([.2, .4, .6, .8], [.4, .4])
        np.testing.assert_array_equal([[True, False], [True, False], [False, True], [False, True]], sets)
        self.assertFalse(study.prediction_sets([.5], [.4, .4]).any())
        self.assertTrue(study.prediction_sets([.5], [.7, .7]).all())

    def test_gate_requires_benign_singleton_and_never_broadens_baseline(self):
        sets = np.array([[True, False], [True, True], [False, False], [False, True], [True, False]])
        baseline = np.array([True, True, True, True, False])
        np.testing.assert_array_equal([True, False, False, False, False], study.conservative_allow(baseline, sets))
        rng = np.random.default_rng(9382)
        for _ in range(25):
            baseline = rng.random(100) > .5
            sets = rng.random((100, 2)) > .5
            allowed = study.conservative_allow(baseline, sets)
            self.assertFalse(np.any(allowed & ~baseline))

    def test_counts_and_intervals_include_empty_sets_and_uncast_decisions(self):
        labels = np.array([0, 0, 1, 1])
        baseline = np.array([True, True, True, False])
        sets = np.array([[True, False], [True, True], [False, False], [True, False]])
        result = study.policy_metrics(labels, study.conservative_allow(baseline, sets), baseline, sets)
        self.assertEqual(1., result["suspicious_detection_rate"])
        self.assertEqual(0., result["suspicious_direct_allow_rate"])
        self.assertEqual(.5, result["legitimate_friction_rate"])
        self.assertEqual(.5, result["coverage"])
        self.assertEqual(1., result["legitimate_coverage"])
        self.assertEqual(0., result["suspicious_coverage"])
        self.assertEqual(1., result["mean_set_size"])
        self.assertEqual(1, result["counts"]["empty_set"])
        self.assertEqual(4, result["wilson95"]["coverage"]["denominator"])
        self.assertEqual(2, result["wilson95"]["coverage"]["numerator"])
        self.assertEqual(2, result["wilson95"]["suspicious_detection_rate"]["denominator"])

    def test_invalid_authority_broadening_and_missing_class_metrics_fail(self):
        with self.assertRaises(ValueError):
            study.policy_metrics([0, 1], np.array([True, True]), np.array([False, True]))
        with self.assertRaises(ValueError):
            study.policy_metrics([0, 0], np.array([True, False]), np.array([True, True]))

    def test_wilson_extreme_counts_and_reference_interval(self):
        interval = study.wilson95(50, 100)
        self.assertAlmostEqual(.4038315304, interval["lower"])
        self.assertAlmostEqual(.5961684696, interval["upper"])
        self.assertAlmostEqual(0., study.wilson95(0, 100)["lower"])
        self.assertGreater(study.wilson95(0, 100)["upper"], 0)
        self.assertAlmostEqual(1., study.wilson95(100, 100)["upper"])
        for numerator, denominator in ((1, 0), (-1, 2), (3, 2)):
            with self.assertRaises(ValueError):
                study.wilson95(numerator, denominator)

    def test_rejection_sampling_preserves_rows_labels_and_fails_on_short_pool(self):
        rows = np.arange(40, dtype=float).reshape(10, 4)
        labels = np.arange(10) % 2
        accepted = labels.astype(float)
        chosen_x, chosen_y, info = study.rejection_sample(rows, labels, accepted, np.random.default_rng(1), count=4)
        np.testing.assert_array_equal(rows[[1, 3, 5, 7]], chosen_x)
        np.testing.assert_array_equal([1, 1, 1, 1], chosen_y)
        self.assertEqual(5, info["accepted_pool_n"])
        with self.assertRaises(ValueError):
            study.rejection_sample(rows, labels, accepted, np.random.default_rng(1), count=6)

    def test_telemetry_mask_is_paired_fixed_half_and_does_not_modify_source_or_labels(self):
        rows, labels = np.ones((20, 10)), np.arange(20) % 2
        masked, unchanged, info = study.masked_telemetry(rows, labels, seed=77)
        np.testing.assert_array_equal(np.ones((20, 10)), rows)
        np.testing.assert_array_equal(labels, unchanged)
        self.assertEqual(10, info["masked_rows"])
        self.assertEqual(50, int((masked == 0).sum()))
        np.testing.assert_array_equal(np.ones((20, 5)), masked[:, [3, 4, 5, 6, 8]])
        repeated, _, _ = study.masked_telemetry(rows, labels, seed=77)
        np.testing.assert_array_equal(masked, repeated)

    def test_dataset_hash_is_endian_stable_and_binds_shape_and_labels(self):
        x, y = np.arange(12, dtype="<f8").reshape(4, 3), np.array([0, 1, 0, 1])
        self.assertEqual(study.dataset_hash(x, y), study.dataset_hash(x.astype(">f8"), y.astype(">i8")))
        self.assertNotEqual(study.dataset_hash(x, y), study.dataset_hash(x.reshape(6, 2), y))
        self.assertNotEqual(study.dataset_hash(x, y), study.dataset_hash(x, 1-y))

    def test_training_probability_selection_conformal_and_test_splits_are_isolated(self):
        draws, seen = [], {}
        original_dataset = study.dataset
        original_conformal = study.fit_conformal
        original_threshold = study.matched_threshold

        def record_dataset(*args, **kwargs):
            data = original_dataset(*args, **kwargs)
            draws.append(data)
            return data

        def record_train(x, y, seed):
            seen["train"] = (x.copy(), y.copy())
            return lambda rows: .05 + .8*rows[:, 0]

        class Calibrator:
            coef_ = np.array([[1.]])
            intercept_ = np.array([0.])

            def fit(self, x, y):
                seen["probability_calibration"] = (x.copy(), y.copy())
                return self

            def predict_proba(self, x):
                p = 1/(1+np.exp(-x[:, 0]))
                return np.column_stack((1-p, p))

        def record_conformal(y, p, *args):
            seen["conformal"] = np.array(y, copy=True)
            return original_conformal(y, p, *args)

        def record_threshold(y, p, target):
            seen["selection"] = np.array(y, copy=True)
            return original_threshold(y, p, target)

        with patch.object(study, "dataset", side_effect=record_dataset), patch.object(study, "fit_blend", side_effect=record_train), \
                patch.object(study, "LogisticRegression", return_value=Calibrator()), \
                patch.object(study, "fit_conformal", side_effect=record_conformal), \
                patch.object(study, "matched_threshold", side_effect=record_threshold):
            run = study.one_seed(study.SEEDS[0])
        x, y = draws[0]
        np.testing.assert_array_equal(x[:6000], seen["train"][0])
        np.testing.assert_array_equal(y[:6000], seen["train"][1])
        np.testing.assert_array_equal(y[6000:7000], seen["probability_calibration"][1])
        np.testing.assert_array_equal(y[7000:8000], seen["selection"])
        np.testing.assert_array_equal(y[8000:10000], seen["conformal"])
        self.assertEqual(1000, len(seen["probability_calibration"][0]))
        self.assertEqual(3, len(draws))
        for condition in run["conditions"].values():
            self.assertEqual(2000, condition["n"])
        self.assertEqual(run["conditions"]["iid"]["label_counts"], run["conditions"]["telemetry_masking"]["label_counts"])

    def test_summary_uses_per_seed_sample_sd_and_not_pooled_pseudoreplication(self):
        runs = [{"conditions": {condition: {"methods": {method: {"suspicious_detection_rate": value, "counts": {}}
                for method in study.METHODS}} for condition in study.CONDITIONS}} for value in (.5, 1.)]
        summary = study.summarize(runs)["iid"]["baseline"]["suspicious_detection_rate"]
        self.assertEqual(.75, summary["mean"])
        self.assertAlmostEqual(np.sqrt(.125), summary["sample_std"])
        self.assertEqual(.5, summary["minimum"])
        self.assertEqual(1., summary["maximum"])
        with self.assertRaises(ValueError):
            study.summarize(runs[:1])


class FrozenUncertaintyReportTests(unittest.TestCase):
    def saved_report(self):
        path = Path(study.ROOT) / "experiments/uncertainty-study.json"
        if not path.exists():
            self.skipTest("Run the frozen study once to create its measured report")
        return json.loads(path.read_text(encoding="utf-8"))

    def test_report_keeps_all_prespecified_seeds_conditions_and_regressions(self):
        report = self.saved_report()
        self.assertEqual(study.SCHEMA_VERSION, report["schema_version"])
        self.assertTrue(report["synthetic"])
        self.assertFalse(report["protocol"]["test_used_for_selection"])
        self.assertFalse(report["protocol"]["shifted_test_used_for_fitting"])
        self.assertFalse(report["protocol"]["runtime_model_replaced"])
        self.assertEqual(study.SEEDS, [run["seed"] for run in report["runs"]])
        self.assertEqual(study.SEEDS, report["seeds"])
        for run in report["runs"]:
            self.assertEqual(set(study.CONDITIONS), set(run["conditions"]))
            self.assertGreaterEqual(run["selection"]["achieved_suspicious_detection"], .8)
            self.assertEqual(len(study.PARTITIONS), len(set(run["partition_hashes"].values())))
            for condition in run["conditions"].values():
                methods = condition["methods"]
                baseline = methods["baseline"]
                for name, metrics in methods.items():
                    self.assertGreaterEqual(metrics["suspicious_detection_rate"], baseline["suspicious_detection_rate"])
                    self.assertGreaterEqual(metrics["legitimate_friction_rate"], baseline["legitimate_friction_rate"])
                    self.assertAlmostEqual(1., metrics["suspicious_detection_rate"]+metrics["suspicious_direct_allow_rate"])
                    if name in ("marginal_gate", "class_conditional_gate"):
                        counts = metrics["counts"]
                        self.assertEqual(condition["n"], sum(counts[key] for key in
                                         ["empty_set", "both_labels", "singleton_legitimate", "singleton_suspicious"]))
                        self.assertLessEqual(counts["suspicious_direct_allow"], condition["label_counts"]["suspicious"]-counts["suspicious_covered"])
                self.assertEqual(1., methods["always_challenge"]["legitimate_friction_rate"])
                self.assertEqual(1., methods["always_challenge"]["suspicious_detection_rate"])
        self.assertEqual(study.summarize(report["runs"]), report["summary"])

    def test_report_source_provenance_matches_frozen_inputs(self):
        report = self.saved_report()
        self.assertEqual(study.ALPHA, report["alpha"])
        self.assertEqual(study.PARTITIONS, report["protocol"]["partitions"])
        self.assertTrue(report["protocol"]["prespecified_before_first_measurement"])
        self.assertFalse(report["protocol"]["runtime_authorization_changed"])
        self.assertEqual({"experiments/uncertainty_study.py", "experiments/risk_protocol.py", "backend/app/risk.py"},
                         set(report["protocol"]["source_hashes"]))
        for path, digest in report["protocol"]["source_hashes"].items():
            with self.subTest(source=path):
                self.assertEqual(hashlib.sha256((study.ROOT/path).read_bytes()).hexdigest(), digest,
                                 "Frozen source changed: preserve the original artifact and disclose a new revision")
        for package in ("python", "platform", "numpy", "scikit-learn", "joblib"):
            self.assertTrue(report["environment"][package])

    def test_report_datasets_and_shift_construction_reproduce_without_refitting(self):
        report = self.saved_report()
        offsets = report["protocol"]["seed_offsets"]
        for run in report["runs"]:
            seed = run["seed"]
            with self.subTest(seed=seed):
                x, y = study.dataset(seed, n=12000)
                self.assertEqual(study.dataset_hash(x, y), run["dataset_sha256"])
                for name, (start, end) in study.PARTITIONS.items():
                    self.assertEqual(study.dataset_hash(x[start:end], y[start:end]), run["partition_hashes"][name])
                test_x, test_y = x[10000:12000], y[10000:12000]
                self.assertEqual(run["partition_hashes"]["iid_test"], run["conditions"]["iid"]["data_sha256"])
                masked_x, masked_y, mask_info = study.masked_telemetry(test_x, test_y, seed+offsets["mask"])
                masking = run["conditions"]["telemetry_masking"]
                self.assertEqual(study.dataset_hash(masked_x, masked_y), masking["data_sha256"])
                self.assertEqual(1000, masking["construction"]["masked_rows"])
                for name, value in mask_info.items():
                    self.assertEqual(value, masking["construction"][name])
                for condition, pool, acceptance_seed in (("remote_work", "remote_pool", "remote_acceptance"),
                                                         ("label_shift", "label_shift_pool", "label_shift_acceptance")):
                    pool_x, pool_y = study.dataset(seed+offsets[pool], n=40000)
                    accepted_probability = ((1+3*pool_x[:, 0]+2*pool_x[:, 1]+2*pool_x[:, 2]+2*pool_x[:, 4])/10
                                            if condition == "remote_work" else np.where(pool_y == 1, 1., .25))
                    rows, labels, info = study.rejection_sample(pool_x, pool_y, accepted_probability,
                                                              np.random.default_rng(seed+offsets[acceptance_seed]))
                    saved = run["conditions"][condition]
                    self.assertEqual(study.dataset_hash(pool_x, pool_y), saved["construction"]["pool_data_sha256"])
                    self.assertEqual(study.dataset_hash(rows, labels), saved["data_sha256"])
                    self.assertEqual({"legitimate": int((labels == 0).sum()), "suspicious": int((labels == 1).sum())},
                                     saved["label_counts"])
                    for name, value in info.items():
                        self.assertEqual(value, saved["construction"][name])

    def test_report_rate_denominators_intervals_and_challenge_costs_reconcile(self):
        report = self.saved_report()
        for run in report["runs"]:
            for condition_name, condition in run["conditions"].items():
                n = condition["n"]
                n0, n1 = (condition["label_counts"][name] for name in ("legitimate", "suspicious"))
                self.assertEqual(n, n0+n1)
                self.assertEqual(n1/n, condition["prevalence"])
                baseline = condition["methods"]["baseline"]["counts"]
                for method, metrics in condition["methods"].items():
                    with self.subTest(seed=run["seed"], condition=condition_name, method=method):
                        counts = metrics["counts"]
                        self.assertEqual(n, counts["direct_allow"]+counts["challenge"])
                        self.assertEqual(n1, counts["suspicious_detection"]+counts["suspicious_direct_allow"])
                        self.assertEqual(counts["challenge"], counts["suspicious_detection"]+counts["legitimate_friction"])
                        self.assertEqual(counts["added_suspicious_detection"],
                                         counts["suspicious_detection"]-baseline["suspicious_detection"])
                        self.assertEqual(counts["added_legitimate_friction"],
                                         counts["legitimate_friction"]-baseline["legitimate_friction"])
                        expected = {
                            "suspicious_direct_allow_rate": (counts["suspicious_direct_allow"], n1),
                            "suspicious_detection_rate": (counts["suspicious_detection"], n1),
                            "legitimate_friction_rate": (counts["legitimate_friction"], n0),
                            "challenge_rate": (counts["challenge"], n),
                            "added_legitimate_friction_rate": (counts["added_legitimate_friction"], n0),
                            "added_suspicious_detection_rate": (counts["added_suspicious_detection"], n1),
                        }
                        if method in ("marginal_gate", "class_conditional_gate"):
                            expected.update({"coverage": (counts["covered"], n),
                                             "legitimate_coverage": (counts["legitimate_covered"], n0),
                                             "suspicious_coverage": (counts["suspicious_covered"], n1),
                                             **{f"{name}_rate": (counts[name], n) for name in
                                                ("empty_set", "both_labels", "singleton_legitimate", "singleton_suspicious")}})
                            self.assertEqual(counts["covered"], counts["legitimate_covered"]+counts["suspicious_covered"])
                            self.assertEqual((counts["singleton_legitimate"]+counts["singleton_suspicious"]
                                              +2*counts["both_labels"])/n, metrics["mean_set_size"])
                        self.assertEqual(set(expected), set(metrics["wilson95"]))
                        for name, (numerator, denominator) in expected.items():
                            self.assertEqual(numerator/denominator, metrics[name])
                            self.assertEqual(study.wilson95(numerator, denominator), metrics["wilson95"][name])


if __name__ == "__main__":
    unittest.main()
