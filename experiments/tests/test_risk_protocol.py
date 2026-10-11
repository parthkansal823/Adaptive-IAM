"""Operating-point and reliability invariants, independent of fitted parameters."""
import unittest
import numpy as np
from experiments.risk_protocol import classification_threshold, matched_threshold, reliability


class RiskProtocolTests(unittest.TestCase):
    def test_threshold_selects_largest_feasible_positive_score_with_ties(self):
        labels = np.array([1, 1, 1, 1, 0])
        scores = np.array([.9, .7, .7, .2, .8])
        threshold = matched_threshold(labels, scores, .75)
        self.assertEqual(threshold, .7)
        self.assertGreaterEqual(np.mean(scores[labels == 1] >= threshold), .75)
        self.assertLess(np.mean(scores[labels == 1] >= np.nextafter(threshold, 1)), .75)

    def test_increasing_calibration_preserves_matched_decisions(self):
        labels = np.array([1, 0, 1, 1, 0, 1])
        scores = np.array([.2, .3, .4, .6, .7, .9])
        calibrated = scores**2
        raw_cutoff = matched_threshold(labels, scores, .75)
        cal_cutoff = matched_threshold(labels, calibrated, .75)
        np.testing.assert_array_equal(scores >= raw_cutoff, calibrated >= cal_cutoff)

    def test_fixed_bins_include_one_and_preserve_empty_bins(self):
        report = reliability(np.array([0, 1]), np.array([0., 1.]))
        self.assertEqual(sum(b["count"] for b in report["bins"]), 2)
        self.assertEqual(report["bins"][-1]["count"], 1)
        self.assertIsNone(report["bins"][4]["observed_positive_rate"])
        self.assertEqual(report["ece"], 0.)

    def test_exact_classification_tuning_preserves_monotone_operating_point(self):
        labels = np.array([1, 0, 1, 1, 0, 1])
        scores = np.array([.2, .3, .4, .6, .7, .9])
        raw = classification_threshold(labels, scores)
        cal = classification_threshold(labels, scores**2)
        np.testing.assert_array_equal(scores >= raw, scores**2 >= cal)

    def test_invalid_selection_and_nonprobabilities_fail(self):
        with self.assertRaises(ValueError):
            matched_threshold([0, 0], [.2, .4], .8)
        with self.assertRaises(ValueError):
            matched_threshold([1], [.2], 0)
        with self.assertRaises(ValueError):
            reliability([1], [float("nan")])


if __name__ == "__main__":
    unittest.main()
