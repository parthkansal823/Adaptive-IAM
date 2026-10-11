"""Abstention accounting must not inflate advisory agreement."""
import unittest
from experiments.multilingual import metrics


class MultilingualAccountingTests(unittest.TestCase):
    def test_abstentions_remain_in_definite_reference_denominator(self):
        rows = [{"reference_label": "suspicious", "assessment": {"label": "uncertain"}},
                {"reference_label": "legitimate", "assessment": {"label": "legitimate"}}]
        result = metrics(rows, "label")
        self.assertEqual(result["suspicious_flag_rate"], 0.)
        self.assertEqual(result["abstentions"], 1)
        self.assertEqual(result["definitive_coverage"], .5)
        self.assertEqual(result["agreement_on_definite_reference_including_model_abstentions"], .5)

    def test_uncertain_reference_is_reported_and_not_binary_attack_truth(self):
        rows = [{"reference_label": "uncertain", "assessment": {"label": "suspicious"}}]
        result = metrics(rows, "label")
        self.assertEqual(result["reference_uncertain"], 1)
        self.assertIsNone(result["suspicious_flag_rate"])
        self.assertIsNone(result["legitimate_flag_rate"])
        self.assertIsNone(result["agreement_on_definite_reference_including_model_abstentions"])


if __name__ == "__main__":
    unittest.main()
