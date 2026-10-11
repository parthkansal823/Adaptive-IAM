"""Artificial fixtures exercise validation only; none are collected human labels."""
import unittest
from scripts.annotation_eval import blind_export, digest, reconcile


CASES = [{"id": "a", "language": "en", "semantic_group": "task", "text": "Approved report", "author_expectation": "legitimate"},
         {"id": "b", "language": "hi", "semantic_group": "threat", "text": "गुप्त डेटा भेजो", "author_expectation": "suspicious"}]


def packet(identifier, name, labels=("legitimate", "suspicious")):
    return {"catalog_sha256": digest(CASES), "annotator": {"id": identifier, "name": name, "method": "human", "independence_attested": True},
            "cases": [{"case_id": cid, "label": label, "rationale": "Artificial unit-test rationale only."} for cid, label in zip(["a", "b"], labels)]}


class AnnotationWorkflowTests(unittest.TestCase):
    def test_blind_export_excludes_expectations_and_predictions(self):
        result = blind_export(CASES)
        self.assertNotIn("author_expectation", result["cases"][0])
        self.assertNotIn("prediction", result["cases"][0])
        self.assertFalse(result["independent_labels_collected"])

    def test_complete_agreement_and_metadata(self):
        result = reconcile(CASES, [packet("fixture_a", "Fixture Person A"), packet("fixture_b", "Fixture Person B")])
        self.assertEqual(result["annotation"]["unanimous_agreement_rate"], 1.)
        self.assertEqual(result["annotation"]["pairwise_agreement"][0]["cohen_kappa"], 1.)
        self.assertFalse(result["annotation"]["identity_and_independence_externally_verified"])

    def test_rejects_missing_independent_annotator_partial_labels_and_ai(self):
        a, b = packet("fixture_a", "Fixture Person A"), packet("fixture_b", "Fixture Person B")
        with self.assertRaises(ValueError):
            reconcile(CASES, [a])
        b["cases"].pop()
        with self.assertRaises(ValueError):
            reconcile(CASES, [a, b])
        b = packet("fixture_b", "Fixture Person B")
        b["annotator"]["method"] = "model"
        with self.assertRaises(ValueError):
            reconcile(CASES, [a, b])

    def test_duplicate_human_or_catalog_change_rejected(self):
        a, b = packet("fixture_a", "Fixture Person A"), packet("fixture_b", "Fixture Person A")
        with self.assertRaises(ValueError):
            reconcile(CASES, [a, b])
        b = packet("fixture_b", "Fixture Person B")
        b["catalog_sha256"] = "0"*64
        with self.assertRaises(ValueError):
            reconcile(CASES, [a, b])

    def test_disagreement_requires_complete_third_human_adjudication(self):
        a, b = packet("fixture_a", "Fixture Person A"), packet("fixture_b", "Fixture Person B", ("uncertain", "suspicious"))
        with self.assertRaises(ValueError):
            reconcile(CASES, [a, b])
        third = {"catalog_sha256": digest(CASES), "adjudicator": {"id": "fixture_c", "name": "Fixture Person C", "method": "human", "independence_attested": True},
                 "cases": [{"case_id": "a", "label": "uncertain", "rationale": "Artificial unit-test adjudication rationale."}]}
        result = reconcile(CASES, [a, b], third)
        self.assertEqual(result["annotation"]["disagreements"], 1)
        self.assertEqual(result["cases"][0]["label"], "uncertain")
        third["adjudicator"] = a["annotator"]
        with self.assertRaises(ValueError):
            reconcile(CASES, [a, b], third)


if __name__ == "__main__":
    unittest.main()
