import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from backend.app.main import create_app
from backend.app import research


class FrozenResearchTests(unittest.TestCase):
    def test_packaged_training_report_exposes_real_fit_and_validation_selection_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "unused-runtime"
            response = TestClient(create_app(runtime)).get("/api/research/real-auth-training")
            self.assertEqual(response.status_code, 200)
            report = response.json()
            self.assertFalse(report["synthetic"])
            self.assertEqual(len(report["datasets"]), 3)
            for dataset in report["datasets"].values():
                training = dataset["training"]
                self.assertEqual(training["reservoir_events"], 30000)
                self.assertEqual(training["fitted_feature_dimensions"], 9)
                self.assertEqual(len(training["tuning"]["candidates"]), 6)
                self.assertEqual(training["weights_frozen_after"], "warmup")
                if not dataset["labels"]["detection_metrics_eligible"]:
                    for method in dataset["methods"].values():
                        self.assertIsNone(method["known_redteam_tuple_recall"])
            self.assertFalse(runtime.exists())

    def test_packaged_real_model_report_preserves_both_dataset_label_boundaries(self):
        response = TestClient(create_app()).get("/api/research/real-auth-models")
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertEqual(report["status"], "measured")
        self.assertEqual(set(report["datasets"]), {"lanl2015_retrospective", "lanl2014_unlabeled"})
        retrospective = report["datasets"]["lanl2015_retrospective"]
        self.assertTrue(retrospective["source"]["retrospective"])
        self.assertTrue(retrospective["labels"]["detection_metrics_eligible"])
        unlabeled = report["datasets"]["lanl2014_unlabeled"]
        self.assertFalse(unlabeled["labels"]["detection_metrics_eligible"])
        for method in unlabeled["methods"].values():
            self.assertIsNone(method["known_redteam_tuple_recall"])

    def test_supported_reports_reject_overflowing_json_numbers(self):
        reports = [
            ("/api/research/real-auth-training", "TRAINING_REPORT_PATH", {
                "schema_version": "real-auth-training-v1", "synthetic": False, "status": "measured",
                "datasets": {"fixture": {"overflow": 1}}, "protocol": {}, "limitations": []}),
            ("/api/research/real-auth-models", "REAL_AUTH_MODELS_PATH", {
                "schema_version": "real-auth-model-study-v1", "synthetic": False,
                "datasets": {"fixture": {"overflow": 1}}, "protocol": {}, "limitations": []}),
            ("/api/research/uncertainty", "REPORT_PATH", {
                "schema_version": "uncertainty-study-v1", "synthetic": True,
                "summary": {"overflow": 1}, "runs": [], "limitations": []}),
            ("/api/research/lanl", "LANL_REPORT_PATH", {
                "schema_version": "lanl-study-v1", "synthetic": False,
                "source_real_enterprise": True, "scan": {"overflow": 1},
                "partitions": {}, "labels": {}, "methods": {}, "limitations": []}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for endpoint, attribute, report in reports:
                with self.subTest(endpoint=endpoint):
                    path.write_text(json.dumps(report).replace('"overflow": 1', '"overflow": 1e999'), encoding="utf-8")
                    with patch.object(research, attribute, path):
                        self.assertEqual(TestClient(create_app()).get(endpoint).status_code, 503)

    def test_real_model_report_is_frozen_public_and_fails_clearly_when_missing(self):
        report = {"schema_version": "real-auth-model-study-v1", "synthetic": False,
                  "datasets": {"fixture": {}}, "protocol": {}, "limitations": ["Fixture only"]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            runtime = Path(directory) / "unused-runtime"
            app = create_app(runtime)
            with patch.object(research, "REAL_AUTH_MODELS_PATH", path):
                self.assertEqual(TestClient(app).get("/api/research/real-auth-models").status_code, 503)
                path.write_text(json.dumps(report), encoding="utf-8")
                response = TestClient(app).get("/api/research/real-auth-models")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), report)
                self.assertEqual(response.headers["x-content-type-options"], "nosniff")
                report["synthetic"] = True
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertEqual(TestClient(app).get("/api/research/real-auth-models").status_code, 503)
            self.assertFalse(runtime.exists())

    def test_training_report_never_fits_or_loads_runtime_model_and_rejects_unfinished_results(self):
        report = {"schema_version": "real-auth-training-v1", "synthetic": False, "status": "measured",
                  "datasets": {"fixture": {}}, "protocol": {}, "limitations": ["Fixture only"]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "training.json"
            runtime = Path(directory) / "unused-runtime"
            app = create_app(runtime)
            with patch.object(research, "TRAINING_REPORT_PATH", path):
                self.assertEqual(TestClient(app).get("/api/research/real-auth-training").status_code, 503)
                path.write_text(json.dumps(report), encoding="utf-8")
                response = TestClient(app).get("/api/research/real-auth-training")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), report)
                report["status"] = "protocol_frozen"
                path.write_text(json.dumps(report), encoding="utf-8")
                self.assertEqual(TestClient(app).get("/api/research/real-auth-training").status_code, 503)
            self.assertFalse(runtime.exists())

    def test_packaged_lanl_study_is_real_data_and_has_no_runtime_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "unused-runtime"
            response = TestClient(create_app(runtime)).get("/api/research/lanl")
            self.assertEqual(response.status_code, 200)
            report = response.json()
            self.assertFalse(report["synthetic"])
            self.assertTrue(report["source_real_enterprise"])
            self.assertEqual(set(report["partitions"]), {"warmup", "validation", "test"})
            self.assertEqual(set(report["methods"]), {"new_user_source", "new_user_destination", "edge_surprise"})
            self.assertFalse(runtime.exists())

    def test_real_enterprise_report_keeps_sparse_label_boundary(self):
        report = {"schema_version": "lanl-study-v1", "synthetic": False, "source_real_enterprise": True,
                  "scan": {}, "partitions": {}, "labels": {"detection_metrics_eligible": False},
                  "methods": {}, "limitations": ["Unlisted events are unlabeled, not verified benign."]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lanl.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            with patch.object(research, "LANL_REPORT_PATH", path):
                response = TestClient(create_app()).get("/api/research/lanl")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), report)
            report["synthetic"] = True
            path.write_text(json.dumps(report), encoding="utf-8")
            with patch.object(research, "LANL_REPORT_PATH", path):
                self.assertEqual(TestClient(create_app()).get("/api/research/lanl").status_code, 503)

    def test_missing_or_nonfinite_real_data_report_fails_without_runtime_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "absent.json"
            for content in (None, '{"invalid": Infinity}', '{"invalid": 1e999}'):
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                with patch.object(research, "LANL_REPORT_PATH", path):
                    response = TestClient(create_app()).get("/api/research/lanl")
                self.assertEqual(response.status_code, 503)
                self.assertIn("LANL_STUDY.md", response.json()["detail"])

    def test_packaged_study_is_served_with_its_research_boundary(self):
        response = TestClient(create_app()).get("/api/research/uncertainty")
        self.assertEqual(response.status_code, 200)
        report = response.json()
        self.assertTrue(report["synthetic"])
        self.assertFalse(report["protocol"]["runtime_model_replaced"])
        self.assertFalse(report["protocol"]["runtime_authorization_changed"])
        self.assertEqual(set(report["summary"]), {"iid", "remote_work", "telemetry_masking", "label_shift"})

    def test_frozen_report_is_public_and_does_not_initialize_runtime_models(self):
        report = {"schema_version": "uncertainty-study-v1", "synthetic": True, "summary": {}, "runs": [], "limitations": ["Fixture only"]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            app = create_app(Path(directory) / "unused-data")
            with patch.object(research, "REPORT_PATH", path):
                response = TestClient(app).get("/api/research/uncertainty")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), report)
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertFalse((Path(directory) / "unused-data").exists())

    def test_missing_malformed_nonfinite_or_unsupported_evidence_fails_clearly(self):
        app = create_app()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for value in (None, "{", "[]", '{"synthetic": false}', '{"value": NaN}', '{"value": 1e999}'):
                with self.subTest(value=value):
                    if value is not None:
                        path.write_text(value, encoding="utf-8")
                    with patch.object(research, "REPORT_PATH", path):
                        response = TestClient(app).get("/api/research/uncertainty")
                    self.assertEqual(response.status_code, 503)
                    self.assertIn("uncertainty_study.py", response.json()["detail"])

    def test_oversized_evidence_is_rejected_before_json_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(b" " * 33)
            with patch.object(research, "REPORT_PATH", path), patch.object(research, "MAX_REPORT_BYTES", 32):
                self.assertEqual(TestClient(create_app()).get("/api/research/uncertainty").status_code, 503)
