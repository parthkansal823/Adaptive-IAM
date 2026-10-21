import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from backend.app.main import create_app
from backend.app import research


class FrozenResearchTests(unittest.TestCase):
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
            for content in (None, '{"invalid": Infinity}'):
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
            for value in (None, "{", "[]", '{"synthetic": false}', '{"value": NaN}'):
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
