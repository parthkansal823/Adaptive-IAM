"""Public, frozen research evidence. Reading a report never trains a model."""
import json
from pathlib import Path

from fastapi import HTTPException
from fastapi.responses import JSONResponse

REPORT_PATH = Path(__file__).resolve().parents[2] / "experiments/uncertainty-study.json"
LANL_REPORT_PATH = Path(__file__).resolve().parents[2] / "experiments/lanl-study.json"
MAX_REPORT_BYTES = 2 * 1024 * 1024


def _reject_constant(value):
    raise ValueError("Non-finite research value")


def install_research(api):
    @api.get("/api/research/uncertainty")
    def uncertainty():
        try:
            with REPORT_PATH.open("rb") as source:
                data = source.read(MAX_REPORT_BYTES + 1)
            if len(data) > MAX_REPORT_BYTES:
                raise ValueError("Oversized report")
            report = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
            if (not isinstance(report, dict) or report.get("schema_version") != "uncertainty-study-v1"
                    or report.get("synthetic") is not True or not isinstance(report.get("summary"), dict)
                    or not isinstance(report.get("runs"), list) or not isinstance(report.get("limitations"), list)):
                raise ValueError("Unsupported report")
        except (OSError, ValueError, UnicodeError):
            raise HTTPException(503, "The uncertainty study is unavailable. Generate experiments/uncertainty-study.json with experiments/uncertainty_study.py and retry.") from None
        return JSONResponse(report, headers={"Cache-Control": "public, max-age=60", "X-Content-Type-Options": "nosniff"})

    @api.get("/api/research/lanl")
    def lanl():
        try:
            with LANL_REPORT_PATH.open("rb") as source:
                data = source.read(MAX_REPORT_BYTES + 1)
            if len(data) > MAX_REPORT_BYTES:
                raise ValueError("Oversized report")
            report = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
            if (not isinstance(report, dict) or report.get("schema_version") != "lanl-study-v1"
                    or report.get("synthetic") is not False or report.get("source_real_enterprise") is not True
                    or not all(isinstance(report.get(key), dict) for key in ("scan", "partitions", "labels", "methods"))
                    or not isinstance(report.get("limitations"), list)):
                raise ValueError("Unsupported report")
        except (OSError, ValueError, UnicodeError):
            raise HTTPException(503, "The LANL study is unavailable. See scripts/evaluate_lanl.py --help and docs/LANL_STUDY.md to reproduce the bounded real-data study.") from None
        return JSONResponse(report, headers={"Cache-Control": "public, max-age=60", "X-Content-Type-Options": "nosniff"})
