"""Reproduce the frozen synthetic benchmark: python experiments/evaluate.py."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.nlp import JustificationEngine
from backend.app.risk import RiskEngine
from backend.app.store import stamp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "experiments" / "results.json")
    args = parser.parse_args()
    model = RiskEngine()  # Always re-train; do not silently reuse cached evidence.
    report = model.report
    report["nlp"] = JustificationEngine().report
    report["generated_at"] = stamp()
    report["model_version"] = model.version
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(f"Evidence saved to {args.output}")
    print(json.dumps({key: {metric: report[key][metric] for metric in ("accuracy", "precision", "recall", "f1", "roc_auc", "brier_score", "threshold")} for key in ("baseline", "improved")}, indent=2))


if __name__ == "__main__":
    main()
