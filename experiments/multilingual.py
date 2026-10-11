"""Frozen runtime language diagnostics and optional independently collected labels."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.nlp import JustificationEngine  # noqa: E402
from scripts.annotation_eval import catalog, digest, reconcile  # noqa: E402


def metrics(rows, field):
    positives = [r for r in rows if r["reference_label"] == "suspicious"]
    negatives = [r for r in rows if r["reference_label"] == "legitimate"]
    definite = [r for r in rows if r["reference_label"] != "uncertain"]
    tp = sum(r["assessment"][field] == "suspicious" for r in positives)
    fp = sum(r["assessment"][field] == "suspicious" for r in negatives)
    abstained = sum(r["assessment"][field] == "uncertain" for r in rows)
    # Abstentions remain in denominators; they are not silently counted correct.
    correct = sum(r["assessment"][field] == r["reference_label"] for r in definite)
    return {"total": len(rows), "reference_suspicious": len(positives), "reference_legitimate": len(negatives),
            "reference_uncertain": len(rows)-len(definite), "suspicious_flagged": tp, "legitimate_flagged": fp,
            "suspicious_flag_rate": tp/len(positives) if positives else None,
            "legitimate_flag_rate": fp/len(negatives) if negatives else None,
            "abstentions": abstained, "definitive_coverage": (len(rows)-abstained)/len(rows),
            "agreement_on_definite_reference_including_model_abstentions": correct/len(definite) if definite else None}


def evaluate(cases, reference, engine, repetitions=5):
    engine.assess("Read-only report review for an approved business ticket.")
    rows = []
    for case in cases:
        elapsed, assessment = [], None
        for _ in range(repetitions):
            started = time.perf_counter()
            assessment = engine.assess(case["text"])
            elapsed.append((time.perf_counter()-started)*1000)
        rows.append({"case_id": case["id"], "language": case["language"], "semantic_group": case["semantic_group"],
                     "reference_label": reference[case["id"]], "assessment": assessment,
                     "latency_ms": {"repetitions": repetitions, "median": statistics.median(elapsed),
                                    "minimum": min(elapsed), "maximum": max(elapsed)}})
    by_language = {}
    for language in sorted({row["language"] for row in rows}):
        selected = [row for row in rows if row["language"] == language]
        by_language[language] = {"classifier": metrics(selected, "classifier_label"), "runtime_advisory": metrics(selected, "label"),
                                 "median_case_latency_ms": statistics.median(row["latency_ms"]["median"] for row in selected)}
    return {"classifier": metrics(rows, "classifier_label"), "runtime_advisory": metrics(rows, "label"), "by_language": by_language, "cases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT/"experiments/multilingual_cases.json")
    parser.add_argument("--annotations", type=Path, nargs="*", default=[])
    parser.add_argument("--adjudication", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT/"experiments/multilingual-results.json")
    args = parser.parse_args()
    cases = catalog(args.catalog)
    if args.annotations:
        reconciled = reconcile(cases, [json.loads(path.read_text(encoding="utf-8")) for path in args.annotations],
                               json.loads(args.adjudication.read_text(encoding="utf-8")) if args.adjudication else None)
        reference = {r["case_id"]: r["label"] for r in reconciled["cases"]}
        mode, annotation = "human_attested_text_intent", reconciled["annotation"]
    else:
        if args.adjudication:
            raise ValueError("Adjudication cannot be used without independent annotation inputs")
        reference = {r["id"]: r["author_expectation"] for r in cases}
        mode, annotation = "author_diagnostics", {"independent_human_labels_collected": False, "status": "pending external human collection"}
    engine = JustificationEngine()
    report = {"protocol": {"mode": mode, "catalog_sha256": digest(cases), "model_and_threshold_changed": False,
                            "human_authorization_required_for_all_cases": True, "bert_measured": bool(engine.bert),
                            "latency": "Five warm sequential CPU assessments per case; initialization excluded; full runtime path included",
                            "semantic_groups": len({c["semantic_group"] for c in cases}),
                            "languages": sorted({c["language"] for c in cases})},
              "annotation": annotation, "environment": {"python": platform.python_version(), "platform": platform.platform(),
                 **{name: importlib.metadata.version(name) for name in ["numpy", "scikit-learn"]}},
              **evaluate(cases, reference, engine),
              "limitations": ["18 translated author-created diagnostic items, not independent deployment or attack data.",
                              "Six semantic groups are shared across languages; individual rows are not independent samples.",
                              "Human intent judgments, if supplied, are not verified attack outcomes or access votes.",
                              "Attestations cannot prove human identity or independence; collection must be supervised externally.",
                              "Classifier scores are uncalibrated class support; handwritten flags and abstention are separate.",
                              "No BERT benefit is claimed when a labeled local model is unavailable.",
                              "No training, threshold selection or authorization change is made from these diagnostics."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "mode": mode, "runtime_advisory": report["runtime_advisory"], "by_language": report["by_language"]}))


if __name__ == "__main__":
    main()
