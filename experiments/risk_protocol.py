"""Validation-matched policy, repeated retraining and fixed-bin calibration study.

This is a new prespecified synthetic study, never a deployment model replacement.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.risk import RiskEngine, dataset, metrics  # noqa: E402

SEEDS = [20261020, 20261021, 20261022, 20261023, 20261024]


def reliability(y, probability, bins=10):
    """Fixed equal-width bins; empty bins remain visible, ECE is descriptive."""
    p = np.asarray(probability, dtype=float)
    labels = np.asarray(y)
    if not isinstance(bins, int) or bins < 1 or not len(labels) or p.shape != labels.shape:
        raise ValueError("Reliability requires aligned nonempty arrays and positive bin count")
    if not np.isfinite(p).all() or np.any((p < 0) | (p > 1)):
        raise ValueError("Probabilities must be finite and within [0,1]")
    assignment = np.minimum((p*bins).astype(int), bins-1)
    rows, ece = [], 0.0
    for i in range(bins):
        mask = assignment == i
        count = int(mask.sum())
        predicted = float(p[mask].mean()) if count else None
        observed = float(labels[mask].mean()) if count else None
        gap = abs(predicted-observed) if count else None
        if count:
            ece += count/len(y)*gap
        rows.append({"lower": i/bins, "upper": (i+1)/bins, "count": count,
                     "mean_probability": predicted, "observed_positive_rate": observed,
                     "absolute_gap": gap})
    return {"definition": f"{bins} fixed equal-width [0,1] bins, last bin inclusive",
            "ece": float(ece), "bins": rows}


def matched_threshold(y, probability, target):
    """Largest observed positive score satisfying target recall; no test access."""
    scores, labels = np.asarray(probability, dtype=float), np.asarray(y)
    if scores.shape != labels.shape or not np.isfinite(scores).all() or not 0 < target <= 1:
        raise ValueError("Threshold matching requires aligned finite scores and a target in (0,1]")
    positive = np.sort(scores[labels == 1])[::-1]
    if not len(positive):
        raise ValueError("Threshold selection requires positive validation labels")
    required = max(1, int(np.ceil(target*len(positive)-1e-12)))
    return float(positive[min(required, len(positive))-1])


def fit_blend(x, y, seed):
    lr = make_pipeline(StandardScaler(), LogisticRegression(C=.7, class_weight="balanced", max_iter=400, random_state=seed))
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, min_samples_leaf=12,
                                class_weight="balanced", random_state=seed, n_jobs=1)
    lr.fit(x, y)
    rf.fit(x, y)
    return lambda rows: .4*lr.predict_proba(rows)[:, 1]+.6*rf.predict_proba(rows)[:, 1]


def classification_threshold(y, probability):
    """Exact validation operating points give both representations equal tuning."""
    scores = np.asarray(probability, dtype=float)
    if scores.shape != np.asarray(y).shape or not len(scores) or not np.isfinite(scores).all():
        raise ValueError("Classification selection requires aligned finite nonempty scores")
    return float(max(np.unique(scores), key=lambda t: (f1_score(y, scores >= t), t)))


def measure(y, p, threshold, low, high):
    curve = reliability(y, p)
    return {**metrics(y, p, threshold, low, high), "fixed_bin_ece": curve["ece"],
            "average_precision_pr_auc": float(average_precision_score(y, p)),
            "reliability": curve}


def one_seed(seed):
    started = time.perf_counter()
    x, y = dataset(seed, n=10000)
    train, cal, selection, test = slice(0, 6000), slice(6000, 7000), slice(7000, 8000), slice(8000, 10000)
    raw = fit_blend(x[train], y[train], seed)
    calibrator = LogisticRegression(C=1000, max_iter=400, random_state=seed)
    calibrator.fit(RiskEngine.logits(raw(x[cal])), y[cal])
    calibrated = lambda rows: calibrator.predict_proba(RiskEngine.logits(raw(rows)))[:, 1]
    ps, cs = raw(x[selection]), calibrated(x[selection])
    slope = float(calibrator.coef_[0, 0])
    selected = slope > 0 and brier_score_loss(y[selection], cs) < brier_score_loss(y[selection], ps)
    candidate = calibrated if selected else raw
    cs = candidate(x[selection])
    raw_classification = classification_threshold(y[selection], ps)
    candidate_classification = classification_threshold(y[selection], cs)
    baseline_target = float(np.mean(ps[y[selection] == 1] >= .3))
    # Both methods receive the same quantile selection rule and target. This avoids
    # attributing a threshold optimization only afforded to one method to calibration.
    low_raw = matched_threshold(y[selection], ps, baseline_target)
    low_calibrated = matched_threshold(y[selection], cs, baseline_target)
    map_cutoff = lambda cutoff: float(calibrator.predict_proba(RiskEngine.logits(np.asarray([cutoff])))[:, 1][0]) if selected else cutoff
    high_mapped = map_cutoff(.7)
    pt, ct = raw(x[test]), candidate(x[test])
    return {"seed": seed, "dataset_sha256": hashlib.sha256(x.tobytes()+y.tobytes()).hexdigest(),
            "full_fit_and_prediction_seconds": time.perf_counter()-started,
            "partitions": {"train": 6000, "calibration": 1000, "selection": 1000, "test": 2000},
            "test_prevalence": float(y[test].mean()), "calibration_retained": bool(selected), "calibrator_logit_slope": slope,
            "selection": {"baseline_policy_recall_target": baseline_target,
                          "raw_matched_low": low_raw, "candidate_matched_low": low_calibrated,
                          "mapped_high": high_mapped, "raw_classification_threshold": raw_classification,
                          "candidate_classification_threshold": candidate_classification,
                          "raw_matched_recall": float(np.mean(ps[y[selection] == 1] >= low_raw)),
                          "candidate_matched_recall": float(np.mean(cs[y[selection] == 1] >= low_calibrated))},
            "paper_baseline": measure(y[test], pt, .5, .3, .7),
            "raw_validation_matched": measure(y[test], pt, raw_classification, low_raw, .7),
            "calibrated_validation_matched": measure(y[test], ct, candidate_classification, low_calibrated, high_mapped),
            "calibrated_80percent_policy": measure(y[test], ct, candidate_classification,
                                                    matched_threshold(y[selection], cs, .8), .7),
            "matched_classification_decisions_identical": bool(np.array_equal(pt >= raw_classification, ct >= candidate_classification)),
            "matched_policy_decisions_identical": bool(np.array_equal(pt >= low_raw, ct >= low_calibrated)),
            "matched_block_decisions_identical": bool(np.array_equal(pt >= .7, ct >= high_mapped))}


def summarize(runs):
    fields = ["f1", "roc_auc", "brier_score", "fixed_bin_ece", "average_precision_pr_auc", "suspicious_challenge_or_block_recall", "legitimate_friction_rate"]
    models = ["paper_baseline", "raw_validation_matched", "calibrated_validation_matched", "calibrated_80percent_policy"]
    summary = {}
    for model in models:
        summary[model] = {}
        for field in fields:
            values = np.asarray([r[model][field] for r in runs])
            summary[model][field] = {"mean": float(values.mean()), "sample_std": float(values.std(ddof=1)),
                                      "minimum": float(values.min()), "maximum": float(values.max())}
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT/"experiments/risk-protocol.json")
    args = parser.parse_args()
    runs = []
    for seed in SEEDS:
        runs.append(one_seed(seed))
        print(f"Completed frozen retraining seed {seed}", flush=True)
    report = {"protocol": {"synthetic": True, "runtime_model_replaced": False,
                           "seeds": SEEDS, "retraining": "Independent dataset and full fit per seed, including calibration and selection",
                           "test_used_for_selection": False, "matched_target": "Raw paper policy validation recall at 0.3, same target and largest feasible threshold for both methods",
                           "calibration_selection": "Positive sigmoid slope and lower selection-partition Brier loss; otherwise retain raw probabilities",
                           "classification_control": "Both methods maximize F1 on identical unique validation-score operating points, highest threshold breaks ties; baseline retains paper threshold 0.5",
                           "high_cutoff": "Map raw 0.7 through fitted monotone calibrator to isolate identical block decisions",
                           "pr_auc_definition": "Average precision, not trapezoidal interpolation",
                           "aggregation": "Five prespecified runs; means/sample standard deviations/ranges, not population confidence intervals"},
              "environment": {"python": platform.python_version(), "platform": platform.platform(),
                              **{name: importlib.metadata.version(name) for name in ["numpy", "scikit-learn", "joblib"]}},
              "runs": runs, "summary": summarize(runs),
              "limitations": ["All labels remain synthetic and reflect the same generator.",
                              "Independent retraining seeds do not establish cross-organization validity.",
                              "Matching validation recall is not a guarantee of equal test recall; both outcomes are disclosed.",
                              "Monotone calibration does not change ranking; matched policy decisions can be identical.",
                              "Reliability/ECE depend on fixed bin definitions and finite sample counts.",
                              "This study never chooses a deployment model or threshold from held-out scores."]}
    args.output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "summary": report["summary"]}, indent=2))


if __name__ == "__main__":
    main()
