"""Independent synthetic study: select on validation, then reveal a fresh test set.

This study exports evidence, not a replacement production model. It compares
model families at the same validation target for suspicious-event challenges.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, f1_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import PolynomialFeatures, StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.risk import SEED, RiskEngine, dataset, metrics  # noqa: E402

STUDY_SEED = SEED + 500


def tune(y, p):
    classification = float(max(np.linspace(.05, .75, 141), key=lambda t: (f1_score(y, p >= t), t)))
    low = min(.699, float(np.nextafter(np.quantile(p[y == 1], .2, method="lower"), 0)))
    return classification, low


def main():
    x, y = dataset(STUDY_SEED, n=12000)
    partitions = {"train": (0, 7200), "calibration": (7200, 8400), "selection": (8400, 9600), "test": (9600, 12000)}
    tx, ty, cx, cy, vx, vy = x[:7200], y[:7200], x[7200:8400], y[7200:8400], x[8400:9600], y[8400:9600]
    for name, (start, stop) in partitions.items():
        if len(np.unique(y[start:stop])) != 2:
            raise ValueError(f"Both labels required in {name}")
    lr = make_pipeline(StandardScaler(), LogisticRegression(C=.7, class_weight="balanced", max_iter=400, random_state=STUDY_SEED))
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, min_samples_leaf=12, class_weight="balanced", random_state=STUDY_SEED, n_jobs=1)
    lr.fit(tx, ty)
    rf.fit(tx, ty)
    interaction = make_pipeline(PolynomialFeatures(degree=2, interaction_only=True, include_bias=False), StandardScaler(), LogisticRegression(C=.7, max_iter=400, random_state=STUDY_SEED))
    histogram = HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=15, min_samples_leaf=30, l2_regularization=1., learning_rate=.1, early_stopping=False, random_state=STUDY_SEED)
    interaction.fit(tx, ty)
    histogram.fit(tx, ty)
    # Model families and parameters above are fixed before any test inspection.
    recipes = {
        "calibrated_paper_blend": lambda rows: .4*lr.predict_proba(rows)[:, 1]+.6*rf.predict_proba(rows)[:, 1],
        "unweighted_interaction_logistic": lambda rows: interaction.predict_proba(rows)[:, 1],
        "histogram_gradient_boosting": lambda rows: histogram.predict_proba(rows)[:, 1],
    }
    frozen = {}
    for name, predict in recipes.items():
        calibrator = LogisticRegression(C=1000, max_iter=400, random_state=STUDY_SEED)
        calibrator.fit(RiskEngine.logits(predict(cx)), cy)
        raw = predict(vx)
        calibrated = calibrator.predict_proba(RiskEngine.logits(raw))[:, 1]
        use_calibration = brier_score_loss(vy, calibrated) < brier_score_loss(vy, raw)
        probability = calibrated if use_calibration else raw
        threshold, low = tune(vy, probability)
        frozen[name] = {"predict": predict, "calibrator": calibrator, "calibration_selected": bool(use_calibration), "threshold": threshold, "low_threshold": low,
                        "validation": metrics(vy, probability, threshold, low)}
    reference = frozen["calibrated_paper_blend"]["validation"]
    eligible = [name for name, item in frozen.items()
                if item["validation"]["roc_auc"] >= reference["roc_auc"]
                and item["validation"]["legitimate_friction_rate"] <= reference["legitimate_friction_rate"]]
    selected = min(eligible, key=lambda name: (frozen[name]["validation"]["brier_score"], name))
    # The selection decision is now frozen. Reveal held-out outcomes exactly once.
    test_x, test_y = x[9600:], y[9600:]
    candidates = {}
    for name, item in frozen.items():
        raw = item["predict"](test_x)
        p = item["calibrator"].predict_proba(RiskEngine.logits(raw))[:, 1] if item["calibration_selected"] else raw
        candidates[name] = {key: item[key] for key in ["calibration_selected", "threshold", "low_threshold", "validation"]}
        candidates[name]["test"] = metrics(test_y, p, item["threshold"], item["low_threshold"])
    report = {
        "study": "Fresh independent model-family comparison",
        "dataset": {"synthetic": True, "seed": STUDY_SEED, "total": len(y), "sha256": hashlib.sha256(x.tobytes()+y.tobytes()).hexdigest(),
                    "partitions": {name: {"events": stop-start, "suspicious": int(y[start:stop].sum())} for name, (start, stop) in partitions.items()}},
        "protocol": {"selection": "Lowest validation Brier score among candidates with validation ROC AUC >= calibrated paper blend and no greater legitimate friction at >=80% validation suspicious challenge detection",
                     "test_used_for_selection": False, "classification_selection": "Maximum validation F1; distinct from authentication policy", "high_threshold": .7,
                     "runtime_model_replaced": False, "purpose": "Independent evidence for a future candidate; deployment requires context-signal and real-dataset validation"},
        "selected_by_validation": selected,
        "candidates": candidates,
        "environment": {"python": platform.python_version(), "platform": platform.platform(), **{name: importlib.metadata.version(name) for name in ["numpy", "scikit-learn"]}},
        "limitations": ["Same synthetic generator family; independent seed is not real-world generalization.", "One fresh train/test split, not nested cross-validation or retraining uncertainty.", "Candidates and calibration selected on one validation partition; held-out outcomes may regress.", "Reported selection does not automatically replace the deployed risk-v4 model.", "Interaction logistic uses observed features only, but synthetic generator structure can favor this family."],
    }
    target = ROOT / "experiments/candidate-study.json"
    target.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"output": str(target), "selected_by_validation": selected, "held_out": {name: item["test"] for name, item in candidates.items()}}, indent=2))


if __name__ == "__main__":
    main()
