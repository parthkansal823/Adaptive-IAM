"""Seeded research risk ensemble with validation-only calibration and tuning."""
from __future__ import annotations

import math
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, brier_score_loss, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import PolynomialFeatures, StandardScaler

FEATURES = ["unknown_device", "unknown_location", "vpn", "failed_attempts", "hour_deviation", "login_velocity", "young_account", "travel_distance", "resource_sensitivity", "prior_risk"]
SEED = 20261009
ARTIFACT_VERSION = "risk-v4-20261009"


def features(context: dict) -> np.ndarray:
    hour = context.get("hour", 10)
    distance = min(abs(hour - 10), 24 - abs(hour - 10)) / 12
    return np.array([
        not context.get("known_device", True), not context.get("known_location", True),
        context.get("vpn", False), context.get("failed_attempts", 0) / 20,
        distance, context.get("login_velocity", 1) / 30,
        1 - min(context.get("account_age_days", 365) / 365, 1),
        context.get("travel_distance_km", 0) / 20000,
        context.get("sensitivity", .5), context.get("prior_risk", .1),
    ], dtype=float)


def dataset(seed: int = SEED, n: int = 10000):
    """Labels are probabilistic, never copied from policy thresholds or feature rules."""
    rng = np.random.default_rng(seed)
    x = np.column_stack([
        rng.binomial(1, .24, n), rng.binomial(1, .17, n), rng.binomial(1, .19, n),
        np.minimum(rng.poisson(1.4, n), 20) / 20,
        rng.beta(1.8, 4.5, n), np.minimum(rng.poisson(2.1, n), 30) / 30,
        rng.beta(1.1, 5, n), rng.beta(.5, 8, n), rng.uniform(.15, 1, n), rng.beta(1, 6, n),
    ])
    # Latent stochastic process deliberately contains interactions and label noise.
    logit = (-4.8 + 1.35*x[:, 0] + 1.1*x[:, 1] + .55*x[:, 2] + 6*x[:, 3]
             + 1.4*x[:, 4] + 4*x[:, 5] + .6*x[:, 6] + 2.5*x[:, 7]
             + .45*x[:, 8] + 2.5*x[:, 9] + 1.4*x[:, 0]*x[:, 1]
             + 1.8*x[:, 2]*x[:, 4])
    p = .015 + .97 / (1 + np.exp(-logit))
    y = rng.binomial(1, p)
    order = rng.permutation(n)
    return x[order], y[order]


def metrics(y, probability, threshold, low_threshold=.3, high_threshold=.7):
    pred = np.asarray(probability) >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(float(accuracy_score(y, pred)), 6),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(y, probability)), 6),
        "brier_score": round(float(brier_score_loss(y, probability)), 6),
        "threshold": round(float(threshold), 4),
        "confusion_matrix": {"true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp)},
        "friction_rate": round(float(np.mean(np.asarray(probability) >= low_threshold)), 6),
        "legitimate_friction_rate": round(float(np.mean(np.asarray(probability)[y == 0] >= low_threshold)), 6),
        "high_risk_block_rate": round(float(np.mean(np.asarray(probability) >= high_threshold)), 6),
        "suspicious_direct_allow_rate": round(float(np.mean(np.asarray(probability)[y == 1] < low_threshold)), 6),
        "suspicious_challenge_or_block_recall": round(float(np.mean(np.asarray(probability)[y == 1] >= low_threshold)), 6),
        "blocked_legitimate_rate": round(float(np.mean(np.asarray(probability)[y == 0] >= high_threshold)), 6),
        "policy_thresholds": {"low": round(float(low_threshold), 6), "high": round(float(high_threshold), 6)},
    }


class RiskEngine:
    def __init__(self, cache_path: Path | None = None):
        self.version = ARTIFACT_VERSION
        if cache_path and cache_path.exists():
            try:
                saved = joblib.load(cache_path)
                if saved.get("version") == self.version:
                    self.__dict__.update(saved)
                    return
            except (ValueError, EOFError, KeyError):
                pass
        self.train()
        if cache_path:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.__dict__, cache_path)

    def train(self):
        x, y = dataset()
        # Split BEFORE fitting every learned transformation. Test remains untouched.
        train_x, train_y = x[:6000], y[:6000]
        calibration_x, calibration_y = x[6000:7000], y[6000:7000]
        selection_x, selection_y = x[7000:8000], y[7000:8000]
        test_x, test_y = x[8000:], y[8000:]
        self.baseline_lr = make_pipeline(StandardScaler(), LogisticRegression(C=.7, class_weight="balanced", max_iter=400, random_state=SEED))
        self.baseline_lr.fit(train_x, train_y)
        self.lr = make_pipeline(PolynomialFeatures(degree=2, interaction_only=True, include_bias=False), StandardScaler(), LogisticRegression(C=.2, class_weight="balanced", max_iter=400, random_state=SEED))
        self.rf = RandomForestClassifier(n_estimators=100, max_depth=10, min_samples_leaf=12, class_weight="balanced", random_state=SEED, n_jobs=1)
        self.lr.fit(train_x, train_y)
        self.rf.fit(train_x, train_y)
        baseline_selection = .4*self.baseline_lr.predict_proba(selection_x)[:, 1]+.6*self.rf.predict_proba(selection_x)[:, 1]
        interaction_selection = self.raw(selection_x)
        self.use_interactions = roc_auc_score(selection_y, interaction_selection) > roc_auc_score(selection_y, baseline_selection)
        if not self.use_interactions:
            self.lr = self.baseline_lr
        raw_cal = self.raw(calibration_x)
        self.calibrator = LogisticRegression(C=1000, max_iter=400, random_state=SEED)
        self.calibrator.fit(self.logits(raw_cal), calibration_y)
        raw_selection = self.raw(selection_x)
        calibrated_selection = self.calibrator.predict_proba(self.logits(raw_selection))[:, 1]
        self.use_calibration = brier_score_loss(selection_y, calibrated_selection) < brier_score_loss(selection_y, raw_selection)
        p_select = self.probabilities(selection_x)
        candidates = np.linspace(.05, .75, 141)
        self.threshold = float(max(candidates, key=lambda t: (f1_score(selection_y, p_select >= t), t)))
        # Predeclared conservative policy target, selected on validation only.
        # Largest threshold satisfying >=80% suspicious detection minimizes friction.
        suspicious_validation = p_select[selection_y == 1]
        self.low_threshold = min(.699, float(np.nextafter(np.quantile(suspicious_validation, .2, method="lower"), 0)))
        self.high_threshold = .7
        legitimate = train_x[train_y == 0]
        self.mean = legitimate.mean(axis=0)
        self.inverse_covariance = np.linalg.pinv(np.cov(legitimate, rowvar=False) + np.eye(len(FEATURES))*.025)
        raw_test = .4*self.baseline_lr.predict_proba(test_x)[:, 1]+.6*self.rf.predict_proba(test_x)[:, 1]
        calibrated_test = self.probabilities(test_x)
        timings = []
        for row in test_x[:80]:
            start = time.perf_counter()
            self.probabilities(row.reshape(1, -1))
            timings.append((time.perf_counter() - start)*1000)
        self.report = {
            "dataset": {"name": "Seeded synthetic contextual login events", "synthetic": True, "seed": SEED, "total": len(y), "train": 6000, "validation": 2000, "calibration": 1000, "threshold_selection": 1000, "test": 2000, "test_suspicious_prevalence": round(float(test_y.mean()), 6), "feature_names": FEATURES},
            "method": {"ensemble": "0.4 × logistic regression + 0.6 × random forest", "improvement": "Validation-gated pairwise interaction features; sigmoid probability calibration", "interaction_features_selected": bool(self.use_interactions), "candidate_selection": "Retain interaction candidate only when selection-partition ROC AUC beats original blend; otherwise original model remains", "calibration": "Platt sigmoid fitted on calibration partition only; retained only if selection-partition Brier error improves", "calibration_selected": bool(self.use_calibration), "threshold_selection": "Maximum F1 on separate validation selection partition", "authentication_policy_selection": "Largest calibrated challenge threshold meeting >=80% suspicious detection on selection partition, minimizing legitimate friction; high cutoff remains 0.7", "validation_policy_recall": round(float(np.mean(suspicious_validation >= self.low_threshold)), 6), "paper_tier_thresholds": {"low": .3, "high": .7}, "tier_thresholds": {"low": round(self.low_threshold, 6), "high": self.high_threshold}, "classification_threshold_is_not_tier_threshold": True, "split_before_preprocessing": True},
            "baseline": {"name": "Paper blend, raw probabilities, 0.5 classification threshold", **metrics(test_y, raw_test, .5)},
            "improved": {"name": "Validation-selected blend + calibrated probabilities + conservative challenge policy", **metrics(test_y, calibrated_test, self.threshold, self.low_threshold, self.high_threshold)},
            "rejected_policy_ablation": {"name": "Calibrated probability with unchanged paper 0.3/0.7 cutoffs", **metrics(test_y, calibrated_test, self.threshold), "reason": "Calibration reduced probabilities; unchanged cutoffs lose suspicious challenge recall, so this policy is not deployed."},
            "majority_baseline": {"name": "Always predict legitimate", **metrics(test_y, np.zeros(len(test_y)), .5), "interpretation": "Imbalanced-label accuracy alone is misleading; this baseline detects no suspicious events."},
            "static_auth_baseline": {"name": "Valid credential always directly allowed", "suspicious_direct_allow_rate": 1.0, "suspicious_challenge_or_block_recall": 0.0, "legitimate_friction_rate": 0.0, "interpretation": "Conceptual policy baseline assumes credentials already passed, with no context challenge."},
            "latency": {"scope": "Single-row model inference, local CPU, excludes HTTP and model training", "samples": len(timings), "median_ms": round(float(np.median(timings)), 3), "p95_ms": round(float(np.percentile(timings, 95)), 3)},
            "limitations": ["Synthetic labels measure this generator, not real-world credential theft detection.", "The paper reports projected benchmarks; these are fresh empirical synthetic measurements.", "Calibration reduces probability error; any accuracy/recall tradeoff is reported without suppressing regressions.", "Client-supplied context is suitable for a local demo; production must derive device, network and behavioral signals server-side.", "No automatic retraining from votes: approval labels are not ground-truth malicious-login labels.", "Authentication challenge cutoff is validation-tuned for >=80% suspicious detection; evaluation maximum-F1 classification threshold is separate.", "Validation recall target is not a guarantee of held-out or real-world detection."],
        }

    @staticmethod
    def logits(p):
        p = np.clip(p, 1e-6, 1-1e-6)
        return np.log(p / (1-p)).reshape(-1, 1)

    def raw(self, x):
        return .4*self.lr.predict_proba(x)[:, 1] + .6*self.rf.predict_proba(x)[:, 1]

    def probabilities(self, x):
        raw = self.raw(x)
        return self.calibrator.predict_proba(self.logits(raw))[:, 1] if self.use_calibration else raw

    def assess(self, context: dict):
        start = time.perf_counter()
        row = features(context).reshape(1, -1)
        lr = float(self.lr.predict_proba(row)[0, 1])
        rf = float(self.rf.predict_proba(row)[0, 1])
        raw = .4*lr + .6*rf
        score = float(self.calibrator.predict_proba(self.logits(np.array([raw])))[0, 1]) if self.use_calibration else raw
        deviation = row[0] - self.mean
        anomaly = math.sqrt(max(0, float(deviation @ self.inverse_covariance @ deviation)))
        tier = "low" if score < self.low_threshold else "medium" if score < self.high_threshold else "high"
        values = [("Device familiarity", context.get("known_device", True), "positive" if context.get("known_device", True) else "negative"),
                  ("Location familiarity", context.get("known_location", True), "positive" if context.get("known_location", True) else "negative"),
                  ("VPN / proxy", context.get("vpn", False), "negative" if context.get("vpn", False) else "neutral"),
                  ("Recent failed attempts", context.get("failed_attempts", 0), "negative" if context.get("failed_attempts", 0) else "positive"),
                  ("Login hour", context.get("hour", 10), "negative" if row[0, 4] > .4 else "positive"),
                  ("Resource sensitivity", context.get("sensitivity", .5), "negative" if context.get("sensitivity", .5) >= .8 else "neutral"),
                  ("Mahalanobis distance", round(anomaly, 3), "negative" if anomaly > 3 else "neutral")]
        alternatives = [("known_device", True), ("known_location", True), ("vpn", False), ("failed_attempts", 0), ("hour", 10), ("sensitivity", .15)]
        alternate_rows = [features({**context, field: value}) for field, value in alternatives]
        alternate_scores = self.probabilities(np.asarray(alternate_rows))
        signals = [{"label": a, "value": b, "impact": c, "counterfactual_delta": round(score-float(alternate_scores[i]), 6) if i < len(alternate_scores) else None} for i, (a, b, c) in enumerate(values)]
        return {"score": round(score, 6), "tier": tier, "action": {"low": "allow", "medium": "mfa", "high": "block"}[tier],
                "signals": signals, "explanation_method": "One feature changed to a benign reference at a time; correlated features make deltas non-additive. Not SHAP or causal attribution.",
                "components": {"logistic_regression": round(lr, 6), "random_forest": round(rf, 6), "raw_ensemble": round(raw, 6), "calibrated": round(score, 6), "mahalanobis_distance": round(anomaly, 3)},
                "latency_ms": round((time.perf_counter()-start)*1000, 3)}
