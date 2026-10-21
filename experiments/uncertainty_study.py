"""Frozen synthetic conformal-set and conservative step-up stress study.

No runtime model, authorization rule or previous research artifact is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import platform
import sys

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.risk import FEATURES, RiskEngine, dataset  # noqa: E402
from experiments.risk_protocol import fit_blend, matched_threshold  # noqa: E402

SCHEMA_VERSION = "uncertainty-study-v1"
SEEDS = [20261101, 20261102, 20261103, 20261104, 20261105]
ALPHA = .1
PARTITIONS = {"train": [0, 6000], "probability_calibration": [6000, 7000],
              "selection": [7000, 8000], "conformal_calibration": [8000, 10000], "iid_test": [10000, 12000]}
METHODS = {
    "baseline": "Validation-selected low threshold meeting at least 80% synthetic suspicious detection.",
    "marginal_gate": "Baseline direct allow AND marginal prediction set exactly {legitimate}; otherwise step up.",
    "class_conditional_gate": "Baseline direct allow AND class-conditional set exactly {legitimate}; otherwise step up.",
    "always_challenge": "Every event requires challenge; trivial detection/friction upper-bound control.",
}
CONDITIONS = {
    "iid": {"title": "IID holdout", "n": 2000,
            "construction": "Untouched final partition from the same simulator; independent of all fitting and selection.",
            "guarantee_scope": "Exchangeability supports marginal coverage and label-conditional coverage for their respective methods; not a per-event certainty claim."},
    "remote_work": {"title": "Remote-work covariate shift", "n": 2000,
                    "construction": "Fresh 40000-row pool; accept with probability (1+3*x0+2*x1+2*x2+2*x4)/10 and retain first 2000 accepted rows. Selection uses X only; labels are unchanged.",
                    "guarantee_scope": "Unweighted conformal has no general coverage guarantee after this covariate shift; no density-ratio correction is applied."},
    "telemetry_masking": {"title": "Missing telemetry stress", "n": 2000,
                          "construction": "Paired IID test; for a fixed random 50% of rows, replace columns 0,1,2,7,9 by zero. Retain original simulator labels.",
                          "guarantee_scope": "Measurement corruption changes observed X/Y relationships; original conformal coverage need not transfer."},
    "label_shift": {"title": "Suspicious-prevalence shift", "n": 2000,
                    "construction": "Fresh 40000-row pool; accept all suspicious rows and each legitimate row with probability .25; retain first 2000 accepted rows.",
                    "guarantee_scope": "Pure label-based sampling preserves X conditional on Y. Class-conditional coverage can transfer under this assumption; marginal coverage need not transfer."},
}


def aligned(y, probability):
    labels, p = np.asarray(y), np.asarray(probability, dtype=float)
    if (labels.ndim != 1 or labels.shape != p.shape or not len(labels)
            or not np.isin(labels, [0, 1]).all() or not np.isfinite(p).all()
            or np.any((p < 0) | (p > 1))):
        raise ValueError("Expected aligned nonempty binary labels and finite probabilities in [0,1]")
    return labels.astype(int), p


def conformal_quantile(scores, alpha=ALPHA):
    """Exact ceil((n+1)*(1-alpha)) order statistic, including ties.

    Bounded scores permit q=1 when the rank is unavailable, including n=0.
    Never substitute a lower interpolated quantile that loses finite-sample validity.
    """
    scores = np.asarray(scores, dtype=float)
    if (scores.ndim != 1 or not math.isfinite(alpha) or not 0 < alpha < 1
            or not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1))):
        raise ValueError("Conformal scores must be bounded and alpha must be in (0,1)")
    rank = math.ceil((len(scores) + 1) * (1 - alpha))
    return 1.0 if rank > len(scores) else float(np.partition(scores, rank - 1)[rank - 1])


def fit_conformal(y, probability, alpha=ALPHA):
    labels, p = aligned(y, probability)
    scores = np.where(labels == 1, 1 - p, p)
    marginal = conformal_quantile(scores, alpha)
    conditional = [conformal_quantile(scores[labels == label], alpha) for label in (0, 1)]
    return {"alpha": alpha, "nonconformity": "1 - probability of the observed true label",
            "marginal_quantile": marginal, "class_quantiles": conditional,
            "class_counts": {"legitimate": int((labels == 0).sum()), "suspicious": int((labels == 1).sum())}}


def prediction_sets(probability, quantiles):
    p, q = np.asarray(probability, dtype=float), np.asarray(quantiles, dtype=float)
    if (p.ndim != 1 or q.shape != (2,) or not np.isfinite(p).all() or not np.isfinite(q).all()
            or np.any((p < 0) | (p > 1)) or np.any((q < 0) | (q > 1))):
        raise ValueError("Prediction sets require bounded probabilities and two bounded class quantiles")
    # Column order is [legitimate, suspicious]. Exact <= keeps tied scores covered.
    return np.column_stack((p <= q[0], 1 - p <= q[1]))


def conservative_allow(baseline_allow, sets):
    baseline = np.asarray(baseline_allow)
    sets = np.asarray(sets)
    if baseline.ndim != 1 or baseline.dtype != bool or sets.shape != (len(baseline), 2) or sets.dtype != bool:
        raise ValueError("Expected binary prediction-set membership and baseline decisions")
    return baseline & sets[:, 0] & ~sets[:, 1]


def wilson95(numerator, denominator):
    """Descriptive per-run binomial interval, conditional on the fitted rule."""
    if denominator < 1 or not 0 <= numerator <= denominator:
        raise ValueError("Wilson intervals require a positive count and a valid numerator")
    z = 1.959963984540054
    p = numerator / denominator
    adjustment = 1 + z*z/denominator
    center = (p + z*z/(2*denominator)) / adjustment
    half = z * math.sqrt(p*(1-p)/denominator + z*z/(4*denominator**2)) / adjustment
    return {"numerator": int(numerator), "denominator": int(denominator),
            "lower": max(0.0, center-half), "upper": min(1.0, center+half)}


def policy_metrics(y, allowed, baseline_allow, sets=None):
    labels = np.asarray(y)
    allowed, baseline_allow = np.asarray(allowed), np.asarray(baseline_allow)
    if (labels.ndim != 1 or not len(labels) or not np.isin(labels, [0, 1]).all()
            or allowed.shape != labels.shape or baseline_allow.shape != labels.shape
            or allowed.dtype != bool or baseline_allow.dtype != bool or np.any(allowed & ~baseline_allow)):
        raise ValueError("Policy evaluation requires aligned decisions that never broaden baseline allows")
    legitimate, suspicious = labels == 0, labels == 1
    n0, n1 = int(legitimate.sum()), int(suspicious.sum())
    if not n0 or not n1:
        raise ValueError("Both classes are required for conditional policy metrics")
    n = len(labels)
    counts = {"direct_allow": int(allowed.sum()), "challenge": int((~allowed).sum()),
              "suspicious_direct_allow": int((suspicious & allowed).sum()),
              "suspicious_detection": int((suspicious & ~allowed).sum()),
              "legitimate_friction": int((legitimate & ~allowed).sum()),
              "added_legitimate_friction": int((legitimate & baseline_allow & ~allowed).sum()),
              "added_suspicious_detection": int((suspicious & baseline_allow & ~allowed).sum())}
    fractions = {"suspicious_direct_allow_rate": (counts["suspicious_direct_allow"], n1),
                 "suspicious_detection_rate": (counts["suspicious_detection"], n1),
                 "legitimate_friction_rate": (counts["legitimate_friction"], n0),
                 "challenge_rate": (counts["challenge"], n),
                 "added_legitimate_friction_rate": (counts["added_legitimate_friction"], n0),
                 "added_suspicious_detection_rate": (counts["added_suspicious_detection"], n1)}
    extra = {}
    if sets is not None:
        sets = np.asarray(sets)
        if sets.shape != (n, 2) or sets.dtype != bool:
            raise ValueError("Prediction-set rows must match labels")
        sizes = sets.sum(axis=1)
        covered = sets[np.arange(n), labels.astype(int)]
        counts.update({"covered": int(covered.sum()), "legitimate_covered": int(covered[legitimate].sum()),
                       "suspicious_covered": int(covered[suspicious].sum()), "empty_set": int((sizes == 0).sum()),
                       "both_labels": int((sizes == 2).sum()),
                       "singleton_legitimate": int((sets[:, 0] & ~sets[:, 1]).sum()),
                       "singleton_suspicious": int((~sets[:, 0] & sets[:, 1]).sum())})
        fractions.update({"coverage": (counts["covered"], n), "legitimate_coverage": (counts["legitimate_covered"], n0),
                          "suspicious_coverage": (counts["suspicious_covered"], n1), "empty_set_rate": (counts["empty_set"], n),
                          "both_labels_rate": (counts["both_labels"], n),
                          "singleton_legitimate_rate": (counts["singleton_legitimate"], n),
                          "singleton_suspicious_rate": (counts["singleton_suspicious"], n)})
        extra["mean_set_size"] = float(sizes.mean())
    return {**{name: numerator/denominator for name, (numerator, denominator) in fractions.items()}, **extra,
            "counts": counts, "wilson95": {name: wilson95(*fraction) for name, fraction in fractions.items()}}


def dataset_hash(x, y):
    """Platform-independent numeric byte representation, with shape included."""
    rows = np.asarray(x, dtype="<f8", order="C")
    labels = np.asarray(y, dtype="<i8", order="C")
    header = json.dumps({"x_shape": list(rows.shape), "y_shape": list(labels.shape),
                         "x_dtype": "little-endian float64", "y_dtype": "little-endian int64"}, sort_keys=True).encode()
    return hashlib.sha256(header + b"\n" + rows.tobytes() + labels.tobytes()).hexdigest()


def rejection_sample(x, y, acceptance, rng, count=2000):
    acceptance = np.asarray(acceptance, dtype=float)
    if (count < 1 or acceptance.shape != (len(y),) or len(x) != len(y)
            or not np.isfinite(acceptance).all() or np.any((acceptance < 0) | (acceptance > 1))):
        raise ValueError("Invalid rejection sampling probabilities")
    accepted = np.flatnonzero(rng.random(len(y)) < acceptance)
    if len(accepted) < count:
        raise ValueError("Prespecified candidate pool has insufficient accepted rows; do not silently adapt protocol")
    chosen = accepted[:count]
    return x[chosen].copy(), y[chosen].copy(), {"pool_n": len(y), "accepted_pool_n": len(accepted),
                                             "chosen_indices_sha256": hashlib.sha256(chosen.astype("<i8").tobytes()).hexdigest()}


def masked_telemetry(x, y, seed):
    rows, labels = np.array(x, copy=True), np.array(y, copy=True)
    chosen = np.random.default_rng(seed).choice(len(rows), size=len(rows)//2, replace=False)
    rows[np.ix_(chosen, [0, 1, 2, 7, 9])] = 0
    return rows, labels, {"masked_rows": len(chosen), "masked_columns": [0, 1, 2, 7, 9],
                          "chosen_indices_sha256": hashlib.sha256(np.sort(chosen).astype("<i8").tobytes()).hexdigest()}


def evaluate_condition(x, y, probability, low, conformal, construction=None):
    labels, p = aligned(y, probability)
    baseline = p < low
    marginal = prediction_sets(p, [conformal["marginal_quantile"]]*2)
    conditional = prediction_sets(p, conformal["class_quantiles"])
    methods = {"baseline": policy_metrics(labels, baseline, baseline),
               "marginal_gate": policy_metrics(labels, conservative_allow(baseline, marginal), baseline, marginal),
               "class_conditional_gate": policy_metrics(labels, conservative_allow(baseline, conditional), baseline, conditional),
               "always_challenge": policy_metrics(labels, np.zeros(len(labels), dtype=bool), baseline)}
    return {"n": len(labels), "prevalence": float(labels.mean()), "data_sha256": dataset_hash(x, labels),
            "label_counts": {"legitimate": int((labels == 0).sum()), "suspicious": int((labels == 1).sum())},
            "probability_diagnostics": {"brier_score": float(brier_score_loss(labels, p)), "roc_auc": float(roc_auc_score(labels, p))},
            "construction": construction or {}, "methods": methods}


def one_seed(seed):
    x, y = dataset(seed, n=12000)
    pieces = {name: (x[start:end], y[start:end]) for name, (start, end) in PARTITIONS.items()}
    train_x, train_y = pieces["train"]
    raw = fit_blend(train_x, train_y, seed)
    probability_x, probability_y = pieces["probability_calibration"]
    calibrator = LogisticRegression(C=1000, max_iter=400, random_state=seed)
    calibrator.fit(RiskEngine.logits(raw(probability_x)), probability_y)
    calibrated = lambda rows: calibrator.predict_proba(RiskEngine.logits(raw(rows)))[:, 1]
    selection_x, selection_y = pieces["selection"]
    raw_selection, calibrated_selection = raw(selection_x), calibrated(selection_x)
    raw_brier = float(brier_score_loss(selection_y, raw_selection))
    calibrated_brier = float(brier_score_loss(selection_y, calibrated_selection))
    slope = float(calibrator.coef_[0, 0])
    retained = slope > 0 and calibrated_brier < raw_brier
    probability = calibrated if retained else raw
    selection_probability = calibrated_selection if retained else raw_selection
    low = matched_threshold(selection_y, selection_probability, .8)
    conformal_x, conformal_y = pieces["conformal_calibration"]
    conformal = fit_conformal(conformal_y, probability(conformal_x))
    test_x, test_y = pieces["iid_test"]
    tests = {"iid": (test_x, test_y, {"paired_with": "telemetry_masking"})}
    remote_x, remote_y = dataset(seed + 100000, n=40000)
    weight = (1 + 3*remote_x[:, 0] + 2*remote_x[:, 1] + 2*remote_x[:, 2] + 2*remote_x[:, 4])/10
    tests["remote_work"] = rejection_sample(remote_x, remote_y, weight, np.random.default_rng(seed+300000))
    tests["remote_work"][2].update({"generator_seed": seed+100000, "rejection_seed": seed+300000,
                                    "pool_data_sha256": dataset_hash(remote_x, remote_y)})
    tests["telemetry_masking"] = masked_telemetry(test_x, test_y, seed+500000)
    tests["telemetry_masking"][2].update({"mask_seed": seed+500000, "paired_with": "iid"})
    shift_x, shift_y = dataset(seed + 200000, n=40000)
    tests["label_shift"] = rejection_sample(shift_x, shift_y, np.where(shift_y == 1, 1., .25), np.random.default_rng(seed+400000))
    tests["label_shift"][2].update({"generator_seed": seed+200000, "rejection_seed": seed+400000,
                                    "pool_data_sha256": dataset_hash(shift_x, shift_y)})
    return {"seed": seed, "dataset_sha256": dataset_hash(x, y), "partitions": PARTITIONS,
            "partition_hashes": {name: dataset_hash(rows, labels) for name, (rows, labels) in pieces.items()},
            "model": {"base": "Fixed 0.4 standardized LR + 0.6 RF from experiments.risk_protocol.fit_blend",
                      "sigmoid_retained": bool(retained), "sigmoid_logit_slope": slope,
                      "sigmoid_logit_intercept": float(calibrator.intercept_[0]),
                      "raw_selection_brier": raw_brier, "sigmoid_selection_brier": calibrated_brier},
            "selection": {"target_suspicious_detection": .8, "low_threshold": low,
                          "achieved_suspicious_detection": float(np.mean(selection_probability[selection_y == 1] >= low)),
                          "suspicious_count": int((selection_y == 1).sum())},
            "conformal": conformal,
            "conditions": {name: evaluate_condition(rows, labels, probability(rows), low, conformal, construction)
                           for name, (rows, labels, construction) in tests.items()}}


def summarize(runs):
    if len(runs) < 2:
        raise ValueError("Sample standard deviations require at least two prespecified runs")
    summary = {}
    for condition in CONDITIONS:
        summary[condition] = {}
        for method in METHODS:
            first = runs[0]["conditions"][condition]["methods"][method]
            fields = [name for name, value in first.items() if isinstance(value, (float, int))]
            summary[condition][method] = {}
            for name in fields:
                values = np.asarray([run["conditions"][condition]["methods"][method][name] for run in runs])
                summary[condition][method][name] = {"mean": float(values.mean()), "sample_std": float(values.std(ddof=1)),
                                                     "minimum": float(values.min()), "maximum": float(values.max())}
    return summary


def make_report(runs):
    return {"schema_version": SCHEMA_VERSION, "synthetic": True, "alpha": ALPHA, "seeds": SEEDS,
            "conditions": CONDITIONS, "methods": METHODS,
            "protocol": {"study_date": "2026-10-20", "prespecified_before_first_measurement": True,
                         "runtime_model_replaced": False, "runtime_authorization_changed": False,
                         "seeds_are_identifiers_not_collection_dates": True,
                         "partitions": PARTITIONS, "features": FEATURES, "dataset_rows_per_run": 12000,
                         "labels": {"0": "simulator legitimate", "1": "simulator suspicious; not confirmed attacks or human access votes"},
                         "score_model": "Same fixed LR/RF architecture, refit independently per seed; no interaction search.",
                         "probability_selection": "Sigmoid fit on probability-calibration split; keep only positive slope and lower Brier on selection split, otherwise raw blend.",
                         "baseline_selection": "Largest observed positive selection score attaining >=80% suspicious detection; no test or conformal labels used.",
                         "conformal_selection": "Prespecified alpha=.1; 1-p(true class); exact ceil((n+1)*(1-alpha)) order statistic, <= inclusion; q=1 if rank unavailable.",
                         "test_used_for_selection": False, "shifted_test_used_for_fitting": False,
                         "gate": "Direct allow requires baseline allow AND prediction set exactly {legitimate}; empty/ambiguous/suspicious sets add step-up only.",
                         "challenge_definition": "Any baseline challenge/block or added step-up; high-risk blocks are not separately estimated. No actual access is granted.",
                         "rejection_pool_rows": 40000, "rejection_failure": "Fail if fewer than 2000 accepted; do not adapt pool or retune conditions after observation.",
                         "seed_offsets": {"remote_pool": 100000, "label_shift_pool": 200000, "remote_acceptance": 300000,
                                          "label_shift_acceptance": 400000, "mask": 500000},
                         "aggregation": "Five independent full fits; per-seed means, sample SD and range; no population CI from five seeds.",
                         "intervals": "Per-run Wilson 95% intervals describe finite-test Bernoulli counts conditional on fitted models/calibration. They are not simultaneous or paired-difference tests and omit training/organization uncertainty.",
                         "hashes": "SHA-256 over shape/dtype JSON header plus little-endian float64 X and int64 y; pool hashes and chosen-index hashes retained.",
                         "source_hashes": {path: hashlib.sha256((ROOT/path).read_bytes()).hexdigest() for path in
                                           ["experiments/uncertainty_study.py", "experiments/risk_protocol.py", "backend/app/risk.py"]}},
            "environment": {"python": platform.python_version(), "platform": platform.platform(),
                            **{package: importlib.metadata.version(package) for package in ["numpy", "scikit-learn", "joblib"]}},
            "runs": runs, "summary": summarize(runs),
            "limitations": [
                "All features/outcomes come from one author-written probabilistic simulator. This is not deployment evidence, attack truth or a new conformal method.",
                "Fresh seeds reduce dependence on a single draw but do not provide independent organizations, identity populations, fairness evidence or real attacker adaptation.",
                "Marginal coverage can conceal poor suspicious-class coverage; report both classes. Coverage is averaged over calibration/test randomness, not a 90% certainty for each event.",
                "IID exchangeability supports the corresponding coverage statement; unweighted coverage may fail after covariate shift or masked telemetry. No weighted conformal correction is implemented.",
                "Pure label shift preserves X|Y by construction; that assumption can support class-conditional transfer but is not validated for real changes in attack prevalence.",
                "Suspicious direct allow is bounded by suspicious set miscoverage for the conservative gate under applicable assumptions; it is not a bound on real access compromise.",
                "Additional detection is purchased with additional legitimate challenges. Always-challenge trivially reaches 100% detection at 100% legitimate friction; no end-to-end challenge success, usability or cost was measured.",
                "Telemetry masking uses zero as the existing feature default and retains latent labels; half of rows share the IID comparison and are paired, not independent populations.",
                "Wilson intervals are descriptive finite-test intervals; rates across methods and paired conditions are dependent. No multiple-comparison significance claim is made.",
                "This experiment writes a separate report only; it cannot approve reviewers, override policy, replace the runtime model or relax server-enforced grants.",
            ],
            "references": [
                {"title": "A Gentle Introduction to Conformal Prediction and Distribution-Free Uncertainty Quantification",
                 "authors": "Anastasios N. Angelopoulos and Stephen Bates", "url": "https://arxiv.org/abs/2107.07511",
                 "role": "Split/class-conditional conformal construction and interpretation; no novelty claim for this method."},
                {"title": "Conformal Prediction Under Covariate Shift",
                 "authors": "Ryan J. Tibshirani, Rina Foygel Barber, Emmanuel J. Candes and Aaditya Ramdas",
                 "url": "https://arxiv.org/abs/1904.06019", "role": "Motivates the exchangeability limitation; weighted conformal is not implemented here."},
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT/"experiments/uncertainty-study.json")
    args = parser.parse_args()
    runs = []
    for seed in SEEDS:
        runs.append(one_seed(seed))
        print(f"Completed prespecified synthetic uncertainty seed {seed}", flush=True)
    report = make_report(runs)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False)+"\n", encoding="utf-8")
    for condition, methods in report["summary"].items():
        values = {method: {key: round(metrics[key]["mean"], 6) for key in
                          ["suspicious_detection_rate", "legitimate_friction_rate"]} for method, metrics in methods.items()}
        print(json.dumps({"condition": condition, "means": values}))


if __name__ == "__main__":
    main()
