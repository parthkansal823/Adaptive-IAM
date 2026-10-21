"""Fit a fixed unsupervised forest on genuine historical authentication features.

Offline only. Neither an anomaly score nor a saved estimator has IAM authority.
Unlisted authentications are unlabeled, never fabricated negative examples.
"""
from __future__ import annotations

import hashlib
import json
import math
import platform
import random
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import ParameterGrid

from experiments.real_auth_models import AuthEvent, NoveltyModel, lanl_groups
from scripts.evaluate_lanl import atomic_json, budget_threshold, read_redteam, sha256_file

BASELINES = ("lifetime_user_computer", "hierarchical_static", "hierarchical_decay")
METHODS = ("isolation_forest", "isolation_forest_tuned") + BASELINES
FEATURES = ("negative_log_prior_user_fraction", "negative_log_prior_pair_given_user_fraction", "negative_log_prior_computer_fraction",
            "log1p_prior_global_event_rate", "smoothed_prior_user_computer_diversity", "unseen_user",
            "unseen_pair", "normalized_log_user_elapsed_seconds", "normalized_log_pair_elapsed_seconds")


def fixed_protocol() -> dict:
    return {
        "version": "real-auth-training-protocol-v1", "features": list(FEATURES),
        "feature_history": "Strictly earlier source seconds; complete equal-second groups score before update",
        "feature_fractions": "-ln((user+1)/(global+2)); -ln((pair+1)/(user+2)); -ln((computer+1)/(global+2)); diversity=(user distinct computers+1)/(user count+2)",
        "feature_event_rate": "log1p(prior global count/max(1,current second-first observed source second))",
        "feature_normalization": "Use relative count/rate features instead of raw cumulative counts to reduce trivial elapsed-history drift; no stationarity guarantee",
        "feature_elapsed": "log1p(min(86400,seconds since last event))/log1p(86400); unseen history uses 86400",
        "excluded_features": ["identifiers", "authentication outcome", "exercise labels", "future counts"],
        "learning": "Unsupervised IsolationForest; no benign or malicious training labels",
        "estimator": {"n_estimators": 100, "max_samples": 256, "contamination": "auto",
                      "max_features": 1.0, "bootstrap": False, "random_state": 20261021, "n_jobs": 1},
        "reservoir_capacity": 30000, "reservoir_seed": 20261021,
        "reservoir": "Uniform Algorithm R over warmup event rows; canonical user/computer ordering inside each second; duplicates retain event multiplicity",
        "fit_scope": "Each release/month fits six forests on warmup only; validation selects parameters, test never fits or selects",
        "warmup_fraction": .5, "validation_fraction": .25, "validation_alert_budget": .01,
        "forest_score": "floor((-score_samples)*10000)/10000; larger means more unusual, not attack probability",
        "forest_score_quantum": .0001, "baseline_score_quantum": .001,
        "threshold": "Conservative validation upper-score budget; never split tied bins; disable if top tie exceeds allowance",
        "baselines": list(BASELINES), "backoff_strength": 8., "decay_half_life_seconds": 86400.,
        "history_update": "All observed rows update feature and baseline histories irrespective of alert or label; forest weights remain frozen after warmup",
        "tail": "Exclude the complete final source-second group of each incomplete compressed prefix",
        "batching": "Batch up to8192 distinct within-second user/computer feature vectors; multiplicities weight all metrics and calibration",
        "strata": ["cold_user", "known_user_new_computer", "familiar_user_computer"],
        "test_reuse": "2015 and month00 windows were inspected previously; retrospective diagnostics. Month01 is another same-institution slice without attack labels.",
        "tuning": {"tool": "sklearn.model_selection.ParameterGrid",
                   "grid": {"max_samples": [128, 256, 512], "max_features": [.75, 1.]},
                   "all_other_settings": "Identical fixed estimator settings and warmup reservoir",
                   "validation_split": "First half of validation source-time span calibrates1% thresholds; later half measures budget stability, whole seconds only",
                   "objective": "Minimize abs(later validation alert fraction-0.01), not detection accuracy",
                   "eligibility": "Both validation halves nonempty, at least two calibration score bins, non-null calibration threshold",
                   "tie_break": "Smallest max_samples, then smallest max_features, then stable candidate ID",
                   "fallback": "Fixed max_samples256/max_features1.0 if no eligible candidate; disclose fallback",
                   "final_threshold": "Recalibrate selected candidate on all validation only; freeze before test",
                   "test": "Evaluate fixed forest plus selected forest and every count control; do not select a test winner"},
        "reporting": "Report every fixed method and regression; never choose a winner from held-out outcomes or replace runtime policy",
    }


def protocol_hash(protocol: dict) -> str:
    return hashlib.sha256(json.dumps(protocol, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def freeze(path: Path) -> dict:
    if path.exists():
        report = json.loads(path.read_text(encoding="utf-8"))
        if report.get("protocol_sha256") != protocol_hash(fixed_protocol()) or protocol_hash(report.get("protocol", {})) != report["protocol_sha256"]:
            raise ValueError("Existing training report has a different frozen protocol")
        return report
    protocol = fixed_protocol()
    report = {"schema_version": "real-auth-training-v1", "synthetic": False, "status": "protocol_frozen",
              "protocol": protocol, "protocol_sha256": protocol_hash(protocol),
              "protocol_frozen_at_utc": datetime.now(timezone.utc).isoformat(), "datasets": {}}
    atomic_json(path, report)
    return report


class FeatureHistory:
    def __init__(self):
        self.users, self.pairs, self.computers = {}, {}, {}
        self.user_degree = {}
        self.user_last, self.pair_last = {}, {}
        self.total, self.last_second, self.first_second = 0, None, None

    def features(self, event: AuthEvent) -> tuple[float, ...]:
        second, user, computer = event.second, event.user, event.computer
        if self.last_second is not None and second <= self.last_second:
            raise ValueError("Features require strictly earlier-second history")
        pair = (user, computer)
        un, pn, cn = self.users.get(user, 0), self.pairs.get(pair, 0), self.computers.get(computer, 0)
        elapsed = lambda last: math.log1p(min(86400, second - last)) / math.log1p(86400)
        return (-math.log((un + 1.) / (self.total + 2.)), -math.log((pn + 1.) / (un + 2.)),
                -math.log((cn + 1.) / (self.total + 2.)),
                math.log1p(self.total / max(1, second - self.first_second)) if self.first_second is not None else 0.,
                (self.user_degree.get(user, 0) + 1.) / (un + 2.), float(un == 0), float(pn == 0),
                1. if user not in self.user_last else elapsed(self.user_last[user]),
                1. if pair not in self.pair_last else elapsed(self.pair_last[pair]))

    def update(self, second: int, pairs: Counter) -> None:
        if self.last_second is not None and second <= self.last_second:
            raise ValueError("History groups must be strictly chronological")
        for (user, computer), count in pairs.items():
            if count <= 0:
                raise ValueError("Positive event multiplicities required")
            if (user, computer) not in self.pairs:
                self.user_degree[user] = self.user_degree.get(user, 0) + 1
            self.users[user] = self.users.get(user, 0) + count
            self.pairs[(user, computer)] = self.pairs.get((user, computer), 0) + count
            self.computers[computer] = self.computers.get(computer, 0) + count
            self.user_last[user], self.pair_last[(user, computer)] = second, second
            self.total += count
        self.last_second = second
        if self.first_second is None:
            self.first_second = second


class Reservoir:
    def __init__(self, capacity=30000, seed=20261021):
        if capacity <= 0:
            raise ValueError("Positive reservoir capacity required")
        self.capacity, self.seen = capacity, 0
        self.values = []
        self.rng = random.Random(seed)

    def add(self, vector, count=1):
        for _ in range(count):
            self.seen += 1
            if len(self.values) < self.capacity:
                self.values.append(vector)
            else:
                index = self.rng.randrange(self.seen)
                if index < self.capacity:
                    self.values[index] = vector

    def tensor(self):
        return np.asarray(self.values, dtype="<f8")


def fit_forest(reservoir: Reservoir):
    if reservoir.seen < 2:
        raise ValueError("At least two historical training events required")
    tensor = reservoir.tensor()
    model = IsolationForest(**fixed_protocol()["estimator"])
    model.fit(tensor)
    return model, hashlib.sha256(tensor.tobytes(order="C")).hexdigest()


def candidate_configs():
    return [{"id": "if_%s_%s" % (entry["max_samples"], str(entry["max_features"]).replace(".", "p")),
             "params": entry} for entry in ParameterGrid(fixed_protocol()["tuning"]["grid"])]


def choose_candidate(candidate_histograms: dict) -> tuple[str, list[dict], bool]:
    """Choose using only two validation halves; exercise labels are unavailable here."""
    if not any(sum(hist["calibration"].values()) + sum(hist["selection"].values())
               for hist in candidate_histograms.values()):
        raise ValueError("Validation window has no selected events")
    candidates = []
    for config in candidate_configs():
        hist = candidate_histograms[config["id"]]
        calibration_events = sum(hist["calibration"].values())
        threshold = budget_threshold(hist["calibration"], .01) if calibration_events else {
            "minimum_score": None, "validation_alerts": 0, "validation_events": 0,
            "validation_alert_fraction": None,
            "tie_policy": "No calibration events; candidate ineligible, no threshold estimated",
        }
        selection_events = sum(hist["selection"].values())
        minimum = threshold["minimum_score"]
        alerts = sum(count for score, count in hist["selection"].items() if minimum is not None and score >= minimum)
        fraction = alerts / selection_events if selection_events else None
        eligible = bool(selection_events and len(hist["calibration"]) >= 2 and minimum is not None)
        candidates.append({**config, "calibration_threshold": threshold,
                           "calibration_events": calibration_events,
                           "selection_events": selection_events, "selection_alerts": alerts,
                           "selection_alert_fraction": fraction,
                           "objective_distance_to_budget": abs(fraction - .01) if eligible else None,
                           "eligible": eligible})
    eligible = [entry for entry in candidates if entry["eligible"]]
    if not eligible:
        return "if_256_1p0", candidates, True
    selected = min(eligible, key=lambda entry: (entry["objective_distance_to_budget"], entry["params"]["max_samples"], entry["params"]["max_features"], entry["id"]))
    return selected["id"], candidates, False


def forest_scores(model, features):
    scores = -model.score_samples(np.asarray(features, dtype=np.float64))
    if not np.isfinite(scores).all() or (scores < 0).any() or (scores > 1).any():
        raise ValueError("Forest produced an invalid bounded anomaly score")
    return np.floor(scores * 10000) / 10000


def save_model(path: Path, model) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    joblib.dump(model, temporary, compress=3)
    temporary.replace(path)
    return sha256_file(path)


def evaluate_groups(groups, scan: dict, labels: set | None, source: dict,
                    *, model_path: Path | None = None, batch_size=8192) -> dict:
    """One chronological feature/history pass; scoring is batched without history references."""
    protocol = fixed_protocol()
    first, last = scan["source_first_second"], scan["source_last_second"]
    if last - first < 4 or batch_size < 1:
        raise ValueError("Need chronological source span and positive score batch size")
    warmup_end = first + math.floor((last - first) * .5)
    validation_end = first + math.floor((last - first) * .75)
    calibration_end = warmup_end + math.floor((validation_end - warmup_end) * .5)
    history, decay = FeatureHistory(), NoveltyModel("hierarchical_decay")
    reservoir = Reservoir(protocol["reservoir_capacity"], protocol["reservoir_seed"])
    partitions = {part: {"events": 0, "first_second": None, "last_second": None, "matched_auth_rows": 0} for part in ("warmup", "validation", "test")}
    matched = {part: set() for part in partitions}
    digests = {part: hashlib.sha256() for part in partitions}
    histograms = {name: Counter() for name in METHODS}
    candidate_histograms = {entry["id"]: {part: Counter() for part in ("calibration", "selection", "all")} for entry in candidate_configs()}
    test = {name: {"alerts": 0, "unlabeled_alerts": 0, "matched_alert_rows": 0, "recalled": set()} for name in METHODS}
    strata = {name: {"events": 0, "matched_auth_rows": 0,
                     "methods": {method: {"alerts": 0, "unlabeled_alerts": 0, "recalled": set()} for method in METHODS}}
              for name in protocol["strata"]}
    model, feature_digest, model_digest, thresholds = None, None, None, None
    models, candidate_artifacts, tuning = {}, {}, None
    selected_id = None
    pending_features, pending = [], []
    previous, active_part = None, "warmup"
    started = time.monotonic()

    def flush():
        if not pending:
            return
        part = pending[0][0]
        ids = list(models) if part == "validation" else list(dict.fromkeys(("if_256_1p0", selected_id)))
        score_arrays = {key: forest_scores(models[key], pending_features) for key in ids}
        for index, (part, second, weight, known_rows, keys, stratum, baseline_scores) in enumerate(pending):
            all_scores = {"isolation_forest": float(score_arrays["if_256_1p0"][index]), **baseline_scores}
            if part == "validation":
                half = "calibration" if second <= calibration_end else "selection"
                for candidate_id, scores in score_arrays.items():
                    score = float(scores[index])
                    candidate_histograms[candidate_id][half][score] += weight
                    candidate_histograms[candidate_id]["all"][score] += weight
                for name, score in all_scores.items():
                    histograms[name][score] += weight
            else:
                all_scores["isolation_forest_tuned"] = float(score_arrays[selected_id][index])
                for name, score in all_scores.items():
                    minimum = thresholds[name]["minimum_score"]
                    alert = minimum is not None and score >= minimum
                    if alert:
                        test[name]["alerts"] += weight
                        test[name]["unlabeled_alerts"] += weight - known_rows
                        test[name]["matched_alert_rows"] += known_rows
                        test[name]["recalled"].update(keys)
                        stratum_counts = strata[stratum]["methods"][name]
                        stratum_counts["alerts"] += weight
                        stratum_counts["unlabeled_alerts"] += weight - known_rows
                        stratum_counts["recalled"].update(keys)
        pending_features.clear()
        pending.clear()

    for second, events in groups:
        if previous is not None and second <= previous or not events or any(event.second != second for event in events):
            raise ValueError("Complete nonempty chronological timestamp groups required")
        previous = second
        part = "warmup" if second <= warmup_end else "validation" if second <= validation_end else "test"
        if part != active_part:
            flush()
            if active_part == "warmup":
                tensor = reservoir.tensor()
                if reservoir.seen < 2:
                    raise ValueError("At least two training events required")
                feature_digest = hashlib.sha256(tensor.tobytes(order="C")).hexdigest()
                for config in candidate_configs():
                    settings = {**protocol["estimator"], **config["params"]}
                    estimator = IsolationForest(**settings).fit(tensor)
                    models[config["id"]] = estimator
                    artifact = None if model_path is None else model_path if config["id"] == "if_256_1p0" else model_path.with_name(model_path.stem + "." + config["id"] + ".joblib")
                    candidate_artifacts[config["id"]] = {"model_artifact": artifact.as_posix() if artifact else None,
                                                         "model_sha256": save_model(artifact, estimator) if artifact else None}
                model = models["if_256_1p0"]
                model_digest = candidate_artifacts["if_256_1p0"]["model_sha256"]
            if part == "test":
                if not partitions["validation"]["events"]:
                    raise ValueError("Validation partition must contain events")
                selected_id, candidates, fallback = choose_candidate(candidate_histograms)
                histograms["isolation_forest_tuned"] = candidate_histograms[selected_id]["all"]
                thresholds = {name: budget_threshold(histograms[name], .01) for name in METHODS}
                for candidate in candidates:
                    candidate.update(candidate_artifacts[candidate["id"]])
                selected_config = next(entry for entry in candidate_configs() if entry["id"] == selected_id)
                tuning = {"tool": protocol["tuning"]["tool"], "objective": protocol["tuning"]["objective"],
                          "calibration_end_second": calibration_end, "selected_candidate_id": selected_id,
                          "selected_params": selected_config["params"], "fallback_used": fallback,
                          "candidates": candidates, "selected_model_sha256": candidate_artifacts[selected_id]["model_sha256"],
                          "selected_model_artifact": candidate_artifacts[selected_id]["model_artifact"],
                          "final_threshold_scope": "all validation; frozen before test"}
            active_part = part
        entry = partitions[part]
        entry["events"] += len(events)
        entry["first_second"] = second if entry["first_second"] is None else entry["first_second"]
        entry["last_second"] = second
        pairs, known_by_pair = Counter(), {}
        for event in events:
            pair = (event.user, event.computer)
            pairs[pair] += 1
            if labels is not None and event.label_key in labels:
                keys, count = known_by_pair.get(pair, (set(), 0))
                keys.add(event.label_key)
                known_by_pair[pair] = keys, count + 1
                matched[part].add(event.label_key)
                entry["matched_auth_rows"] += 1
        # Canonical ordering guarantees within-second row-order invariance.
        for (user, computer), weight in sorted(pairs.items()):
            event = AuthEvent(second, user, computer)
            features = history.features(event)
            digest_row = json.dumps([second, user, computer, weight], separators=(",", ":")).encode()
            digests[part].update(len(digest_row).to_bytes(4, "big") + digest_row)
            if part == "warmup":
                reservoir.add(features, weight)
            else:
                un, pn = history.users.get(user, 0), history.pairs.get((user, computer), 0)
                pg = (history.computers.get(computer, 0) + 1.) / (history.total + 2.)
                lifetime = math.log1p(un) - math.log1p(pn)
                static = -math.log(min(1., max(1e-12, (pn + 8. * pg) / (un + 8.))))
                scores = {"lifetime_user_computer": math.floor(max(0., lifetime) / .001) * .001,
                          "hierarchical_static": math.floor(max(0., static) / .001) * .001,
                          "hierarchical_decay": decay.score(event)}
                stratum = "cold_user" if un == 0 else "known_user_new_computer" if pn == 0 else "familiar_user_computer"
                keys, known_rows = known_by_pair.get((user, computer), (set(), 0))
                if part == "test":
                    strata[stratum]["events"] += weight
                    strata[stratum]["matched_auth_rows"] += known_rows
                pending_features.append(features)
                pending.append((part, second, weight, known_rows, keys, stratum, scores))
                if len(pending) >= batch_size:
                    flush()
        history.update(second, pairs)
        decay.update(events)
    flush()
    if thresholds is None or model is None or not partitions["test"]["events"]:
        raise ValueError("Warmup, validation and test all require events")
    if sum(entry["events"] for entry in partitions.values()) != scan["selected_rows"]:
        raise ValueError("Source selection metadata does not match evaluated rows")
    for part, entry in partitions.items():
        entry.update({"known_redteam_unique_tuples": len(matched[part]) if labels is not None else None,
                      "unlabeled_events": entry["events"] - entry["matched_auth_rows"],
                      "canonical_selected_stream_sha256": digests[part].hexdigest()})
    eligible = labels is not None and bool(matched["test"])
    methods = {}
    total_test, unlabeled = partitions["test"]["events"], partitions["test"]["unlabeled_events"]
    for name, counts in test.items():
        recalled = counts.pop("recalled")
        methods[name] = {"threshold": thresholds[name], "test_alerts": counts["alerts"],
                         "test_alert_fraction": counts["alerts"] / total_test,
                         "unlabeled_alerts": counts["unlabeled_alerts"],
                         "alert_fraction_over_unlabeled": counts["unlabeled_alerts"] / unlabeled if unlabeled else None,
                         "known_redteam_alerted_auth_rows": counts["matched_alert_rows"] if eligible else None,
                         "known_redteam_recalled_unique_tuples": len(recalled) if eligible else None,
                         "known_redteam_tuple_recall": len(recalled) / len(matched["test"]) if eligible else None}
    for entry in strata.values():
        for counts in entry["methods"].values():
            recalled = counts.pop("recalled")
            counts["alert_fraction"] = counts["alerts"] / entry["events"] if entry["events"] else None
            counts["known_redteam_recalled_unique_tuples"] = len(recalled) if eligible else None
    return {"source": source, "scan": scan, "partitions": partitions,
            "partition_cutoffs": {"warmup_end_second": warmup_end, "validation_end_second": validation_end},
            "labels": {"available": labels is not None, "detection_metrics_eligible": eligible,
                       "interpretation": "Sparse exercise reference; unlisted events unlabeled" if labels is not None else "No attack labels; alert burden only"},
            "training": {"algorithm": "IsolationForest", "warmup_events_seen": reservoir.seen,
                         "reservoir_events": len(reservoir.values), "fitted_feature_dimensions": len(FEATURES),
                         "feature_tensor_sha256": feature_digest, "feature_tensor_dtype": "little-endian float64, C order",
                         "model_sha256": model_digest, "model_artifact": model_path.as_posix() if model_path else None,
                         "actual_max_samples": model.max_samples_, "fitted_tree_count": len(model.estimators_),
                         "weights_frozen_after": "warmup", "elapsed_seconds": round(time.monotonic() - started, 3),
                         "tuning": tuning},
            "methods": methods, "test_strata": strata}


def environment():
    return {"python_version": platform.python_version(), "platform": platform.platform(),
            "numpy": np.__version__, "scikit_learn": sklearn.__version__, "joblib": joblib.__version__}


def run_study(report_path: Path, artifacts: Path, descriptors: list[dict]) -> dict:
    if not descriptors:
        raise ValueError("Provide actual observed source descriptors")
    report = freeze(report_path)
    execution_hash = sha256_file(Path(__file__))
    report["pending_execution_commitment"] = {"module_sha256": execution_hash,
        "datasets": [item["name"] for item in descriptors], "recorded_at_utc": datetime.now(timezone.utc).isoformat()}
    atomic_json(report_path, report)
    artifacts.mkdir(parents=True, exist_ok=True)
    # Check exact atomic final destinations before scanning/fitting any source.
    for item in descriptors:
        destination = artifacts / (item["name"] + ".isolation-forest.joblib")
        destinations = [destination] + [destination.with_name(destination.stem + "." + entry["id"] + ".joblib") for entry in candidate_configs() if entry["id"] != "if_256_1p0"]
        for target in destinations:
            if not target.exists():
                save_model(target, {"status": "pending_fit", "protocol_sha256": report["protocol_sha256"]})
            else:
                # Existing weights survive the preflight. The atomic publication path is probed.
                probe = target.with_name(target.name + ".preflight")
                save_model(probe, {"status": "write_check"})
                probe.unlink()
    for item in descriptors:
        auth = Path(item["auth"])
        metadata = json.loads(Path(item["metadata"]).read_text(encoding="utf-8"))
        digest = sha256_file(auth)
        if item["kind"] == "lanl2015":
            if digest != metadata["source"]["auth_sha256"] or sha256_file(Path(item["redteam"])) != metadata["source"]["redteam_sha256"]:
                raise ValueError("LANL2015 input differs from frozen measured source")
            groups = lanl_groups(auth)
            labels, scan = read_redteam(Path(item["redteam"])), metadata["scan"]
            source = {"source_url": metadata["source"]["landing_page"], "auth_sha256": digest,
                      "redteam_sha256": metadata["source"]["redteam_sha256"], "bounded_prefix": True,
                      "retrospective": True, "release": "LANL2015 cyber1", "actual_calendar_dates_disclosed": False}
        else:
            from scripts.evaluate_lanl2014 import event_groups
            if digest != metadata["compressed_prefix_sha256"]:
                raise ValueError("Monthly input differs from recorded acquisition provenance")
            groups = ((second, [AuthEvent(second, event.user, event.computer, destination=event.computer) for event in events])
                      for second, events in event_groups(auth, prefix=True))
            labels, scan = None, metadata["scan"]
            source = {"source_url": metadata.get("source_url"), "auth_sha256": digest,
                      "bounded_prefix": True, "retrospective": item["name"] != "lanl2014_month01",
                      "release": "LANL2014 successful auth", "monthly_file": metadata.get("filename", auth.name),
                      "actual_calendar_dates_disclosed": False, "provenance": metadata}
        result = evaluate_groups(groups, scan, labels, source,
                                 model_path=artifacts / (item["name"] + ".isolation-forest.joblib"))
        result["implementation_sha256"] = execution_hash
        result["execution_environment"] = environment()
        result["measured_at_utc"] = datetime.now(timezone.utc).isoformat()
        report["datasets"][item["name"]] = result
        # Persist each completed expensive fit, retaining its implementation identity.
        atomic_json(report_path, report)
        print(json.dumps({"dataset": item["name"], "training_events": result["training"]["warmup_events_seen"],
                          "test_events": result["partitions"]["test"]["events"], "status": "fit_and_evaluation_saved"}), flush=True)
    report.update({"status": "measured", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "execution_commitment": report.pop("pending_execution_commitment"),
        "environment": environment(), "implementation": {"module": "experiments/real_auth_training.py", "sha256": execution_hash},
        "limitations": [
            "Unsupervised forest learns recurring telemetry, not benign intent. Warmup and adapting history may contain compromise.",
            "LANL2015 labels cover sparse clustered controlled-exercise events; all unlisted events are unlabeled. No false-positive rate, precision or production accuracy is identifiable.",
            "2014 monthly slices have no attack labels. Lower alert burden does not establish higher detection quality.",
            "All releases originate at one historic institution, with anonymization, successful-authentication filtering and possible overlap. Additional months are not independent organizations.",
            "2015 targeted prefix and month00 were inspected previously; these comparisons are retrospective diagnostics, not untouched confirmation or externally preregistered evidence.",
            "Contiguous bounded prefixes exclude their incomplete final second and lack full archive checksum/trailer verification; source calendar dates are undisclosed.",
            "Feature count distributions shift as history grows; fixed learned weights and validation budgets do not guarantee test alert or detection performance.",
            "All fixed candidates and regressions are reported; no held-out winner is promoted. Forest scores are not probabilities and cannot grant, revoke or bypass IAM policy.",
            "Saved joblib estimators are executable pickle artifacts. Load only trusted local files after matching their report SHA-256 and software environment; runtime does not load these artifacts.",
        ]})
    atomic_json(report_path, report)
    return report
