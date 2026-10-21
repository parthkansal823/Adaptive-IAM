"""Fixed offline real-authentication model comparison; no runtime IAM authority.

Scores estimate observable novelty, never attack probabilities. The hierarchical
backoff uses per-computer Bernoulli propensities, not a categorical likelihood.
"""
from __future__ import annotations

import hashlib
import json
import math
import platform
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from scripts.evaluate_lanl import (
    atomic_json, budget_threshold, event_groups as lanl_event_groups,
    read_redteam, sha256_file,
)

METHODS = ("lifetime_user_computer", "hierarchical_static", "hierarchical_decay")


def fixed_protocol() -> dict:
    return {
        "version": "real-auth-model-protocol-v1", "methods": list(METHODS),
        "common_observables": "relative second, source user, destination computer; no outcome or label features",
        "lifetime_user_computer": "ln(1+past user count)-ln(1+past user/computer count)",
        "hierarchical_propensity": "pG=(global computer count+1)/(global count+2); pU=(user/computer count+8*pG)/(user count+8); score=-ln(pU)",
        "propensity_interpretation": "Empirical-Bayes-style smoothed per-computer marginal Bernoulli propensity; not normalized categorical likelihood or attack probability",
        "backoff_strength": 8.0, "global_positive_prior": 1.0, "global_negative_prior": 1.0,
        "decay_half_life_seconds": 86400.0,
        "decay": "All four counts exponentially decay to current source second before scoring; lazy updates use elapsed seconds",
        "score_quantum": .001, "score_quantization": "Floor scores to fixed0.001bins before threshold calibration and evaluation",
        "probability_floor": 1e-12, "warmup_fraction": .5, "validation_fraction": .25,
        "validation_alert_budget": .01,
        "threshold": "Conservative upper-score threshold; no tied-score splitting; top tie over budget disables alerts",
        "history": "Score every event in a source-second group from strictly earlier seconds, then update all methods together; online history continues through validation/test",
        "tail_policy": "Exclude whole final source-second group of incomplete compressed prefixes",
        "strata": ["cold_user", "known_user_new_computer", "familiar_user_computer"],
        "stratum_definition": "Lifetime strictly prior user and user/computer counts shared across all methods",
        "evaluation_scope": "LANL2015 targeted prefix is already-inspected retrospective diagnostic; LANL2014 separate real logs have no attack labels and measure burden only",
        "model_selection": "All three prespecified methods reported, including regressions; no test-driven selection, tuning or automatic runtime replacement",
    }


def protocol_hash(protocol: dict) -> str:
    return hashlib.sha256(json.dumps(protocol, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def freeze(path: Path) -> dict:
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("protocol_sha256") != protocol_hash(fixed_protocol()) or protocol_hash(existing.get("protocol", {})) != existing.get("protocol_sha256"):
            raise ValueError("Existing report has a different frozen protocol")
        return existing
    protocol = fixed_protocol()
    result = {"schema_version": "real-auth-model-study-v1", "synthetic": False, "status": "protocol_frozen",
              "protocol_frozen_at_utc": datetime.now(timezone.utc).isoformat(),
              "implementation_sha256_at_freeze": sha256_file(Path(__file__)),
              "protocol_sha256": protocol_hash(protocol), "protocol": protocol, "datasets": {}}
    atomic_json(path, result)
    return result


@dataclass(frozen=True)
class AuthEvent:
    second: int
    user: str
    computer: str
    source: str | None = None
    destination: str | None = None

    @property
    def label_key(self):
        return (self.second, self.user, self.source, self.destination)


class Counts:
    def __init__(self, half_life: float | None):
        self.values = {}
        self.half_life = half_life

    def get(self, key, second: int) -> float:
        value, last = self.values.get(key, (0., second))
        if second < last:
            raise ValueError("Counts cannot observe earlier time after later history")
        if self.half_life is not None:
            value *= math.exp(-math.log(2.) * (second - last) / self.half_life)
        return value

    def add(self, key, second: int, count: int) -> None:
        self.values[key] = (self.get(key, second) + count, second)


class NoveltyModel:
    def __init__(self, method: str):
        if method not in METHODS:
            raise ValueError("Unknown fixed method")
        self.method = method
        self.protocol = fixed_protocol()
        self.counts = Counts(self.protocol["decay_half_life_seconds"] if method == "hierarchical_decay" else None)

    def score(self, event: AuthEvent) -> float:
        now, user, computer = event.second, event.user, event.computer
        user_n = self.counts.get(("user", user), now)
        pair_n = self.counts.get(("pair", user, computer), now)
        if self.method == "lifetime_user_computer":
            score = math.log1p(user_n) - math.log1p(pair_n)
        else:
            global_n = self.counts.get(("global",), now)
            computer_n = self.counts.get(("computer", computer), now)
            propensity = (computer_n + 1.) / (global_n + 2.)
            probability = (pair_n + 8. * propensity) / (user_n + 8.)
            score = -math.log(min(1., max(self.protocol["probability_floor"], probability)))
        quantum = self.protocol["score_quantum"]
        return math.floor(max(0., score) / quantum) * quantum

    def update(self, events: list[AuthEvent]) -> None:
        if not events:
            return
        now = events[0].second
        if any(event.second != now for event in events):
            raise ValueError("Only a single complete timestamp group may update history")
        pairs = Counter((event.user, event.computer) for event in events)
        users, computers = Counter(), Counter()
        for (user, computer), count in pairs.items():
            self.counts.add(("pair", user, computer), now, count)
            users[user] += count
            computers[computer] += count
        for user, count in users.items():
            self.counts.add(("user", user), now, count)
        if self.method != "lifetime_user_computer":
            for computer, count in computers.items():
                self.counts.add(("computer", computer), now, count)
            self.counts.add(("global",), now, len(events))


def csv_groups(path: Path, *, prefix: bool = True):
    last, events = None, []
    with path.open(encoding="ascii") as handle:
        for line in iter(lambda: handle.readline(257), ""):
            if len(line) > 256:
                raise ValueError("Oversized canonical authentication record")
            parts = line.rstrip("\r\n").split(",")
            if len(parts) != 3 or not parts[1] or not parts[2] or parts[1] == "?" or parts[2] == "?":
                raise ValueError("Canonical authentication rows require second,user,computer")
            now = int(parts[0])
            if now < 1 or last is not None and now < last:
                raise ValueError("Canonical rows require positive chronological seconds")
            if last is not None and now != last:
                yield last, events
                events = []
            events.append(AuthEvent(now, parts[1], parts[2], destination=parts[2]))
            last = now
    if events and not prefix:
        yield last, events


def lanl_groups(path: Path):
    for second, events in lanl_event_groups(path, prefix=True):
        yield second, [AuthEvent(second, event.user, event.destination, event.source, event.destination) for event in events]


def scan_csv(path: Path) -> dict:
    first = last = None
    rows = 0
    for second, events in csv_groups(path, prefix=False):
        first = second if first is None else first
        last = second
        rows += len(events)
    if first is None:
        raise ValueError("No authentication events")
    return {"source_first_second": first, "source_last_second": last, "source_rows": rows, "selected_rows": rows}


def evaluate_groups(group_iterator, scan: dict, labels: set | None, source: dict) -> dict:
    protocol = fixed_protocol()
    first, last = scan["source_first_second"], scan["source_last_second"]
    if last - first < 4:
        raise ValueError("Insufficient chronological source span")
    warmup_end = first + math.floor((last - first) * protocol["warmup_fraction"])
    validation_end = first + math.floor((last - first) * (protocol["warmup_fraction"] + protocol["validation_fraction"]))
    models = {name: NoveltyModel(name) for name in METHODS}
    histograms = {name: Counter() for name in METHODS}
    thresholds = None
    partitions = {name: {"events": 0, "first_second": None, "last_second": None, "matched_auth_rows": 0} for name in ("warmup", "validation", "test")}
    matched = {name: set() for name in partitions}
    test_counts = {name: {"alerts": 0, "unlabeled_alerts": 0, "matched_alert_rows": 0, "recalled": set()} for name in METHODS}
    strata = {stratum: {"events": 0, "matched_auth_rows": 0, "known_tuples": set(),
                       "methods": {name: {"alerts": 0, "unlabeled_alerts": 0, "score_sum": 0., "zero_scores": 0, "recalled": set()} for name in METHODS}}
              for stratum in protocol["strata"]}
    previous_second = None
    for second, events in group_iterator:
        if previous_second is not None and second <= previous_second:
            raise ValueError("Timestamp groups must be strictly chronological")
        if any(event.second != second for event in events):
            raise ValueError("Event timestamp differs from its group")
        previous_second = second
        part = "warmup" if second <= warmup_end else "validation" if second <= validation_end else "test"
        if part == "test" and thresholds is None:
            thresholds = {name: budget_threshold(histograms[name], protocol["validation_alert_budget"]) for name in METHODS}
        entry = partitions[part]
        entry["events"] += len(events)
        entry["first_second"] = second if entry["first_second"] is None else entry["first_second"]
        entry["last_second"] = second
        score_cache = {}
        strata_cache = {}
        for event in events:
            pair = (event.user, event.computer)
            if pair not in score_cache:
                score_cache[pair] = {name: model.score(event) for name, model in models.items()}
                baseline = models["lifetime_user_computer"]
                if baseline.counts.get(("user", event.user), second) == 0:
                    strata_cache[pair] = "cold_user"
                elif baseline.counts.get(("pair", event.user, event.computer), second) == 0:
                    strata_cache[pair] = "known_user_new_computer"
                else:
                    strata_cache[pair] = "familiar_user_computer"
            known = labels is not None and event.label_key in labels
            if known:
                matched[part].add(event.label_key)
                entry["matched_auth_rows"] += 1
            if part == "validation":
                for name, score in score_cache[pair].items():
                    histograms[name][score] += 1
            elif part == "test":
                stratum = strata[strata_cache[pair]]
                stratum["events"] += 1
                stratum["matched_auth_rows"] += int(known)
                if known:
                    stratum["known_tuples"].add(event.label_key)
                for name, score in score_cache[pair].items():
                    minimum = thresholds[name]["minimum_score"]
                    alert = minimum is not None and score >= minimum
                    counts = test_counts[name]
                    counts["alerts"] += int(alert)
                    counts["unlabeled_alerts"] += int(alert and not known)
                    counts["matched_alert_rows"] += int(alert and known)
                    stratum_method = stratum["methods"][name]
                    stratum_method["alerts"] += int(alert)
                    stratum_method["unlabeled_alerts"] += int(alert and not known)
                    stratum_method["score_sum"] += score
                    stratum_method["zero_scores"] += int(score == 0)
                    if alert and known:
                        counts["recalled"].add(event.label_key)
                        stratum_method["recalled"].add(event.label_key)
        for model in models.values():
            model.update(events)
    if thresholds is None or not partitions["test"]["events"]:
        raise ValueError("Validation and test must have events")
    if sum(entry["events"] for entry in partitions.values()) != scan["selected_rows"]:
        raise ValueError("Evaluated event count differs from hash-linked source selection metadata")
    for name, entry in partitions.items():
        entry["known_redteam_unique_tuples"] = len(matched[name]) if labels is not None else None
        entry["unlabeled_events"] = entry["events"] - entry["matched_auth_rows"]
    test = partitions["test"]
    eligible = labels is not None and len(matched["test"]) > 0
    methods = {}
    for name, counts in test_counts.items():
        methods[name] = {"threshold": thresholds[name], "test_alerts": counts["alerts"],
                         "test_alert_fraction": counts["alerts"] / test["events"],
                         "unlabeled_alerts": counts["unlabeled_alerts"],
                         "alert_fraction_over_unlabeled": counts["unlabeled_alerts"] / test["unlabeled_events"] if test["unlabeled_events"] else None,
                         "known_redteam_alerted_auth_rows": counts["matched_alert_rows"] if eligible else None,
                         "known_redteam_recalled_unique_tuples": len(counts["recalled"]) if eligible else None,
                         "known_redteam_tuple_recall": len(counts["recalled"]) / len(matched["test"]) if eligible else None}
    for entry in strata.values():
        known_tuples = entry.pop("known_tuples")
        entry["known_redteam_unique_tuples"] = len(known_tuples) if labels is not None else None
        unlabeled = entry["events"] - entry["matched_auth_rows"]
        entry["unlabeled_events"] = unlabeled
        for counts in entry["methods"].values():
            recalled = counts.pop("recalled")
            counts["mean_score"] = counts.pop("score_sum") / entry["events"] if entry["events"] else None
            counts["alert_fraction_over_unlabeled"] = counts["unlabeled_alerts"] / unlabeled if unlabeled else None
            counts["known_redteam_recalled_unique_tuples"] = len(recalled) if eligible else None
    return {"source": source, "scan": scan, "partition_cutoffs": {"warmup_end_second": warmup_end, "validation_end_second": validation_end},
            "partitions": partitions, "methods": methods, "test_strata": strata,
            "labels": {"available": labels is not None, "detection_metrics_eligible": eligible,
                       "interpretation": "Listed controlled-exercise tuples; all unlisted events UNLABELED" if labels is not None else "No attack labels exist for this source; burden only, no detection superiority inference"}}


def run_study(report_path: Path, lanl_auth: Path | None = None, lanl_redteam: Path | None = None,
              lanl_report: Path | None = None, additional_auth: Path | None = None,
              additional_provenance: Path | None = None) -> dict:
    targets = [name for name, provided in (("lanl2015_retrospective", lanl_auth),
                                           ("lanl2014_unlabeled", additional_auth)) if provided is not None]
    if not targets:
        raise ValueError("At least one actual dataset is required for evaluation")
    frozen = freeze(report_path)
    execution_hash = sha256_file(Path(__file__))
    # Preserve the exact implementation identity of retained dataset results.
    previous_hash = frozen.get("implementation", {}).get("sha256")
    for dataset in frozen.get("datasets", {}).values():
        if "implementation_sha256" not in dataset:
            if not isinstance(previous_hash, str) or len(previous_hash) != 64 or any(c not in "0123456789abcdef" for c in previous_hash):
                raise ValueError("Retained dataset lacks an execution implementation identity")
            dataset["implementation_sha256"] = previous_hash
            dataset["execution_environment"] = {key: frozen["implementation"][key]
                                                 for key in ("python_version", "platform")
                                                 if key in frozen["implementation"]}
    frozen["pending_execution_commitment"] = {"module_sha256": execution_hash,
                                              "datasets": targets,
                                              "recorded_at_utc": datetime.now(timezone.utc).isoformat()}
    # Exact final-report atomic path is checked before the potentially long scan.
    atomic_json(report_path, frozen)
    result = {key: value for key, value in frozen.items() if key != "datasets"}
    with tempfile.NamedTemporaryFile(dir=report_path.parent, prefix=".model-study-write-check-", delete=True):
        pass
    result["datasets"] = dict(frozen.get("datasets", {}))
    if lanl_auth is not None:
        previous = json.loads(lanl_report.read_text(encoding="utf-8"))
        if sha256_file(lanl_auth) != previous["source"]["auth_sha256"] or sha256_file(lanl_redteam) != previous["source"]["redteam_sha256"]:
            raise ValueError("LANL2015 files differ from frozen source metadata")
        result["datasets"]["lanl2015_retrospective"] = evaluate_groups(lanl_groups(lanl_auth), previous["scan"], read_redteam(lanl_redteam),
            {"kind": "Real enterprise background with sparse exercise-redteam reference", "retrospective": True,
             "source_url": previous["source"]["landing_page"], "auth_sha256": previous["source"]["auth_sha256"],
             "redteam_sha256": previous["source"]["redteam_sha256"], "bounded_prefix": True,
             "limitations": "Previously inspected targeted prefix; diagnostic reuse, not untouched confirmation. Source/destination labels matched exactly; model observes user/destination only."})
    if additional_auth is not None:
        from scripts.evaluate_lanl2014 import event_groups as additional_groups, scan_auth as scan_additional
        metadata = json.loads(additional_provenance.read_text(encoding="utf-8")) if additional_provenance else {}
        actual_hash = sha256_file(additional_auth)
        if metadata.get("compressed_prefix_sha256") != actual_hash:
            raise ValueError("Additional source hash does not match acquisition provenance")
        groups = ((second, [AuthEvent(second, event.user, event.computer, destination=event.computer) for event in events])
                  for second, events in additional_groups(additional_auth, prefix=True))
        result["datasets"]["lanl2014_unlabeled"] = evaluate_groups(groups, metadata.get("scan") or scan_additional(additional_auth, prefix=True), None,
            {"kind": "Real enterprise successful authentication; no attack labels", "retrospective": False,
             "source_url": metadata.get("source_url"), "auth_sha256": actual_hash, "bounded_prefix": True, "provenance": metadata})
    completed_at = datetime.now(timezone.utc).isoformat()
    for name, provided in (("lanl2015_retrospective", lanl_auth), ("lanl2014_unlabeled", additional_auth)):
        if provided is not None:
            result["datasets"][name]["implementation_sha256"] = execution_hash
            result["datasets"][name]["execution_environment"] = {"python_version": platform.python_version(),
                                                                  "platform": platform.platform()}
            result["datasets"][name]["execution_commitment"] = dict(result["pending_execution_commitment"])
            result["datasets"][name]["measured_at_utc"] = completed_at
    result["execution_commitment"] = result.pop("pending_execution_commitment")
    dataset_hashes = {name: dataset["implementation_sha256"] for name, dataset in result["datasets"].items()}
    distinct_hashes = set(dataset_hashes.values())
    result.update({"status": "measured", "generated_at_utc": completed_at,
                   "implementation": {"module": "experiments/real_auth_models.py",
                                      "sha256": next(iter(distinct_hashes)) if len(distinct_hashes) == 1 else None,
                                      "mixed_dataset_implementations": len(distinct_hashes) > 1,
                                      "dataset_sha256": dataset_hashes},
                   "limitations": ["Marginal novelty scores are not calibrated attack probabilities or runtime authorization decisions.",
                                   "Methods use identical user/computer observables; older source+destination baseline scores are not a like-for-like control.",
                                   "Previously inspected LANL2015 prefix is retrospective; ten clustered exercise tuples cannot support broad superiority.",
                                   "LANL2014 has no attack labels, so alert burden cannot establish detection sensitivity or false-positive rate.",
                                   "Both releases originate at LANL. Publication years do not prove independent collection periods; calendar dates are undisclosed and temporal overlap cannot be ruled out.",
                                   "Exponential decay adapts familiarity but can forget legitimate infrequent pairs, while unlabeled compromise can poison all histories.",
                                   "Validation budgets do not guarantee identical test burden; all fixed methods are reported regardless of regressions."]})
    atomic_json(report_path, result)
    return result
