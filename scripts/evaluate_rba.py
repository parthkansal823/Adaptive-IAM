"""Evaluate a user-provided chronological RBA CSV; never downloads or publishes data."""
from __future__ import annotations

import argparse
from bisect import bisect_right
import csv
import hashlib
import importlib.metadata
import json
import platform
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.risk import FEATURES, RiskEngine, features, metrics  # noqa: E402

REQUIRED = {"User ID", "Login Timestamp", "User Agent String", "Country", "Login Successful"}
LABELS = ("Is Account Takeover", "Is Attack IP")
PROTOCOL_VERSION = "rba-evaluation-v2"


def boolean(value: str) -> bool:
    value = value.strip().lower()
    if value not in {"true", "false", "1", "0"}:
        raise ValueError("Boolean fields must contain true/false or 1/0")
    return value in {"true", "1"}


def timestamp(value: str) -> datetime:
    try:
        number = float(value)
        if number > 1e12:
            number /= 1000
        return datetime.fromtimestamp(number, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def read_events(path: Path, max_rows: int, label="Is Account Takeover", include_users=False):
    if label not in LABELS:
        raise ValueError("Use an explicitly supported source label")
    if isinstance(max_rows, bool) or not isinstance(max_rows, int) or max_rows < 1:
        raise ValueError("A positive integer row limit is required")
    histories = defaultdict(lambda: {"devices": set(), "countries": set(), "failures": deque(), "events": deque(), "first": None})
    rows, labels, times, users = [], [], [], []
    last, group_start = None, 0
    pending = []

    def update_group():
        # A source timestamp has no trustworthy within-timestamp order. Score
        # its entire group before any outcome/device updates become visible.
        for user, device, country, successful in pending:
            history = histories[user]
            history["events"].append(last)
            if successful:
                history["devices"].add(device)
                history["countries"].add(country)
            else:
                history["failures"].append(last)
        pending.clear()
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = (REQUIRED | {label}) - set(reader.fieldnames or [])
        if missing:
            raise ValueError("Missing CSV columns: " + ", ".join(sorted(missing)))
        for index, row in enumerate(reader):
            now = timestamp(row["Login Timestamp"])
            if last is not None and now < last:
                raise ValueError("CSV must be globally chronological. Sort by Login Timestamp before evaluation.")
            if index >= max_rows:
                # One lookahead row distinguishes an exact group boundary from
                # a cap that bisects a timestamp. Exclude the whole partial group.
                if now == last:
                    for values in (rows, labels, times, users):
                        del values[group_start:]
                break
            if last is not None and now != last:
                update_group()
                group_start = len(rows)
            last = now
            history = histories[row["User ID"]]
            if history["first"] is None:
                history["first"] = now
            for key in ("failures", "events"):
                while history[key] and (now - history[key][0]).total_seconds() > 3600:
                    history[key].popleft()
            # Every feature uses only strictly EARLIER timestamps. Current login success,
            # attack IP and account-takeover label are never included in X.
            context = {
                "known_device": row["User Agent String"] in history["devices"],
                "known_location": row["Country"] in history["countries"],
                "failed_attempts": min(len(history["failures"]), 20),
                "login_velocity": min(len(history["events"]), 30),
                "account_age_days": min((now - history["first"]).total_seconds() / 86400, 3650),
                "hour": now.hour,
                "vpn": False, "travel_distance_km": 0, "sensitivity": .5, "prior_risk": .1,
            }
            rows.append(features(context))
            labels.append(int(boolean(row[label])))
            times.append(now.isoformat())
            users.append(hashlib.sha256(row["User ID"].encode()).hexdigest())
            pending.append((row["User ID"], row["User Agent String"], row["Country"], boolean(row["Login Successful"])))
    if not rows:
        raise ValueError("CSV has no complete timestamp groups within the row limit")
    result = (np.asarray(rows), np.asarray(labels), times)
    return (*result, users) if include_users else result


def partitions(users, split, times=None):
    """Timestamp-preserving windows or hash cohorts; no label-driven assignment."""
    count=len(users)
    if split == "chronological":
        if times is None or len(times) != count:
            raise ValueError("Chronological splitting requires an aligned timestamp for every event")
        normalized = [timestamp(value) for value in times]
        if any(a > b for a, b in zip(normalized, normalized[1:])):
            raise ValueError("Partition timestamps must be chronological")
        ends = [0]
        for ratio in (.6, .7, .8):
            end = max(ends[-1], int(count * ratio))
            # Move a nominal cut to the end of its timestamp group. Large ties
            # can empty a partition; eligibility rejects it before model fitting.
            ends.append(bisect_right(normalized, normalized[end - 1], lo=end) if end else 0)
        ends.append(count)
        return [np.arange(ends[i],ends[i+1]) for i in range(4)]
    if split != "user-disjoint":
        raise ValueError("Unknown split protocol")
    # Hash a stable opaque user digest with a fixed protocol salt. Cohort choice
    # never observes outcomes; ratios refer to users, not equal event counts.
    cohorts=np.asarray([int(hashlib.sha256(('rba-user-study-v1:'+u).encode()).hexdigest()[:8],16)/2**32 for u in users])
    return [np.flatnonzero((cohorts>=low)&(cohorts<high)) for low,high in ((0,.6),(.6,.7),(.7,.8),(.8,1))]


def evaluate(path: Path, max_rows: int, split="chronological", label="Is Account Takeover"):
    x, y, times, users = read_events(path, max_rows, label, include_users=True)
    if len(y) < 100:
        raise ValueError("At least 100 events are required; use a representative dataset with sufficient takeovers.")
    slices = partitions(users, split, times)
    names = ["train", "calibration", "threshold_selection", "test"]
    for name, part in zip(names, slices):
        if len(np.unique(y[part])) != 2:
            raise ValueError(f"{name} partition needs both classes for {label}; no results were generated.")
    lr = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=600, random_state=42))
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, min_samples_leaf=12, class_weight="balanced", n_jobs=1, random_state=42)
    lr.fit(x[slices[0]], y[slices[0]])
    rf.fit(x[slices[0]], y[slices[0]])

    def raw(part):
        return .4 * lr.predict_proba(part)[:, 1] + .6 * rf.predict_proba(part)[:, 1]

    calibrator = LogisticRegression(C=1000, max_iter=400, random_state=42)
    calibrator.fit(RiskEngine.logits(raw(x[slices[1]])), y[slices[1]])

    def calibrated(part):
        return calibrator.predict_proba(RiskEngine.logits(raw(part)))[:, 1]

    validation = calibrated(x[slices[2]])
    threshold = float(max(np.linspace(.05, .75, 141), key=lambda t: (f1_score(y[slices[2]], validation >= t), t)))
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "implementation": {"entry_point": "scripts/evaluate_rba.py",
                           "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                           "risk_feature_metrics_sha256": hashlib.sha256((ROOT / "backend/app/risk.py").read_bytes()).hexdigest()},
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        **{name: importlib.metadata.version(name) for name in ("numpy", "scikit-learn")}},
        "dataset": {"name": "Supplied RBA CSV (provenance required separately)", "sha256": digest.hexdigest(), "rows_used": len(y), "row_limit": max_rows, "label": label, "feature_names": FEATURES,
                    "partitions": {name: {"rows": len(y[part]), "positives": int(y[part].sum()), "users":len({users[i] for i in part}), "start": times[part[0]], "end": times[part[-1]]} for name, part in zip(names, slices)}},
        "method": {"protocol_version": PROTOCOL_VERSION, "split": split+" 60/10/10/20", "allocation_unit":"whole timestamp groups near nominal event ratios" if split=="chronological" else "users by fixed SHA-256 cohorts; event ratios vary", "partition_tie_policy": "Move chronological cuts to the end of timestamp groups; reject empty or single-class partitions", "row_limit_policy": "Discard the whole final timestamp group if a one-row lookahead shows the cap bisected it", "user_overlap_train_test":len({users[i] for i in slices[0]} & {users[i] for i in slices[3]}), "ensemble": "0.4 LR + 0.6 RF", "calibration": "Platt sigmoid on independent calibration partition", "threshold_selection": "F1 on validation only", "features_use_prior_events_only": True, "features_use_strictly_earlier_timestamps_only": True},
        "baseline": metrics(y[slices[3]], raw(x[slices[3]]), .5),
        "improved": metrics(y[slices[3]], calibrated(x[slices[3]]), threshold),
        "limitations": ["This command does not deploy or alter the demo's risk model.", "The published RBA dataset is synthesized, not raw production data.", "Is Attack IP is a threat-intelligence proxy, not confirmed account takeover." if label=="Is Attack IP" else "Source takeover indicators in synthesized data do not establish real attack truth.", "VPN, travel distance, resource sensitivity and prior risk are unavailable and held constant.", "Normal hour uses the demo's fixed 10:00 reference, not a learned per-user baseline.", "Temporal split permits known users across periods; unseen-user generalization is not measured." if split=="chronological" else "User cohorts are disjoint but time windows overlap; this is not simultaneous future-time generalization. Test users accumulate their own prior online history without outcome features.", "Historical successful logins can include compromised sessions; device familiarity is not identity proof.", "Metrics may regress; no test-set tuning or automatic improvement claim."],
        "source": "https://github.com/das-group/rba-dataset",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=200000)
    parser.add_argument("--split", choices=("chronological","user-disjoint"), default="chronological")
    parser.add_argument("--label", choices=LABELS, default=LABELS[0])
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/results/rba.json")
    args = parser.parse_args()
    if args.max_rows < 100:
        parser.error("--max-rows must be at least 100")
    try:
        report = evaluate(args.csv, args.max_rows, args.split, args.label)
    except (ValueError, OSError) as error:
        parser.exit(2, str(error) + "\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "rows": report["dataset"]["rows_used"], "baseline_f1": report["baseline"]["f1"], "candidate_f1": report["improved"]["f1"]}))


if __name__ == "__main__":
    main()
