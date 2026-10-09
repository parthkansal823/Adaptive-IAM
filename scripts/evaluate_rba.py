"""Evaluate a user-provided chronological RBA CSV; never downloads or publishes data."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
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

REQUIRED = {"User ID", "Login Timestamp", "User Agent String", "Country", "Login Successful", "Is Account Takeover"}


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


def read_events(path: Path, max_rows: int):
    histories = defaultdict(lambda: {"devices": set(), "countries": set(), "failures": deque(), "events": deque(), "first": None})
    rows, labels, times = [], [], []
    last = None
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError("Missing CSV columns: " + ", ".join(sorted(missing)))
        for index, row in enumerate(reader):
            if index >= max_rows:
                break
            now = timestamp(row["Login Timestamp"])
            if last is not None and now < last:
                raise ValueError("CSV must be globally chronological. Sort by Login Timestamp before evaluation.")
            last = now
            history = histories[row["User ID"]]
            if history["first"] is None:
                history["first"] = now
            for key in ("failures", "events"):
                while history[key] and (now - history[key][0]).total_seconds() > 3600:
                    history[key].popleft()
            # Every feature uses only events BEFORE this event. Current login success,
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
            labels.append(int(boolean(row["Is Account Takeover"])))
            times.append(now.isoformat())
            history["events"].append(now)
            if boolean(row["Login Successful"]):
                history["devices"].add(row["User Agent String"])
                history["countries"].add(row["Country"])
            else:
                history["failures"].append(now)
    if not rows:
        raise ValueError("CSV has no events")
    return np.asarray(rows), np.asarray(labels), times


def evaluate(path: Path, max_rows: int):
    x, y, times = read_events(path, max_rows)
    if len(y) < 100:
        raise ValueError("At least 100 events are required; use a representative dataset with sufficient takeovers.")
    ends = [int(len(y) * ratio) for ratio in (.6, .7, .8)]
    slices = [slice(0, ends[0]), slice(ends[0], ends[1]), slice(ends[1], ends[2]), slice(ends[2], len(y))]
    names = ["train", "calibration", "threshold_selection", "test"]
    for name, part in zip(names, slices):
        if len(np.unique(y[part])) != 2:
            raise ValueError(f"{name} partition needs both takeover and legitimate examples; no results were generated.")
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
        "dataset": {"name": "User-provided RBA CSV", "sha256": digest.hexdigest(), "rows_used": len(y), "row_limit": max_rows, "label": "Is Account Takeover", "feature_names": FEATURES,
                    "partitions": {name: {"rows": len(y[part]), "positives": int(y[part].sum()), "start": times[part.start], "end": times[part.stop-1]} for name, part in zip(names, slices)}},
        "method": {"split": "chronological 60/10/10/20", "ensemble": "0.4 LR + 0.6 RF", "calibration": "Platt sigmoid on independent calibration partition", "threshold_selection": "F1 on validation only", "features_use_prior_events_only": True},
        "baseline": metrics(y[slices[3]], raw(x[slices[3]]), .5),
        "improved": metrics(y[slices[3]], calibrated(x[slices[3]]), threshold),
        "limitations": ["This command does not deploy or alter the demo's risk model.", "The published RBA dataset is synthesized, not raw production data.", "VPN, travel distance, resource sensitivity and prior risk are unavailable and held constant.", "Normal hour uses the demo's fixed 10:00 reference, not a learned per-user baseline.", "Temporal split permits known users across periods; unseen-user generalization is not measured.", "Historical successful logins can include compromised sessions; device familiarity is not identity proof.", "Metrics may regress; no test-set tuning or automatic improvement claim."],
        "source": "https://github.com/das-group/rba-dataset",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=200000)
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/results/rba.json")
    args = parser.parse_args()
    if args.max_rows < 100:
        parser.error("--max-rows must be at least 100")
    try:
        report = evaluate(args.csv, args.max_rows)
    except (ValueError, OSError) as error:
        parser.exit(2, str(error) + "\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "rows": report["dataset"]["rows_used"], "baseline_f1": report["baseline"]["f1"], "candidate_f1": report["improved"]["f1"]}))


if __name__ == "__main__":
    main()
