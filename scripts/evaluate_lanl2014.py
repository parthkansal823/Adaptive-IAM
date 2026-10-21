"""Bounded offline LANL 2014 successful-authentication novelty study.

This dataset has no attack labels. Alert burden is not false-positive rate,
accuracy, recall, or evidence that an event should be denied by IAM policy.
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import json
import math
import platform
import re
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "https://csr.lanl.gov/data/auth/"
MIRROR = "https://lanl.ma.ic.ac.uk/data/auth/"
FILENAME = "lanl-auth-dataset-1-00.bz2"
EXPECTED_FULL_SHA256 = "c8e5efe0b33e80eb2d17f5414255fc4b78be600f8df5040084018dbb5abe25e8"
METHODS = ("new_user_computer", "user_computer_surprise")
IDENTIFIER = re.compile(r"[UC][0-9]+\Z")
MAX_LINE_BYTES = 256


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def bzip_lines(chunks, *, allow_prefix=False, max_output_bytes=4 * 1024**3):
    """Bound decompression and never emit incomplete trailing records."""
    decoder = bz2.BZ2Decompressor()
    pending = b""
    emitted = 0
    for chunk in chunks:
        if decoder.eof and chunk:
            raise ValueError("Trailing bytes or concatenated bzip2 archives are unsupported")
        compressed = chunk
        while compressed or not decoder.needs_input:
            output = decoder.decompress(compressed, 1024 * 1024)
            compressed = b""
            if decoder.unused_data:
                raise ValueError("Trailing bytes or concatenated bzip2 archives are unsupported")
            emitted += len(output)
            if emitted > max_output_bytes:
                raise ValueError("Decompressed byte limit exceeded")
            pending += output
            lines = pending.split(b"\n")
            pending = lines.pop()
            for line in lines:
                if len(line) > MAX_LINE_BYTES:
                    raise ValueError("Oversized authentication record")
                yield line.decode("ascii")
            if len(pending) > MAX_LINE_BYTES:
                raise ValueError("Oversized authentication record")
            if decoder.eof:
                break
    if not decoder.eof and not allow_prefix:
        raise ValueError("Truncated bzip2 archive needs explicit prefix mode")
    if decoder.eof and pending:
        yield pending.decode("ascii")


@dataclass(frozen=True)
class AuthEvent:
    second: int
    user: str
    computer: str


def auth_event(line: str) -> AuthEvent:
    fields = line.split(",")
    if len(fields) != 3:
        raise ValueError("LANL2014 requires exactly three fields")
    second = int(fields[0])
    if second < 1 or not IDENTIFIER.fullmatch(fields[1]) or not fields[1].startswith("U"):
        raise ValueError("Invalid authentication timestamp or user identifier")
    if not IDENTIFIER.fullmatch(fields[2]) or not fields[2].startswith("C"):
        raise ValueError("Invalid computer identifier")
    return AuthEvent(second, fields[1], fields[2])


def file_lines(path: Path, *, prefix=False):
    if any(path.name.endswith(suffix) for suffix in (".bz2", ".bz2.prefix", ".bz2.prefix.tmp")):
        with path.open("rb") as handle:
            yield from bzip_lines(iter(lambda: handle.read(65536), b""), allow_prefix=prefix)
    else:
        with path.open("r", encoding="ascii") as handle:
            for line in handle:
                if len(line) > MAX_LINE_BYTES:
                    raise ValueError("Oversized authentication record")
                yield line.rstrip("\r\n")


def event_groups(path: Path, *, prefix=False):
    """Discard the final timestamp of any partial archive in its entirety."""
    last = None
    group = []
    for line in file_lines(path, prefix=prefix):
        event = auth_event(line)
        if last is not None and event.second < last:
            raise ValueError("Authentication rows must be globally chronological")
        if last is not None and event.second > last:
            yield last, group
            group = []
        last = event.second
        group.append(event)
    if group and not prefix:
        yield last, group


def scan_auth(path: Path, *, prefix=False) -> dict:
    count = 0
    first = last = None
    final_group = 0
    for line in file_lines(path, prefix=prefix):
        event = auth_event(line)
        if last is not None and event.second < last:
            raise ValueError("Authentication rows must be globally chronological")
        if last != event.second:
            final_group = 0
        final_group += 1
        first = event.second if first is None else first
        last = event.second
        count += 1
    return {"source_rows": count, "source_first_second": first, "source_last_second": last,
            "selected_rows": count - final_group if prefix else count,
            "final_timestamp_rows_excluded": final_group if prefix else 0}


def fetch(output: Path, *, max_bytes=16 * 1024**2, max_seconds=300) -> dict:
    if not 0 < max_bytes <= 128 * 1024**2 or not 0 < max_seconds <= 300:
        raise ValueError("Acquisition must stay within 128 MiB and 300 seconds")
    output.mkdir(parents=True, exist_ok=True)
    target = output / (FILENAME + ".prefix")
    if target.exists():
        raise ValueError("Sample already exists; use another output directory to avoid replacing frozen evidence")
    temporary = target.with_name(target.name + ".tmp")
    started = time.monotonic()
    digest = hashlib.sha256()
    count = 0
    request = urllib.request.Request(MIRROR + FILENAME, headers={
        "User-Agent": "Adaptive-IAM-offline-auth-research/1.0", "Accept-Encoding": "identity"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response, temporary.open("wb") as handle:
            if response.status != 200:
                raise ValueError("Expected sequential HTTP 200 public source response")
            content_length = response.headers.get("Content-Length")
            while count < max_bytes and time.monotonic() - started < max_seconds:
                chunk = response.read(min(65536, max_bytes - count))
                if not chunk:
                    break
                handle.write(chunk)
                digest.update(chunk)
                count += len(chunk)
        # Parsing is deliberately outside the transfer timeout; no additional
        # network requests occur during bounded decompression and evaluation.
        scan = scan_auth(temporary, prefix=True)
        if not scan["selected_rows"]:
            raise ValueError("No complete timestamp groups within acquisition bounds")
        temporary.replace(target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    provenance = {"dataset": "LANL User-Computer Authentication Associations in Time (2014)",
        "source_url": SOURCE, "mirror_url": MIRROR, "doi": "10.11578/1160076",
        "license": "LANL waiver of copyright and neighboring rights (public-domain dedication)",
        "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
        "download_url": MIRROR + FILENAME, "filename": target.name,
        "compressed_bytes": count, "compressed_prefix_sha256": digest.hexdigest(),
        "expected_full_archive_sha256": EXPECTED_FULL_SHA256,
        "full_archive_sha256_verified": False, "full_bzip2_integrity_verified": False,
        "server_content_length": int(content_length) if content_length else None,
        "limits": {"compressed_bytes": max_bytes, "network_seconds": max_seconds,
                   "decompressed_bytes": 4 * 1024**3},
        "elapsed_seconds_including_validation": round(time.monotonic() - started, 3),
        "stop_reason": "byte_or_time_bound", "scan": scan}
    atomic_json(output / "provenance.json", provenance)
    return provenance


class Novelty:
    def __init__(self):
        self.user = Counter()
        self.edge = Counter()
        self.computer = Counter()

    def score(self, event: AuthEvent) -> tuple[float, float]:
        edge = (event.user, event.computer)
        surprise = round(math.log1p(self.user[event.user]) - math.log1p(self.edge[edge]), 6)
        return float(self.edge[edge] == 0), surprise

    def update(self, events):
        for event in events:
            self.user[event.user] += 1
            self.computer[event.computer] += 1
            self.edge[(event.user, event.computer)] += 1


def budget_threshold(histogram: Counter, fraction: float) -> dict:
    total = sum(histogram.values())
    if not total:
        raise ValueError("Validation partition has no events")
    allowance = math.floor(total * fraction)
    threshold = None
    alerts = 0
    for value, count in sorted(histogram.items(), reverse=True):
        if alerts + count > allowance:
            break
        threshold = value
        alerts += count
    return {"minimum_score": threshold, "validation_alerts": alerts, "validation_events": total,
            "validation_alert_fraction": alerts / total,
            "tie_policy": "All scores >= threshold; none when top tied group exceeds budget"}


def evaluate(auth: Path, *, prefix=False, budget=.01, provenance: Path | None = None) -> dict:
    if not 0 < budget < 1:
        raise ValueError("Alert budget must be strictly between zero and one")
    scan = scan_auth(auth, prefix=prefix)
    first, last = scan["source_first_second"], scan["source_last_second"]
    if first is None or last - first < 4:
        raise ValueError("Study requires at least five distinct source seconds")
    warmup_end = first + math.floor((last - first) * .5)
    validation_end = first + math.floor((last - first) * .75)
    model = Novelty()
    histograms = [Counter() for _ in METHODS]
    thresholds = None
    partitions = {name: {"events": 0, "first_second": None, "last_second": None,
                         "new_user_events": 0, "new_computer_events": 0,
                         "new_user_computer_events": 0, "new_pair_known_user_events": 0}
                  for name in ("warmup", "validation", "test")}
    alerts = [0] * len(METHODS)
    for second, events in event_groups(auth, prefix=prefix):
        name = "warmup" if second <= warmup_end else "validation" if second <= validation_end else "test"
        if name == "test" and thresholds is None:
            thresholds = [budget_threshold(hist, budget) for hist in histograms]
        entry = partitions[name]
        entry["first_second"] = second if entry["first_second"] is None else entry["first_second"]
        entry["last_second"] = second
        entry["events"] += len(events)
        for event in events:
            scores = model.score(event)
            entry["new_user_events"] += int(model.user[event.user] == 0)
            entry["new_computer_events"] += int(model.computer[event.computer] == 0)
            entry["new_user_computer_events"] += int(scores[0])
            entry["new_pair_known_user_events"] += int(scores[0] and model.user[event.user] > 0)
            if name == "validation":
                for histogram, score in zip(histograms, scores):
                    histogram[score] += 1
            elif name == "test":
                for index, score in enumerate(scores):
                    threshold = thresholds[index]["minimum_score"]
                    alerts[index] += int(threshold is not None and score >= threshold)
        model.update(events)
    if thresholds is None or not all(part["events"] for part in partitions.values()):
        raise ValueError("Warmup, validation and test must each contain events")
    for part in partitions.values():
        part["unlabeled_events"] = part["events"]
        for field in ("new_user", "new_computer", "new_user_computer", "new_pair_known_user"):
            part[field + "_event_fraction"] = part[field + "_events"] / part["events"]
    source = {"kind": "real_enterprise_successful_authentication_without_attack_labels",
              "source_url": SOURCE, "mirror_url": MIRROR, "doi": "10.11578/1160076",
              "bounded_auth_prefix": prefix, "compressed_input_sha256": sha256_file(auth)}
    if provenance:
        fetched = json.loads(provenance.read_text(encoding="utf-8"))
        if fetched.get("compressed_prefix_sha256") != source["compressed_input_sha256"]:
            raise ValueError("Provenance hash differs from evaluated input")
        source["acquisition"] = fetched
    return {"schema_version": "lanl2014-study-v1", "synthetic": False,
        "source_real_enterprise": True, "evidence_type": source["kind"],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(), "source": source, "scan": scan,
        "protocol": {"warmup_time_fraction": .5, "validation_time_fraction": .25,
                     "test_time_fraction": .25, "warmup_end_second": warmup_end,
                     "validation_end_second": validation_end, "alert_budget": budget,
                     "score_rounding_decimals": 6,
                     "history": "Score entire equal-second group using prior groups, then update all rows regardless of alert",
                     "selection": "First monthly file, first bounded sequential prefix; no outcome-based window selection",
                     "tail": "Discard entire final timestamp group for partial archives"},
        "labels": {"attack_labels_available": False, "detection_metrics_eligible": False,
                   "eligibility_reason": "Successful authentication is not proof of benign behavior; no attack reference provided"},
        "partitions": partitions,
        "methods": {method: {"threshold": thresholds[index], "test_alerts": alerts[index],
            "test_alert_fraction": alerts[index] / partitions["test"]["events"],
            "known_redteam_tuple_recall": None, "accuracy": None, "false_positive_rate": None}
            for index, method in enumerate(METHODS)},
        "implementation": {"entry_point": "scripts/evaluate_lanl2014.py",
            "sha256": sha256_file(Path(__file__)), "python_version": platform.python_version(),
            "platform": platform.platform()},
        "limitations": ["No attack labels: alert fraction is workload, never false-positive rate or accuracy.",
            "Successful events alone omit failures and cannot establish legitimate intent.",
            "Another historic dataset from the same institution is not cross-organization validation; cohort/time overlap is unknown.",
            "A bounded early-file prefix is not representative of all nine months or contemporary deployments.",
            "The partial bzip2 archive lacks verified final CRC/trailer and full-file checksum.",
            "User/computer identifiers are anonymized; domain policy, access intent and device trust are unavailable.",
            "Sequential history adapts using every prior event, including possible undisclosed malicious events.",
            "Scores are offline research signals and cannot grant or revoke access."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    download = sub.add_parser("fetch", help="Acquire public bounded prefix; never submit source contact forms")
    download.add_argument("--output-dir", type=Path, default=ROOT / "data" / "lanl2014")
    download.add_argument("--max-mib", type=int, default=16)
    download.add_argument("--max-seconds", type=float, default=300)
    study = sub.add_parser("evaluate")
    study.add_argument("--auth", type=Path, required=True)
    study.add_argument("--prefix", action="store_true")
    study.add_argument("--provenance", type=Path)
    study.add_argument("--budget", type=float, default=.01)
    study.add_argument("--output", type=Path, default=ROOT / "experiments" / "lanl2014-study.json")
    args = parser.parse_args()
    if args.command == "fetch":
        report = fetch(args.output_dir, max_bytes=args.max_mib * 1024**2, max_seconds=args.max_seconds)
        print(json.dumps({"compressed_bytes": report["compressed_bytes"], "scan": report["scan"]}))
    else:
        report = evaluate(args.auth, prefix=args.prefix, budget=args.budget, provenance=args.provenance)
        atomic_json(args.output, report)
        print(json.dumps({"schema_version": report["schema_version"], "scan": report["scan"],
                          "methods": report["methods"]}, allow_nan=False))


if __name__ == "__main__":
    main()
