"""Bounded, reproducible LANL authentication novelty study (standard library only).

Raw deidentified records remain in ignored data/lanl. Missing redteam labels mean
UNLABELED, never benign. This offline study cannot grant or revoke access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import re
import sys
import tempfile
import time
import urllib.request
import zlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "https://csr.lanl.gov/data/cyber1/"
MIRROR = "https://lanl.ma.ic.ac.uk/data/cyber1/"
HUMAN = re.compile(r"U[0-9]+@[^,]+\Z")
METHODS = ("new_user_source", "new_user_destination", "edge_surprise")
MAX_LINE_BYTES = 4096


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def implementation_metadata() -> dict:
    return {"entry_point": "scripts/evaluate_lanl.py", "sha256": sha256_file(Path(__file__)),
            "python_version": platform.python_version(), "platform": platform.platform(),
            "hash_scope": "Finalized evaluator source; metadata and input-validation edits do not alter reported scoring rules"}


def bounded_bytes(response, limit: int, deadline: float):
    """Read no more than the caller's transfer allowance, even without EOF."""
    read = 0
    while read < limit and time.monotonic() < deadline:
        chunk = response.read(min(65536, limit - read))
        if not chunk:
            return
        read += len(chunk)
        yield chunk


def gzip_lines(chunks, *, allow_prefix: bool = False, max_output_bytes: int = 256 * 1024**3):
    """Yield complete lines only; truncated gzip needs explicit prefix permission.

    A streaming prefix cannot verify the archive CRC/trailer. Even if a byte cap
    bisects a compressed block, zlib can emit complete preceding text records.
    """
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    pending = b""
    emitted = 0
    for chunk in chunks:
        if decoder.eof and chunk:
            raise ValueError("Concatenated gzip members or trailing bytes are unsupported")
        compressed = chunk
        while compressed:
            output = decoder.decompress(compressed, 1024 * 1024)
            if decoder.unused_data:
                raise ValueError("Concatenated gzip members or trailing bytes are unsupported")
            compressed = decoder.unconsumed_tail
            emitted += len(output)
            if emitted > max_output_bytes:
                raise ValueError("Decompressed byte limit exceeded")
            pending += output
            lines = pending.split(b"\n")
            pending = lines.pop()
            for line in lines:
                if len(line) > MAX_LINE_BYTES:
                    raise ValueError("Oversized LANL record")
                yield line.decode("ascii")
            if len(pending) > MAX_LINE_BYTES:
                raise ValueError("Oversized LANL record")
    if not decoder.eof and not allow_prefix:
        raise ValueError("Truncated gzip: use an explicitly documented bounded prefix")
    if decoder.eof and pending:
        yield pending.decode("ascii")


def file_lines(path: Path, *, prefix: bool = False):
    if path.suffix == ".gz" or path.name.endswith(".gz.prefix"):
        with path.open("rb") as handle:
            yield from gzip_lines(iter(lambda: handle.read(65536), b""), allow_prefix=prefix)
    else:
        with path.open("r", encoding="ascii") as handle:
            for line in handle:
                if len(line) > MAX_LINE_BYTES:
                    raise ValueError("Oversized LANL record")
                yield line.rstrip("\n\r")


@dataclass(frozen=True)
class Event:
    second: int
    user: str
    source: str
    destination: str

    @property
    def key(self):
        return (self.second, self.user, self.source, self.destination)


def auth_event(line: str) -> tuple[int, Event | None]:
    fields = line.split(",")
    if len(fields) != 9:
        raise ValueError("LANL auth records require exactly nine fields")
    second = int(fields[0])
    if second < 1:
        raise ValueError("LANL seconds must be positive")
    # Fixed observable selection; outcome is never read or used. Both
    # Success and Fail rows are eligible. Missing host values are excluded.
    selected = bool(HUMAN.fullmatch(fields[1])) and fields[7] == "LogOn" and fields[3] not in {"", "?"} and fields[4] not in {"", "?"}
    return second, Event(second, fields[1], fields[3], fields[4]) if selected else None


def read_redteam(path: Path) -> set[tuple]:
    known = set()
    for line in file_lines(path):
        fields = line.split(",")
        if len(fields) != 4:
            raise ValueError("LANL redteam records require exactly four fields")
        known.add((int(fields[0]), *fields[1:]))
    return known


def scan_auth(path: Path, *, prefix: bool = False) -> dict:
    rows = selected = 0
    first = last = None
    selected_first = selected_last = None
    for line in file_lines(path, prefix=prefix):
        second, event = auth_event(line)
        if last is not None and second < last:
            raise ValueError("Authentication rows must be globally chronological")
        first = second if first is None else first
        last = second
        rows += 1
        if event:
            selected += 1
            selected_first = second if selected_first is None else selected_first
            selected_last = second
    return {"source_rows": rows, "selected_rows": selected, "source_first_second": first,
            "source_last_second": last, "selected_first_second": selected_first,
            "selected_last_second": selected_last}


def fetch(output: Path, max_bytes: int, max_seconds: float, stop_second: int | None = None) -> dict:
    """Fetch a sequential prefix; keep original compressed bytes and provenance.

    Source endpoints are fixed public institutional URLs. No contact forms,
    credentials, Range tricks or source gates are submitted/bypassed.
    """
    if not 0 < max_bytes <= 512 * 1024**2 or not 0 < max_seconds <= 1800:
        raise ValueError("Use 1..512 MiB and 0..1800 seconds")
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    provenance = {"dataset": "LANL Comprehensive, Multi-Source Cyber-Security Events (2015)",
                  "source_url": SOURCE, "mirror_url": MIRROR, "doi": "10.17021/1179829",
                  "license": "LANL copyright and neighboring-rights waiver (CC0/public-domain dedication)",
                  "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
                  "limits": {"auth_compressed_bytes": max_bytes, "elapsed_seconds": max_seconds,
                             "stop_after_source_second": stop_second}, "files": {}}
    # Tiny reference file is always downloaded completely and gzip-verified.
    for name, cap in (("redteam.txt.gz", 1024 * 1024), ("auth.txt.gz", max_bytes)):
        url = MIRROR + name
        target = output / (name if name.startswith("redteam") else name + ".prefix")
        temporary = target.with_name(target.name + ".tmp")
        count = 0
        digest = hashlib.sha256()
        first = last = None
        rows = selected = 0
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        pending = b""
        stopped_at_target = False
        request = urllib.request.Request(url, headers={"User-Agent": "Adaptive-IAM-LANL-research/1.0", "Accept-Encoding": "identity"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response, temporary.open("wb") as handle:
                if response.status != 200:
                    raise ValueError("Expected a sequential HTTP 200 source response")
                content_length = response.headers.get("Content-Length")
                for chunk in bounded_bytes(response, cap, started + max_seconds):
                    handle.write(chunk)
                    count += len(chunk)
                    digest.update(chunk)
                    if name.startswith("auth"):
                        compressed = chunk
                        while compressed:
                            text = decoder.decompress(compressed, 1024 * 1024)
                            if decoder.unused_data:
                                raise ValueError("Concatenated gzip members or trailing bytes are unsupported")
                            compressed = decoder.unconsumed_tail
                            pending += text
                            parts = pending.split(b"\n")
                            pending = parts.pop()
                            for raw in parts:
                                if len(raw) > MAX_LINE_BYTES:
                                    raise ValueError("Oversized LANL record")
                                second, event = auth_event(raw.decode("ascii"))
                                if last is not None and second < last:
                                    raise ValueError("Authentication rows must be chronological")
                                first = second if first is None else first
                                last = second
                                rows += 1
                                selected += int(event is not None)
                            if len(pending) > MAX_LINE_BYTES:
                                raise ValueError("Oversized LANL record")
                        if stop_second is not None and last is not None and last > stop_second:
                            stopped_at_target = True
                            break
                handle.flush()
            if name.startswith("redteam"):
                # This also checks the gzip checksum and complete trailer.
                redteam = list(gzip_lines([temporary.read_bytes()], max_output_bytes=4 * 1024**2))
                if not redteam:
                    raise ValueError("Redteam reference is empty")
                if any(len(line.split(",")) != 4 for line in redteam):
                    raise ValueError("Invalid redteam reference format")
                complete = True
            else:
                complete = decoder.eof
                if not rows:
                    raise ValueError("No complete authentication records within the bound")
            temporary.replace(target)
            provenance["files"][name] = {"path": str(target.relative_to(output)), "url": url,
                "compressed_bytes": count, "sha256": digest.hexdigest(),
                "server_content_length": int(content_length) if content_length else None,
                "full_gzip_integrity_verified": complete,
                "stop_reason": "target_second" if stopped_at_target else ("complete" if complete else "byte_or_time_limit")}
            if name.startswith("auth"):
                provenance["pilot_scan"] = {"source_rows": rows, "selected_rows": selected,
                    "source_first_second": first, "source_last_second": last}
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    provenance["elapsed_seconds"] = round(time.monotonic() - started, 3)
    atomic_json(output / "provenance.json", provenance)
    return provenance


class Novelty:
    """Only prior timestamp groups update counts, irrespective of outcomes."""

    def __init__(self):
        self.source = Counter()
        self.destination = Counter()
        self.edge = Counter()
        self.user = Counter()

    def score(self, event: Event) -> tuple[float, float, float]:
        source = (event.user, event.source)
        destination = (event.user, event.destination)
        edge = (event.user, event.source, event.destination)
        # Label-free empirical frequency surprise, smoothed with one prior count.
        surprise = math.log1p(self.user[event.user]) - math.log1p(self.edge[edge])
        return (float(self.source[source] == 0), float(self.destination[destination] == 0), surprise)

    def update(self, events: list[Event]) -> None:
        for event in events:
            self.source[(event.user, event.source)] += 1
            self.destination[(event.user, event.destination)] += 1
            self.edge[(event.user, event.source, event.destination)] += 1
            self.user[event.user] += 1


def event_groups(path: Path, *, prefix: bool = False):
    """Never use an incomplete final source second from a bounded prefix."""
    group = []
    last = None
    for line in file_lines(path, prefix=prefix):
        second, event = auth_event(line)
        if last is not None and second < last:
            raise ValueError("Authentication rows must be globally chronological")
        if last is not None and second > last:
            if group:
                yield last, group
            group = []
        last = second
        if event:
            group.append(event)
    if group and not prefix:
        yield last, group


def budget_threshold(histogram: Counter, fraction: float) -> dict:
    """Conservative score threshold: tied scores are never split or randomized."""
    total = sum(histogram.values())
    if not total:
        raise ValueError("Validation window has no selected events")
    allowance = math.floor(total * fraction)
    alerts = 0
    threshold = None
    for value, count in sorted(histogram.items(), reverse=True):
        if alerts + count > allowance:
            break
        threshold = value
        alerts += count
    return {"minimum_score": threshold, "validation_alerts": alerts,
            "validation_events": total, "validation_alert_fraction": alerts / total,
            "tie_policy": "alert on all scores >= threshold; no alerts when top tie exceeds budget"}


def evaluate(auth: Path, redteam: Path, *, prefix: bool = False, budget: float = .01,
             warmup_fraction: float = .5, validation_fraction: float = .25,
             provenance: Path | None = None) -> dict:
    if not 0 < budget < 1 or not 0 < warmup_fraction < 1 or not 0 < validation_fraction < 1 - warmup_fraction:
        raise ValueError("Invalid alert budget or chronological partition fractions")
    summary = scan_auth(auth, prefix=prefix)
    first, last = summary["source_first_second"], summary["source_last_second"]
    if first is None or last - first < 4:
        raise ValueError("Study requires at least five source seconds")
    # Absolute time cutoffs retain entire equal-second groups in one partition.
    warmup_end = first + math.floor((last - first) * warmup_fraction)
    validation_end = first + math.floor((last - first) * (warmup_fraction + validation_fraction))
    labels = read_redteam(redteam)
    model = Novelty()
    histograms = [Counter() for _ in METHODS]
    thresholds = None
    partitions = {name: {"events": 0, "first_second": None, "last_second": None,
                          "matched_auth_rows": 0} for name in ("warmup", "validation", "test")}
    positive_keys = {name: set() for name in partitions}
    test_alerts = [0] * len(METHODS)
    test_unlabeled_alerts = [0] * len(METHODS)
    test_redteam_alert_rows = [0] * len(METHODS)
    recalled_keys = [set() for _ in METHODS]
    all_matched = set()
    for second, events in event_groups(auth, prefix=prefix):
        partition = "warmup" if second <= warmup_end else "validation" if second <= validation_end else "test"
        if partition == "test" and thresholds is None:
            thresholds = [budget_threshold(hist, budget) for hist in histograms]
        entry = partitions[partition]
        entry["events"] += len(events)
        entry["first_second"] = second if entry["first_second"] is None else entry["first_second"]
        entry["last_second"] = second
        for event in events:
            scores = model.score(event)
            known = event.key in labels
            if known:
                positive_keys[partition].add(event.key)
                all_matched.add(event.key)
                entry["matched_auth_rows"] += 1
            if partition == "validation":
                for histogram, score in zip(histograms, scores):
                    histogram[score] += 1
            elif partition == "test":
                for index, (score, threshold) in enumerate(zip(scores, thresholds)):
                    alerted = threshold["minimum_score"] is not None and score >= threshold["minimum_score"]
                    test_alerts[index] += int(alerted)
                    test_unlabeled_alerts[index] += int(alerted and not known)
                    test_redteam_alert_rows[index] += int(alerted and known)
                    if alerted and known:
                        recalled_keys[index].add(event.key)
        model.update(events)
    if thresholds is None or not partitions["test"]["events"]:
        raise ValueError("Chronological validation and test require selected events")
    for name, entry in partitions.items():
        entry["known_redteam_unique_tuples"] = len(positive_keys[name])
        entry["unlabeled_events"] = entry["events"] - entry["matched_auth_rows"]
    test = partitions["test"]
    eligible = bool(positive_keys["test"])
    methods = {}
    for index, name in enumerate(METHODS):
        methods[name] = {"threshold": thresholds[index], "test_alerts": test_alerts[index],
            "test_alert_fraction": test_alerts[index] / test["events"],
            "unlabeled_alerts": test_unlabeled_alerts[index],
            "alert_fraction_over_unlabeled": test_unlabeled_alerts[index] / test["unlabeled_events"] if test["unlabeled_events"] else None,
            "known_redteam_alerted_auth_rows": test_redteam_alert_rows[index] if eligible else None,
            "known_redteam_recalled_unique_tuples": len(recalled_keys[index]) if eligible else None,
            "known_redteam_tuple_recall": len(recalled_keys[index]) / len(positive_keys["test"]) if eligible else None}
    artifact = {"schema_version": "lanl-study-v1", "study": "LANL real enterprise authentication novelty (offline)",
        "evidence_type": "real_enterprise_authentication_with_exercise_redteam", "synthetic": False,
        "source_real_enterprise": True, "implementation": implementation_metadata(),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": {"landing_page": SOURCE, "download_mirror": MIRROR, "doi": "10.17021/1179829",
            "citation": "A. D. Kent, Comprehensive, Multi-Source Cybersecurity Events, LANL, 2015",
            "license": "LANL copyright and neighboring-rights waiver (CC0/public-domain dedication)",
            "kind": "real deidentified enterprise authentication; sparse exercise-redteam reference",
            "calendar_dates": "Not disclosed by source; relative seconds only",
            "auth_sha256": sha256_file(auth), "redteam_sha256": sha256_file(redteam),
            "auth_compressed_bytes": auth.stat().st_size, "redteam_compressed_bytes": redteam.stat().st_size,
            "bounded_auth_prefix": prefix,
            "full_auth_archive_integrity_verified": not prefix if auth.suffix == ".gz" else False},
        "selection": {"predicate": "source user matches U[0-9]+@domain, orientation=LogOn, both computers known",
            "outcomes": "Success and Fail included; current outcome excluded from scores and history updates",
            "final_second": "Excluded for incomplete prefix; retained for full verified input"},
        "scan": summary,
        "protocol": {"partition": "chronological source-second windows; equal-second groups never split",
            "warmup_end_second_inclusive": warmup_end, "validation_end_second_inclusive": validation_end,
            "warmup_fraction": warmup_fraction, "validation_fraction": validation_fraction,
            "alert_budget": budget, "threshold_fit": "validation observables only; labels never used",
            "history": "Prequential updates only after scoring every selected row in a source-second group; update continues in validation/test",
            "score_definition": {"new_user_source": "1 if user/source unseen in earlier seconds, else 0",
                "new_user_destination": "1 if user/destination unseen in earlier seconds, else 0",
                "edge_surprise": "ln(1 + prior user event count) - ln(1 + prior user/source/destination count)"}},
        "partitions": partitions,
        "labels": {"unique_redteam_tuples_in_reference": len(labels),
            "reference_first_second": min(key[0] for key in labels) if labels else None,
            "reference_last_second": max(key[0] for key in labels) if labels else None,
            "matched_unique_tuples_across_partitions": len(all_matched),
            "matching": "Exact (second, source user@domain, source computer, destination computer); all matching auth duplicates share weak tuple label",
            "unlisted_events": "UNLABELED; absence of a redteam record is not proof of benign behavior",
            "detection_metrics_eligible": eligible,
            "eligibility_reason": "Test contains exact selected redteam tuples" if eligible else "No exact selected redteam tuple in test; known-redteam detection metrics withheld"},
        "methods": methods,
        "limitations": ["A single historic institution and contiguous prefix do not establish production generalization or IAM takeover detection.",
            "The targeted prefix endpoint was chosen after consulting the public first redteam time: label-informed feasibility sampling, not externally preregistered representative or untouched test data. Methods and thresholds were not tuned on test outcomes.",
            "Redteam events are controlled exercise activity, with incomplete negative labels; no accuracy, precision, FPR or AUROC is claimed.",
            "Only human-source LogOn events with known computers are selected; machine/service activity and other orientations are excluded.",
            "Source excludes failures for users without any successful authentication in its full dataset; this creates source selection bias.",
            "Reference tuple lacks auth type/orientation/outcome; duplicate auth rows cannot be resolved to unique compromise events.",
            "Validation alert budget is a calibration target; shifted test traffic and tied discrete scores can produce zero alerts or exceed the target.",
            "Offline logged observables are not trusted live telemetry, randomized interventions or independent operational validation."]}
    if provenance is not None:
        metadata = json.loads(provenance.read_text(encoding="utf-8"))
        files = metadata.get("files", {})
        if files.get("auth.txt.gz", {}).get("sha256") != artifact["source"]["auth_sha256"] or files.get("redteam.txt.gz", {}).get("sha256") != artifact["source"]["redteam_sha256"]:
            raise ValueError("Provenance hashes do not match supplied files")
        artifact["download_provenance"] = metadata
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    download = sub.add_parser("fetch", help="Download a bounded sequential auth prefix + complete tiny redteam reference")
    download.add_argument("--output-dir", type=Path, default=ROOT / "data" / "lanl")
    download.add_argument("--max-mib", type=int, default=256)
    download.add_argument("--max-seconds", type=float, default=600)
    download.add_argument("--stop-second", type=int)
    study = sub.add_parser("evaluate", help="Evaluate previously acquired LANL files without network access")
    study.add_argument("--auth", type=Path, required=True)
    study.add_argument("--redteam", type=Path, required=True)
    study.add_argument("--prefix", action="store_true", help="Allow unverified gzip prefix and exclude its final timestamp")
    study.add_argument("--provenance", type=Path)
    study.add_argument("--budget", type=float, default=.01)
    study.add_argument("--output", type=Path, default=ROOT / "experiments" / "lanl-study.json")
    args = parser.parse_args()
    try:
        if args.command == "fetch":
            result = fetch(args.output_dir.resolve(), args.max_mib * 1024**2, args.max_seconds, args.stop_second)
            print(json.dumps({"downloaded_bytes": {name: entry["compressed_bytes"] for name, entry in result["files"].items()},
                              "pilot_scan": result["pilot_scan"], "elapsed_seconds": result["elapsed_seconds"]}))
        else:
            # Fail before the long streaming passes when report writes are denied.
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=args.output.parent, prefix=".lanl-write-check-", delete=True):
                pass
            result = evaluate(args.auth, args.redteam, prefix=args.prefix, budget=args.budget, provenance=args.provenance)
            atomic_json(args.output, result)
            print(json.dumps({"source_rows": result["scan"]["source_rows"], "test_rows": result["partitions"]["test"]["events"],
                              "detection_metrics_eligible": result["labels"]["detection_metrics_eligible"], "output": str(args.output)}))
    except (OSError, ValueError, zlib.error) as error:
        # Parser errors deliberately omit malformed source lines and identifiers.
        print("LANL study failed: " + type(error).__name__ + ". No raw records printed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
