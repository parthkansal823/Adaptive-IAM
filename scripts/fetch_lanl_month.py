"""Acquire a fixed, bounded prefix of LANL's second 30-day authentication file.

This is additional time coverage of the same institution and release, not an
independent organization or an attack-labelled dataset. Raw identifiers remain
in ignored data/; only aggregate acquisition evidence is exported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
from datetime import datetime, timezone
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.evaluate_lanl2014 import auth_event, bzip_lines, sha256_file

SOURCE = "https://csr.lanl.gov/data/auth/"
MIRROR = "https://lanl.ma.ic.ac.uk/data/auth/"
FILENAME = "lanl-auth-dataset-1-01.bz2"
EXPECTED_FULL_SHA256 = "3329d782da62084238c4e349754e7feb77768768d6bd05c18c2b7407f5afddc3"
MAX_COMPRESSED_BYTES = 16 * 1024**2
MAX_OUTPUT_BYTES = 512 * 1024**2


def scan_prefix(path: Path) -> dict:
    """Validate all complete rows and exclude the whole final timestamp group."""
    count = group_count = 0
    first = last = previous = None
    with path.open("rb") as handle:
        chunks = iter(lambda: handle.read(65536), b"")
        for line in bzip_lines(chunks, allow_prefix=True, max_output_bytes=MAX_OUTPUT_BYTES):
            event = auth_event(line)
            if last is not None and event.second < last:
                raise ValueError("Authentication rows must be globally chronological")
            if event.second != last:
                previous, last, group_count = last, event.second, 0
            first = event.second if first is None else first
            group_count += 1
            count += 1
    return {"source_rows": count, "selected_rows": count - group_count,
            "source_first_second": first, "source_last_second": last,
            "selected_first_second": first if count > group_count else None,
            "selected_last_second": previous,
            "final_timestamp_rows_excluded": group_count}


def _publish_without_replacing(temporary: Path, target: Path) -> None:
    # Hard-link publication is atomic and fails if a concurrent actor created
    # target. Both paths have the same parent and filesystem.
    os.link(temporary, target)
    temporary.unlink()


def fetch(output_dir: Path, report_path: Path, *, max_bytes=MAX_COMPRESSED_BYTES,
          max_seconds=300) -> dict:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 0 < max_bytes <= MAX_COMPRESSED_BYTES:
        raise ValueError("Acquisition must stay within 16 MiB compressed")
    if isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float)) or not math.isfinite(max_seconds) or not 0 < max_seconds <= 300:
        raise ValueError("Transfer deadline must be finite and within 300 seconds")
    output_dir, report_path = Path(output_dir), Path(report_path)
    target = output_dir / (FILENAME + ".prefix")
    provenance_path = output_dir / "provenance.json"
    destinations = (target, provenance_path, report_path)
    if len({path.resolve() for path in destinations}) != len(destinations):
        raise ValueError("Acquisition and report destinations must be distinct")
    temporary_paths = tuple(path.with_name(path.name + ".tmp") for path in destinations)
    for path in (*destinations, *temporary_paths):
        if path.exists() or path.is_symlink():
            raise ValueError("Output already exists; frozen evidence is never overwritten")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    owned = []
    started = time.monotonic()
    count = 0
    digest = hashlib.sha256()
    content_length = None
    stop_reason = "transfer_deadline"
    try:
        # Reserve all writable outputs before starting a potentially long scan.
        # This also exposes permission problems before a network download.
        for path in temporary_paths:
            with path.open("xb") as handle:
                handle.write(b"" if path == temporary_paths[0] else b"{}\n")
            owned.append(path)
        request = urllib.request.Request(MIRROR + FILENAME, headers={
            "User-Agent": "Adaptive-IAM-offline-auth-research/1.0",
            "Accept-Encoding": "identity"})
        with urllib.request.urlopen(request, timeout=min(10, max_seconds)) as response:
            if response.status != 200:
                raise ValueError("Expected sequential HTTP 200 public source response")
            content_length = response.headers.get("Content-Length")
            with temporary_paths[0].open("wb") as handle:
                while count < max_bytes and time.monotonic() - started < max_seconds:
                    chunk = response.read(min(65536, max_bytes - count))
                    if not chunk:
                        stop_reason = "server_eof"
                        break
                    handle.write(chunk)
                    digest.update(chunk)
                    count += len(chunk)
            if count == max_bytes:
                stop_reason = "compressed_byte_cap"
        scan = scan_prefix(temporary_paths[0])
        if not scan["selected_rows"]:
            raise ValueError("No complete timestamp groups within acquisition bounds")
        provenance = {
            "dataset": "LANL User-Computer Authentication Associations in Time (2014 release)",
            "source_url": SOURCE, "mirror_url": MIRROR, "doi": "10.11578/1160076",
            "license": "LANL waiver of copyright and related or neighboring rights",
            "checksums_url": MIRROR + "checksums.txt", "source_monthly_file_index": 1,
            "monthly_slice_description": "Second published 30-day file; actual calendar dates undisclosed",
            "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
            "download_url": MIRROR + FILENAME, "filename": target.name,
            "compressed_bytes": count, "compressed_prefix_sha256": digest.hexdigest(),
            "expected_full_archive_sha256": EXPECTED_FULL_SHA256,
            "full_archive_sha256_verified": False, "full_bzip2_integrity_verified": False,
            "server_content_length": int(content_length) if content_length else None,
            "limits": {"compressed_bytes": max_bytes, "network_deadline_seconds": max_seconds,
                       "per_request_timeout_seconds": min(10, max_seconds),
                       "decompressed_bytes": MAX_OUTPUT_BYTES},
            "deadline_semantics": "Deadline checked before each read; an outstanding read has a maximum ten-second socket timeout; local parsing is separate",
            "elapsed_seconds_including_validation": round(time.monotonic() - started, 3),
            "stop_reason": stop_reason, "scan": scan}
        report = {"schema_version": "lanl2014-month-data-v1", "synthetic": False,
            "source_real_enterprise": True,
            "evidence_type": "real_enterprise_successful_authentication_without_attack_labels",
            "source": {"kind": "real_enterprise_successful_authentication_without_attack_labels",
                       "bounded_auth_prefix": True, "acquisition": provenance},
            "scan": scan,
            "protocol": {"selection": "Second monthly file, fixed first 16 MiB prefix, chosen before acquisition or outcomes",
                         "tail": "Discard every row at the final observed timestamp",
                         "relative_time": "Original release-relative seconds; never shifted to a calendar epoch"},
            "labels": {"attack_labels_available": False, "detection_metrics_eligible": False,
                       "eligibility_reason": "Successful authentication alone does not establish legitimate intent; source provides no attack labels"},
            "implementation": {"entry_point": "scripts/fetch_lanl_month.py",
                               "sha256": sha256_file(Path(__file__)),
                               "parser_sha256": sha256_file(ROOT / "scripts" / "evaluate_lanl2014.py")},
            "limitations": ["Additional time slice from the same institution and release; not an independent organization or third independent dataset.",
                "Actual collection dates and identity overlap with other releases are undisclosed.",
                "Only a bounded file prefix is acquired, not the full 30-day slice or nine-month release.",
                "Successful-only events have no attack labels and are not a benign training guarantee.",
                "Full-archive SHA-256 and final bzip2 CRC/trailer are not verified; decoder still validates available blocks.",
                "Acquisition statistics alone are not a learned-model evaluation or deployment recommendation."]}
        temporary_paths[1].write_text(json.dumps(provenance, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        temporary_paths[2].write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        for temporary, destination in zip(temporary_paths, destinations):
            _publish_without_replacing(temporary, destination)
        return report
    finally:
        for path in owned:
            path.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "data" / "lanl2014-month01")
    parser.add_argument("--report", type=Path, default=ROOT / "experiments" / "lanl2014-month01-data.json")
    args = parser.parse_args()
    report = fetch(args.output_dir, args.report)
    print(json.dumps({"schema_version": report["schema_version"], "scan": report["scan"],
                      "compressed_bytes": report["source"]["acquisition"]["compressed_bytes"]}))


if __name__ == "__main__":
    main()
