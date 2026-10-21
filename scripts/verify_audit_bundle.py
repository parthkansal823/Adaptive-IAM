"""Offline, bounded audit inclusion verification; performs no network requests."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.audit_proofs import MAX_BUNDLE_BYTES, decode_bundle, verify_bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="Hash-only audit-inclusion-v1 JSON export")
    parser.add_argument("--expected-root", help="Lowercase SHA-256 root obtained from an independently trusted context")
    args = parser.parse_args()
    try:
        with args.bundle.open("rb") as source:
            data = source.read(MAX_BUNDLE_BYTES + 1)
        result = verify_bundle(decode_bundle(data), args.expected_root)
    except (OSError, ValueError, TypeError, RecursionError):
        print(json.dumps({"inclusion_valid": False, "trusted_root_match": None, "anchor_checked": False, "error": "Invalid, unsupported or oversized audit proof"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["inclusion_valid"] and result["trusted_root_match"] is not False else 1


if __name__ == "__main__":
    raise SystemExit(main())
