"""Freeze and run the fixed offline user/computer novelty comparison."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.real_auth_models import freeze, run_study  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("freeze", "evaluate"))
    parser.add_argument("--output", type=Path, default=ROOT / "experiments" / "real-auth-model-study.json")
    parser.add_argument("--lanl-auth", type=Path)
    parser.add_argument("--lanl-redteam", type=Path)
    parser.add_argument("--lanl-report", type=Path, default=ROOT / "experiments" / "lanl-study.json")
    parser.add_argument("--additional-auth", type=Path)
    parser.add_argument("--additional-provenance", type=Path)
    args = parser.parse_args()
    if bool(args.lanl_auth) != bool(args.lanl_redteam):
        parser.error("Supply both LANL auth and redteam files")
    if args.command == "freeze":
        report = freeze(args.output)
        print(json.dumps({"status": report["status"], "protocol_sha256": report["protocol_sha256"]}))
    else:
        report = run_study(args.output, args.lanl_auth, args.lanl_redteam, args.lanl_report,
                           args.additional_auth, args.additional_provenance)
        print(json.dumps({"status": report["status"], "datasets": {name: {"test_events": result["partitions"]["test"]["events"],
                          "known_test_tuples": result["partitions"]["test"]["known_redteam_unique_tuples"]}
                          for name, result in report["datasets"].items()}}))


if __name__ == "__main__":
    main()
