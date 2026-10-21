"""Freeze or fit/evaluate the fixed real authentication IsolationForest study."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiments.real_auth_training import freeze, run_study  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("freeze", "train"))
    parser.add_argument("--output", type=Path, default=ROOT / "experiments" / "real-auth-training.json")
    parser.add_argument("--artifacts", type=Path, default=Path("data/real-auth-models"))
    parser.add_argument("--datasets", nargs="+", choices=("lanl2015_retrospective", "lanl2014_month00", "lanl2014_month01"),
                        default=("lanl2015_retrospective", "lanl2014_month00", "lanl2014_month01"))
    args = parser.parse_args()
    if args.command == "freeze":
        report = freeze(args.output)
        print(json.dumps({"status": report["status"], "protocol_sha256": report["protocol_sha256"]}))
        return
    descriptors = {
        "lanl2015_retrospective": {"kind": "lanl2015", "auth": ROOT / "data/lanl/study/auth.txt.gz.prefix",
            "metadata": ROOT / "experiments/lanl-study.json", "redteam": ROOT / "data/lanl/study/redteam.txt.gz"},
        "lanl2014_month00": {"kind": "monthly", "auth": ROOT / "data/lanl2014/lanl-auth-dataset-1-00.bz2.prefix",
            "metadata": ROOT / "data/lanl2014/provenance.json"},
        "lanl2014_month01": {"kind": "monthly", "auth": ROOT / "data/lanl2014-month01/lanl-auth-dataset-1-01.bz2.prefix",
            "metadata": ROOT / "data/lanl2014-month01/provenance.json"},
    }
    selected = [{"name": name, **descriptors[name]} for name in args.datasets]
    for item in selected:
        for key in ("auth", "metadata", "redteam"):
            if key in item and not item[key].is_file():
                parser.error("Missing actual dataset input: " + str(item[key]))
    report = run_study(args.output, args.artifacts, selected)
    print(json.dumps({"status": report["status"], "datasets": list(report["datasets"])}))


if __name__ == "__main__":
    main()
