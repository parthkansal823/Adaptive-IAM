"""Host-only isolated study driver; does not expose a Docker socket to containers."""
from __future__ import annotations

import argparse
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECT = "adaptive-iam-qbft-check"
BASE = ["docker", "compose", "-p", PROJECT, "-f", "deployment/compose.qbft.yaml"]


def run(*arguments):
    subprocess.run(BASE + list(arguments), cwd=ROOT, check=True, env={**os.environ, "IAM_QBFT_PREFIX": "172.29.84", "IAM_QBFT_SUBNET": "172.29.84.0/24"})


def phase(name, extra=None):
    arguments = ["run", "--rm", "--no-deps", "-e", "IAM_QBFT_PHASE="+name]
    if extra is not None:
        arguments += ["-e", "IAM_QBFT_RECOVERY_START="+str(extra)]
    run(*arguments, "qbft-tests")


def main():
    parser = argparse.ArgumentParser(description="Run the separate synthetic QBFT outage study")
    parser.add_argument("--keep", action="store_true", help="Keep isolated test containers and volumes for inspection")
    args = parser.parse_args()
    # This exact project is reserved for disposable tests, never live IAM state.
    run("down", "--volumes", "--remove-orphans")
    try:
        run("up", "--build", "-d", "--wait")
        phase("baseline")
        run("stop", "qbft4")
        phase("one_down")
        run("stop", "qbft3")
        phase("two_down")
        recovery_started = time.time()
        run("start", "qbft3", "qbft4")
        phase("recovered", recovery_started)
        print("Measured private-network evidence: experiments/qbft-results.json")
    finally:
        if not args.keep:
            run("down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    main()
