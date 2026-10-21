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


def phase(name, extra=None, results=None):
    arguments = ["run", "--rm", "--no-deps", "-e", "IAM_QBFT_PHASE="+name]
    if extra is not None:
        arguments += ["-e", "IAM_QBFT_RECOVERY_START="+str(extra)]
    if results:
        arguments += ["-e", "IAM_QBFT_RESULTS_FILE=/results/"+results]
    run(*arguments, "qbft-tests")


def wait_for_signer():
    # RPC chain-ID health can precede the first fresh QBFT finalization. Allow
    # the isolated signer's fail-closed restart policy to recover during boot.
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        result = subprocess.run(["docker", "inspect", "--format", "{{.State.Health.Status}}", PROJECT+"-registry-signer-1"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip() == "healthy":
            return
        time.sleep(2)
    raise RuntimeError("Disposable QBFT signer did not become healthy within 180 seconds")


def main():
    parser = argparse.ArgumentParser(description="Run the separate synthetic QBFT outage study")
    parser.add_argument("--keep", action="store_true", help="Keep isolated test containers and volumes for inspection")
    parser.add_argument("--primary-outage", action="store_true", help="Also test validator 1 failure and save separate failover evidence")
    args = parser.parse_args()
    results = "qbft-failover-results.json" if args.primary_outage else None
    # This exact project is reserved for disposable tests, never live IAM state.
    run("down", "--volumes", "--remove-orphans")
    try:
        run("up", "--build", "-d")
        wait_for_signer()
        phase("baseline", results=results)
        if args.primary_outage:
            run("stop", "qbft1")
            phase("primary_down", results=results)
            run("up", "-d", "--wait", "--no-deps", "qbft1")
        run("stop", "qbft4")
        phase("one_down", results=results)
        run("stop", "qbft3")
        phase("two_down", results=results)
        recovery_started = time.time()
        run("start", "qbft3", "qbft4")
        phase("recovered", recovery_started, results=results)
        print("Measured private-network evidence: experiments/"+(results or "qbft-results.json"))
    finally:
        if not args.keep:
            run("down", "--volumes", "--remove-orphans")


if __name__ == "__main__":
    main()
