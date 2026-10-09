"""Run unittest discovery and reject empty suites instead of silently succeeding."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-s", "--start-directory", required=True)
    parser.add_argument("-p", "--pattern", default="test*.py")
    args = parser.parse_args()
    directory = Path(args.start_directory)
    if not directory.is_dir():
        print(f"Test directory does not exist: {directory}", file=sys.stderr)
        return 1
    try:
        suite = unittest.defaultTestLoader.discover(str(directory), pattern=args.pattern)
    except (ImportError, OSError) as exc:
        print(f"Test discovery failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    count = suite.countTestCases()
    if count == 0:
        print(f"No tests discovered in {directory}; refusing an empty-suite success.", file=sys.stderr)
        return 1
    print(f"Discovered {count} tests in {directory}.", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
