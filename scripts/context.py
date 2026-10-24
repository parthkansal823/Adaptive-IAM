"""Bounded project context for people and trusted Codex lifecycle hooks."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MAP = """Adaptive IAM: local research prototype.
backend/ - Python API, identity/challenges, risk, reviews, timed grants, SQLite audit, tests.
frontend/ - React/Vite console, API client, responsive dark/light themes.
integrations/ - Node/Python OIDC clients, protected websites, security tests.
blockchain/ - Solidity registry, local EVM and optional four-validator QBFT network.
deployment/ + compose.yaml - restricted Docker environment, local Web3 operations.
experiments/ - seeded baseline/candidate evaluation and measured reports.
reports/ + docs/paper/ - evidence report, manuscript draft and verified bibliography.
research/ - 31 original assets; docs/RESEARCH_INDEX.md maps preserved filenames.
docs/ - STATUS, TECH_STACK, SAAS_WEBSITE, ARCHITECTURE, RESEARCH, SECURITY, API.
scripts/ - setup/dev/verify/check; .codex/ - reviewed hooks and focused agents.
Read root + scoped AGENTS.md; target searches to owned modules.
Do not dump datasets, paper extracts, binaries, lockfiles, .env or secret-bearing logs.
Synthetic results are not real deployment accuracy; SQLite chaining is not distributed blockchain.
"""


def compact_context() -> str:
    status = ROOT / "docs" / "STATUS.md"
    status_text = status.read_text(encoding="utf-8-sig")[:2200] if status.is_file() else "Status not written."
    return (MAP + "\nCurrent status:\n" + status_text)[:4000]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hook", action="store_true", help="Read lifecycle event JSON; output SessionStart context.")
    args = parser.parse_args()
    if not args.hook:
        print(compact_context())
        return
    # Do not inspect or store transcripts, model prompts, paths or credentials from the event.
    try:
        payload = json.loads(sys.stdin.read(65536) or "{}")
    except (ValueError, TypeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    if payload.get("hook_event_name", "SessionStart") != "SessionStart":
        print(json.dumps({"continue": True}))
        return
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": compact_context()}}))


if __name__ == "__main__":
    main()
