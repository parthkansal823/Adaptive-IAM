# Project status

Research prototype. All 31 originals remain under `research/` with SHA-256 checksums. Synthetic measurements are not production accuracy; reports disclose limitations/regressions.

Implemented: Python API; React dark/light UI; passkeys, TOTP/recovery; session checks; OAuth/OIDC + PKCE; Node/Python SDKs; organization onboarding; secret rotation; attack diagnostics; owner/quorum review and timed grants. Orbit SaaS on port 3001 uses sample records and live IAM permissions. See `docs/SAAS_WEBSITE.md`.

Authority: server-enforced identity, policy and grants; NLP/LLMs advise only. SQLite chaining is local tamper evidence. EVM checks deny on RPC failure. Ganache is a development chain; four-validator Besu QBFT shares one host administrator, not independent operational trust.

Upgrade, 14 October 2026: React 19.3.0, TypeScript 7.0.2, Vite 8.3.4, React Router DOM 7.18.4; Docker/CI use Python 3.13 and Node 24 LTS. [Technology choices](TECH_STACK.md) and [Web3 upgrades](WEB3_UPGRADES.md) document sources and boundaries. Next.js/PostgreSQL were reviewed; neither is installed. SQLite remains local storage.

Reliability, 17 October: standard OAuth Basic client authentication; overlapping confirmed-grant selection with strict local expiry; session-safe asynchronous UI actions; retryable Attack lab; eight unique callback URLs; authenticated website-config reuse and non-destructive recovery. `npm run doctor` diagnoses prerequisites; `npm run check` is portable. API/onboarding/recovery guides and regression checks accompany the changes.

Verification, 17 October: full `npm run check` passed on Python 3.11 / Node 24.22: 117 backend cases including six opt-in live-chain skips, 33 Node integration, 15 contract/RPC, 12 Python SDK, 15 script and seven research-protocol cases. Two additional expiry-boundary cases passed after final review (119 backend cases total). TypeScript/Vite build, six headless Edge fixture cases, dependency diagnostics and all 31 asset checksums passed. Python 3.13 remains the Docker/CI target. Browser fixtures are reproducible via `frontend/tests/console-regression.mjs`; they do not replace live-provider testing.

Prior live evidence, 14 October: isolated Ganache/API, Docker OIDC and all five Besu failover/outage/recovery phases passed. These Docker/live-network checks were not rerun on 17 October. See `experiments/qbft-failover-results.json` and `docs/images/README.md`.

Evidence: experiment JSON files disclose results and limits. External data is author-synthesized; scarce takeover labels do not support a takeover score. Independent annotation, trusted telemetry, security/interoperability review, shared sessions and recovery remain boundaries.

Workflow: scoped agents, compact context, Git checks and CI. Codex hooks need trust through `/hooks`. Commits/pushes remain the user's responsibility.
