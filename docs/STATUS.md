# Project status

21 October 2026. Research prototype; all 31 original assets remain checksum-verified under `research/`. Measured reports disclose sampling, regressions and evidence limits.

Implemented: Python API; React dark/light console; passkeys, TOTP/recovery; observed-context session checks; OAuth/OIDC + PKCE; Node/Python SDKs; organization onboarding/rotation; attack diagnostics; owner/quorum review and timed grants. Orbit SaaS uses sample records and live IAM permissions. [Website guide](SAAS_WEBSITE.md).

Authority remains server-enforced; models/LLMs advise only. SQLite chaining is local tamper evidence. Optional EVM access denies on RPC failure. Four Besu validators share one administrative host. Docker/CI target Python 3.13 and Node 24 LTS; the local interpreter is Python 3.11.

Reliability additions: encrypted same-host Node website sessions survive restart and share revocation; [offline backup/restore](BACKUP.md) validates state and keys before installation; access search/filters and expiry-aware displays remove elapsed authority. Final website permission checks enforce expiry after session reads. Direct Python/Git-hook checks discover trusted portable Node/npm without global PATH changes.

Research: the [uncertainty study](UNCERTAINTY_STUDY.md) measures five fresh fits and four stress conditions; extra verification increases both exercise detection and legitimate friction in simulation, with telemetry/coverage failures disclosed. The [real LANL study](LANL_STUDY.md) scans 37,752,359 source rows, selects 4,394,776 logins, and tests 886,224 events. Edge surprise flags 8/10 known exercise tuples plus 7,484/886,214 unlabeled events. This targeted historic prefix cannot establish production accuracy or a false-positive rate. Both frozen reports are served/exported in Experiments. The older external RBA corpus is creator-synthesized.

Verification, 21 October: complete verifier exited 0: 127 backend cases (six opt-in skips), 75 script cases (one Windows privilege skip), 24 research cases, 12 Python SDK, 49 Node integration, 15 contract/RPC, 11 isolated live-chain API and 15 browser fixtures. Typecheck/build and all asset checksums passed. API/website Docker images built; read-only non-root website session restart/revocation passed. Backup tests also ran on Linux/Python 3.13. Besu consensus and full live-provider Docker flows retain their earlier dated evidence.

Current extension: another genuine LANL authentication dataset and a stronger, fixed sequential novelty candidate are being evaluated. Existing results remain frozen; no sparse-label study automatically replaces runtime policy. Independent organizational labels, trusted telemetry, human annotation, multi-host sessions and external interoperability/security review remain boundaries. Commits/pushes remain the user's responsibility.
