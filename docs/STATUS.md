# Project status

Research assets: 31 originals organized under `research/`, with verified SHA-256 checksums.

Implementation: adaptive IAM console, Python API, React dark/light UI, registered OAuth/OIDC website sign-in, Node/Python permission SDKs and reproducible experiments. Docker adds a real local Ethereum/Solidity registry. This is a synthetic-data prototype; real deployment accuracy is unestablished.

Security boundary: server-side identity, risk, eligible owner/quorum review and timed grants. SQLite audit chaining remains local. When Web3 is configured, live local contract grants/checkpoints also gate resource access; RPC failure denies access. Ganache is one trusted local development chain, not independent distributed consensus. LLM/BERT are optional advisers.

Development: root/scoped agent instructions, compact context helper, Git checks, CI, and project Codex config. Lifecycle hook definitions require review/trust through Codex `/hooks`; creating files alone does not activate them.

Evidence: `experiments/results.json`, `robustness.json`, `candidate-study.json` and 32 diagnostic runtime language cases disclose gains, regressions and abstentions. The report/manuscript and verified readings document the research boundary. No external benchmark is claimed yet.

Verification, 10 October 2026: the complete project verifier passed (60 backend tests plus five optional live-RPC skips, four history-feature tests, 12 Python SDK tests, 13 Node SDK tests, two Solidity tests and frontend build). Separate isolated Docker execution passed all 11 blockchain tests, including live RPC, and a live OIDC smoke flow covered PKCE, signed identity, human approval, contract grants, revocation and client disable. Browser checks confirmed dark/light UI, narrow consent layout and a connected website's protected page; captures are in `docs/images/`. Production still needs trusted telemetry, independent data, verified MFA, protocol review and operational validation.
