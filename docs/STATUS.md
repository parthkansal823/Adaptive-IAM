# Project status

Research assets: 31 originals organized under `research/`, with verified SHA-256 checksums.

Implementation: local adaptive IAM research console, Python API, React frontend, and reproducible experiments. This is a prototype using synthetic data; real deployment accuracy is unestablished.

Security boundary: server-side identities, risk policy, reviewer eligibility, timed grants, and a local SQLite SHA-256 audit chain. External LLM/BERT components are optional. The ledger is not a distributed blockchain.

Development: root/scoped agent instructions, compact context helper, Git checks, CI, and project Codex config. Lifecycle hook definitions require review/trust through Codex `/hooks`; creating files alone does not activate them.

Next evidence: keep `experiments/results.json` current after model or dataset changes; optional RBA reports live in `experiments/results/`. Production work requires trusted telemetry, independent external data, stronger MFA/SSO, distributed audit anchoring, and operational validation.
