# Backend scope

Read `../docs/ARCHITECTURE.md` and the relevant module before editing. Use `python scripts/run_tests.py -s backend/tests` for security and HTTP integration checks (fails if no tests are discovered). Test dependencies: `python -m pip install -r backend/requirements-dev.txt`. Run `python experiments/evaluate.py` only when ML features, models or evaluation change. Tests use temporary databases; never change the workspace database to test.

Preserve authenticated actor ownership, expiring single-use MFA, deny-by-default voting, resource-owner quorum and grant expiration on access. NLP and LLM outputs are advisory. Audit logging is a local tamper-evident SHA-256 chain, not distributed consensus. Metrics must identify synthetic data and train/validation/test separation. Do not add credentials or real identities. Demo credentials are intentionally public and gated by demo mode.

OAuth app tokens and console sessions are distinct authorities. Keep exact callback validation, mandatory PKCE S256, single-use expiring code, nonce/audience/issuer-bound RS256 identity tokens, application/resource mapping and identity-bound grant enforcement. App secret appears only at registration; private signing keys stay in ignored runtime data. Disabling an app and token revocation must remove app access immediately.
