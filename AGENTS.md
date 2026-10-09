# Adaptive IAM / Aegis

Research prototype. Preserve original research assets; see `docs/RESEARCH_INDEX.md`.

## Read only what is needed

- Start with `docs/STATUS.md`; use `python scripts/context.py` for the small project map.
- `backend/` owns APIs, security policy, SQLite audit ledger; read its scoped `AGENTS.md`.
- `frontend/` owns the React UI; read its scoped `AGENTS.md`.
- `experiments/` owns reproducible datasets and evaluation. `docs/RESEARCH.md` distinguishes measured evidence from paper projections.
- Read full papers only for a research-specific question. Avoid dumps of lockfiles, binaries, datasets, `.env`, logs, and model artifacts.

## Work conventions

- Use bounded `rg` searches and targeted reads. Independent subtasks can run in parallel with clear file ownership; return concise findings with file paths.
- Treat the paper as research motivation, not a mandate to preserve weak assumptions. Explain deviations in docs.
- Never describe synthetic scores as real deployment results. Human access votes are not ground-truth attack labels.
- Authorization must remain server enforced. LLMs may recommend eligible reviewers; they must never grant access or bypass policy.
- Keep audit events free of credentials, tokens, OTPs and raw secret-bearing prompts.
- Hash chaining in SQLite is a local tamper-evident audit log, not a distributed blockchain or tamper-proof store.
- Run relevant checks after changes; avoid full suites for prose-only edits. API/schema changes need backend checks and frontend build.
- Keep `docs/STATUS.md` short and current; document behavior/API changes alongside implementation.

## Commands

`python scripts/check.py --all` performs lightweight syntax and secret checks. `python scripts/verify.py` runs project checks. See `README.md` for setup and launch commands.

