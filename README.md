# Adaptive IAM Research Console

A local implementation of the supplied adaptive IAM research idea: contextual authentication, natural-language access requests, human reviewer decisions, timed access grants, and a verifiable audit chain. The responsive React console supports dark and light themes.

The paper's performance values are projections. This project measures its own baseline and improved candidates on reproducible synthetic data. Those scores do not establish real deployment performance. SQLite SHA-256 chaining is a local tamper-evident log; distributed blockchain consensus and smart contracts are future work.

## Start on Windows

Prerequisites: Python 3.11+, Node.js 22+, npm and Git. Run from the repository root:

```powershell
.\scripts\setup.ps1
npm run dev
```

`npm run dev` starts the API and frontend together. Ctrl+C stops both. For separate terminals or backend hot reload, use:

```powershell
.\scripts\dev.ps1 -Service backend
# In another terminal:
.\scripts\dev.ps1 -Service frontend
```

Open the frontend URL printed by Vite (normally `http://127.0.0.1:5173`). API reference: `http://127.0.0.1:8000/docs`. Both development servers bind to loopback by default. [Connect your own website](docs/INTEGRATION.md) with registered OAuth/OIDC login and server-enforced resource permissions.

If local PowerShell policy blocks a script, execute its documented commands directly rather than changing machine policy:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend/requirements-dev.txt
npm.cmd --prefix frontend ci
npm.cmd --prefix integrations/node ci
.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
npm.cmd --prefix frontend run dev
```

## macOS / Linux

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements-dev.txt
npm --prefix frontend ci
npm --prefix integrations/node ci
npm run dev
```

## Verify and reproduce

```powershell
.\scripts\verify.ps1 -Research
.venv\Scripts\python.exe experiments/evaluate.py
python scripts/context.py
```

Evaluation writes measured results to `experiments/results.json`; model artifacts and local SQLite runtime data are ignored by Git. [RESEARCH.md](docs/RESEARCH.md) explains comparison design and limitations. [DEVELOPMENT.md](docs/DEVELOPMENT.md) covers hooks, optional models and contribution workflow.

## Repository guide

| Path | Purpose |
| --- | --- |
| `backend/` | Python API, models, policy enforcement and security tests |
| `frontend/` | React/TypeScript interface and theme system |
| `integrations/` | Node/Python OIDC server SDKs, protected website examples and tests |
| `experiments/` | Reproducible model evaluation and measured result reports |
| `research/` | 31 preserved originals arranged by type |
| `docs/` | Architecture, API, security, research, development and roadmap |
| `scripts/` | Setup/dev/checks and bounded agent context |
| `.codex/` | Project agents and reviewable lifecycle hook configuration |

All original paper, proposal, report, slide and diagram filenames were preserved. [RESEARCH_INDEX.md](docs/RESEARCH_INDEX.md) maps every old location to its new location with a SHA-256 manifest. No original paper content was edited.

## Developer setup

`setup.ps1` installs dependencies and sets the repository's Git hook path. Pre-commit checks staged syntax/secrets; pre-push runs relevant tests/build. The project includes short root/scoped `AGENTS.md` instructions and focused agent profiles without overriding your chosen model.

Codex lifecycle hooks restore at most 4,000 characters of curated context at session start/resume/compaction. Review and trust the project hook definitions through `/hooks` before relying on them. Files alone do not activate Codex hooks. See the [official hook guide](https://learn.chatgpt.com/docs/hooks).

Source changes and Git commits remain yours to review and commit. Do not deploy this research prototype as a production identity provider without the work in [SECURITY.md](docs/SECURITY.md).

## License & Usage

© 2026 Parth Kansal & Niyati. All Rights Reserved.

This project is a joint academic work developed as part of a college major project.
No part of this repository may be used, copied, modified, or distributed without explicit written permission from ALL authors.
