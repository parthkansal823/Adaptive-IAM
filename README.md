# Adaptive IAM Research Console

A local implementation of the supplied adaptive IAM research idea: contextual authentication, natural-language access requests, human reviewer decisions, timed access grants, and a verifiable audit chain. The responsive React console supports dark and light themes.

The paper's performance values are projections. This project measures its own baseline and candidates on reproducible synthetic data, including regressions. SQLite SHA-256 chaining is a local tamper-evident log; the Docker environment adds a real local Ethereum/Solidity registry for audit checkpoints and timed grants. A single development chain does not establish decentralized production trust.

## Start in Docker

Start Docker Desktop and run from this folder:

```powershell
docker compose up --build -d
docker compose ps
```

Open [Adaptive IAM](http://127.0.0.1:5173/) and [API docs](http://127.0.0.1:8000/docs). Sign in with a listed demo identity and password `Demo@123!`. Containers run without root with read-only filesystems and restricted privileges; the Ethereum RPC remains inside the internal Docker network. The API and console are published only to this computer. [Deployment guide](deployment/README.md) explains persistence, grant confirmation, revocation and safe shutdown. Stop host development servers before using the same ports in Docker.

The console tooling uses React 19.3, TypeScript 7 and Vite 8. Docker/CI use Node.js 24 LTS and Python 3.13. [Technology decisions](docs/TECH_STACK.md) records official sources, selected upgrades, alternatives and remaining deployment work.

```powershell
docker compose stop
docker compose up -d
```

For the provider plus a separately protected demonstration website on port 3001:

```powershell
docker compose -f compose.yaml -f deployment/compose.website.yaml --profile website up --build -d --wait
```

Open [Orbit SaaS workspace](http://127.0.0.1:3001/) for the separate business website: product home, plans, signed-in dashboard, searchable sample projects, protected reports and account settings. Business data/pricing are illustrative; identity and permission checks use the running IAM provider. [SaaS walkthrough](docs/SAAS_WEBSITE.md) covers the sign-in and access journey.

The [integration guide](docs/INTEGRATION.md) explains consent, human grants and reusable Node/Python SDKs. Security now supports verified passkeys, TOTP, single-use recovery codes and server-observed session checks. Public passwords/displayed challenges remain explicit demo features until a real factor is enrolled. [Authentication](docs/AUTHENTICATION.md) documents enrollment, private operator provisioning and `IAM_DEMO_MODE=false`; private first sign-in is limited to five minutes of factor setup before it can access protected APIs.

The Developer portal adds organizations, an application wizard, exact callback diagnostics and confidential-secret rotation. New organization/app security changes require recent real-factor verification. The Attack lab provides 12 recorded diagnostics from the running model and current owned permissions; it cannot create grants or cast votes. Organization membership scopes app management but seeded resources remain shared research infrastructure, not complete tenant isolation.

An optional [four-validator QBFT network](docs/WEB3_NETWORK.md) uses Besu and an isolated narrow signer; its console runs separately on port 15173. Actual outage/latency readings are in `experiments/qbft-results.json`. All local validators still share one administrative host.

## Start on Windows

Recommended prerequisites: Python 3.13, Node.js 24 LTS, npm and Git, matching Docker/CI. Other runtime versions need their own compatibility checks. Run from the repository root:

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
npm.cmd --prefix blockchain ci
.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
npm.cmd --prefix frontend run dev
```

## macOS / Linux

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements-dev.txt
npm --prefix frontend ci
npm --prefix integrations/node ci
npm --prefix blockchain ci
npm run dev
```

## Verify and reproduce

The Experiments screen includes an [uncertainty and distribution-shift study](docs/UNCERTAINTY_STUDY.md): five fresh fits, conformal prediction sets, four held-out conditions and explicit detection/friction costs. Its measured JSON and [exported figure](experiments/figures/uncertainty-study.svg) accompany the code. Reproduce with `npm run research:uncertainty`; it does not replace the deployed model.

Node website sessions can survive restarts using encrypted local SQLite; the Docker website enables this in its own volume. [Integration settings](docs/INTEGRATION.md) describe keys and same-host workers. [Offline backup/restore](docs/BACKUP.md) preserves IAM SQLite state, signing identity and enrolled-factor keys with validation before installation.

Run `npm run check:complete` to include installed-browser regressions and fresh isolated live-chain API checks. The command preserves existing IAM/chain state and requires no running Docker stack.

Run `npm run doctor` to check runtimes and installed dependency versions without changing configuration. `npm run check` uses the repository's virtual environment and runs the same project checks on Windows, macOS and Linux. It also accepts `npm run check -- --changed`.

```powershell
.\scripts\verify.ps1 -Research
.venv\Scripts\python.exe experiments/evaluate.py
python scripts/context.py
```

Evaluation writes measured results to `experiments/results.json`; model artifacts and local SQLite runtime data are ignored by Git. [RESEARCH.md](docs/RESEARCH.md) explains comparison design and limitations, with [paired uncertainty](experiments/robustness.json), [independent candidate selection](experiments/candidate-study.json) and [32 runtime language cases](experiments/case-study.json). The [evidence report](reports/Adaptive%20IAM%20evidence%20study.md), [manuscript draft](docs/paper/MANUSCRIPT.md) and [verified readings](research_notes/Adaptive%20IAM%20evidence%20study/readings.md) support a new paper. [DEVELOPMENT.md](docs/DEVELOPMENT.md) covers network-free Docker analysis, hooks, optional models and contribution workflow.

The latest studies add [five complete retraining runs](experiments/risk-protocol.json), [external synthesized-data eligibility and proxy holdouts](experiments/external-study.json), [multilingual diagnostics](experiments/multilingual-results.json) and an [independent human annotation workflow](docs/ANNOTATION.md). Calibration improves probability error, while equally tuned raw/calibrated controls make identical decisions. External proxy results include a user-disjoint regression; only three takeover labels occur in the sample, so no takeover score is claimed. All readings and figures remain reviewable alongside the manuscript.

## Repository guide

| Path | Purpose |
| --- | --- |
| `backend/` | Python API, models, policy enforcement and security tests |
| `frontend/` | React/TypeScript interface and theme system |
| `integrations/` | Node/Python OIDC server SDKs, protected website examples and tests |
| `blockchain/` | Solidity registry, local-chain deployment and contract tests |
| `deployment/`, `compose.yaml` | Docker isolation, local Web3 stack and operations |
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
