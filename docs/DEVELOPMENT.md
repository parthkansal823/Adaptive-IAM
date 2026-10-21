# Development

Run commands from the repository root. See [README](../README.md) for installation and two-terminal startup.

Use **Node.js 24 LTS** and **Python 3.13** to match Docker/CI. The console pins React 19.3.0, TypeScript 7.0.2, Vite 8.3.4 and React Router DOM 7.18.4. Install through `npm ci` after a lockfile update; do not reuse old `node_modules` across runtime/platform changes. [TECH_STACK.md](TECH_STACK.md) links upstream migration guides and explains the choices.

If Windows application control blocks a native dependency, use the Linux Docker build/test workflow and keep the operating-system policy in place. A successful dependency install alone does not validate the authentication flow.

## Everyday commands

| Task | Command on Windows |
| --- | --- |
| Install | `.\scripts\setup.ps1` |
| API + UI together | `npm run dev` |
| API | `.\scripts\dev.ps1 -Service backend` |
| UI | `.\scripts\dev.ps1 -Service frontend` |
| Full checks | `.\scripts\verify.ps1` |
| Research checksums too | `.\scripts\verify.ps1 -Research` |
| Changed-file checks | `.\scripts\verify.ps1 -Changed` |
| Reproduce evaluation | `.venv\Scripts\python.exe experiments/evaluate.py` |
| Small project map | `python scripts/context.py` |
| Prerequisite diagnostics | `npm run doctor` |
| Portable full checks | `npm run check` |
| Checks with browser and isolated live EVM | `npm run check:complete` |
| Reproduce uncertainty stress study | `npm run research:uncertainty` |
| Real enterprise acquisition/evaluation help | `npm run research:lanl -- --help` |
| Additional real authentication release | `npm run research:lanl2014 -- --help` |
| Fixed multi-dataset model comparison | `npm run research:real-auth-models -- --help` |
| Train and tune on real authentication | `npm run research:train-real-auth -- --help` |

`npm run doctor` uses the repository's virtual environment when present, checks Python/Node and direct dependency versions, and reports missing tools without installing anything or reading runtime credentials. A Python version differing from CI is reported explicitly. `npm run check` uses the same interpreter selection and forwards verification arguments, for example `npm run check -- --changed`. Optional browser fixture regressions and browser prerequisites are documented in [frontend/README.md](../frontend/README.md#browser-regression-checks).

The portable runner is `python scripts/verify.py`, using your active interpreter. It runs Python state-transition/security tests, available experiment adapter tests, Node/Python OIDC relying-party tests, and the frontend typecheck/build. It never installs dependencies. Research evaluation is explicit because it trains models and rewrites measured artifacts. Website setup is in [INTEGRATION.md](INTEGRATION.md).

Direct Python verification and Git hooks discover Node/npm on PATH, then a complete trusted official distribution extracted under `.cache/runtime/node-v<VERSION>-<PLATFORM>-<ARCH>` (for example `node-v24.22.0-win-x64`). They run npm through the resolved Node executable and add its directory only to child-process PATH. This supports editor Git processes that lack Node in their inherited PATH without changing global settings or bypassing checks. No runtime is downloaded automatically. Diagnose with `.venv/Scripts/python.exe scripts/doctor.py`; run `.venv/Scripts/python.exe scripts/verify.py --browser --live-web3` when npm itself is unavailable in your terminal. On Unix, use `.venv/bin/python`.

`npm run check:complete` additionally runs the installed Chromium browser against isolated API fixtures and creates a fresh ephemeral loopback Ganache chain for the real API checkpoint/grant tests. The live-chain runner never uses configured IAM RPC, wallet, database or deployment metadata. Its temporary chain and files are closed/removed after the run. It needs the existing blockchain dependencies and Python backend dependencies; no Docker service is required. The separate Besu consensus experiment remains opt-in.

CI runs both browser fixtures and the isolated API/EVM tests. The browser job uses Chrome/Chromium supplied by the [GitHub Ubuntu runner image](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md); local overrides are documented in the frontend README. Full fresh-model research generation is explicit: `npm run research:uncertainty`. Export its measured figure with `.venv/Scripts/python.exe experiments/plot_uncertainty.py` using the analysis requirements. See [the study](UNCERTAINTY_STUDY.md) and [backup operations](BACKUP.md).

## Git hooks

Enable the reviewable repo-local hooks with `git config --local core.hooksPath .githooks`. On Unix, also run `chmod +x .githooks/pre-commit .githooks/pre-push`. Git for Windows uses its bundled shell.

Pre-commit reads index bytes, so it evaluates the actual staged Python/JSON/TOML syntax and common key patterns without printing detected values. Pre-push requires relevant source/test files to match the actual pushed commit; it fails if uncommitted or untracked source would make tests check different code. Review and commit the complete intended changes before pushing. It then checks the pushed diff when its remote base resolves, otherwise it runs full checks. New branches run full checks. These lightweight secret checks are a guardrail, not exhaustive secret discovery.

`scripts/run_tests.py` fails when discovery produces zero tests, the directory is missing, discovery fails or any test fails. CI and local verification use this runner so an incomplete test suite cannot produce a green result.

Hooks do not stage, commit or push anything. Local `.env`, SQLite databases, model artifacts, dependency folders and logs are ignored.

## Codex agents and token economy

The project has compact root/scoped `AGENTS.md`, a bounded `scripts/context.py`, and focused `.codex/agents/` profiles. Agents inherit your selected model and reasoning setting. The concurrency limit is three spawned agents excluding the main thread; use narrower delegation when work overlaps. Subagents themselves consume tokens, so summaries and targeted reads matter.

`SessionStart` matches `startup|resume|clear|compact` and supplies at most 4,000 characters of curated file map plus `docs/STATUS.md`. It does not read transcripts, environment files, source datasets, or full papers. Compaction restoration uses the documented `SessionStart` context contract; `PostCompact` has no documented additional-context contract.

Project `.codex/` config and non-managed hooks must be reviewed and trusted using `/hooks`. Changed definitions need review again. No trust-bypass flag is used. Templates remain under `config/codex/` for review and recovery. Consult the [official hooks](https://learn.chatgpt.com/docs/hooks) and [custom agents](https://learn.chatgpt.com/docs/agent-configuration/subagents) documentation for current behavior.

## Scientific figures in Linux Docker

The analysis image supplies pinned scientific dependencies independently of the Windows Python installation. This also supports machines whose application-control policy blocks a native plotting extension; the workflow does not require changing that policy.

```powershell
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm --build analysis python experiments/evaluate.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/robustness.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/candidate_study.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/cases.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/plot_results.py
```

Run from the repository root. The container has no network and writes only the mounted experiment outputs plus temporary files. Figures in `experiments/figures/` derive from the checked-in JSON evidence; PNGs support preview and SVGs support publication. A new scientific dataset or training change requires regenerating the underlying experiment first, rather than redrawing old results as new evidence.

## Optional external dataset

The [RBA dataset](https://github.com/das-group/rba-dataset) is a creator-synthesized public dataset, not raw organizational login telemetry; the creator cautions against production use. Download its plain CSV separately and review its license/provenance. Keep it under ignored `data/`.

```powershell
.venv\Scripts\python.exe scripts/evaluate_rba.py --csv data/rba.csv --max-rows 200000 --output experiments/results/rba.json
```

The adapter follows input row chronology, uses only past history, excludes target-derived features, and separates training, calibration, threshold selection and test intervals (60/10/10/20). File rows must already be chronological. See the generated report for schema, accepted rows, metrics and limitations. This supplements synthetic experiments without claiming production validation.

## Optional local model configuration

The default application needs no external model service. Set environment variables before launching the API; it does not automatically load a `.env` file.

| Variable | Purpose / default |
| --- | --- |
| `IAM_DATA_DIR` | SQLite directory; default `backend/data` |
| `IAM_OLLAMA_MODEL` | Installed local Ollama model name; empty means deterministic reviewers |
| `IAM_OLLAMA_URL` | Loopback HTTP endpoint; default `http://127.0.0.1:11434` |
| `IAM_LLM_MAX_CALLS` | Per-process cap, default 20, bounded 0–100 |
| `IAM_BERT_MODEL_PATH` | Existing local classifier directory with `legitimate` / `suspicious` labels |

Ollama receives organizational IDs and resource metadata, not the untrusted justification text. Requests have a two-second timeout, bounded generated output, one-hour suggestion cache and policy validation. Failure returns the deterministic selection. BERT requires separately installed Transformers/runtime dependencies and a task-trained local artifact; it uses local-files-only loading and is unmeasured by the default benchmark. A capability field shows which optional engines are available.

Example with your installed Ollama model:

```powershell
$env:IAM_OLLAMA_MODEL = 'your-installed-model'
$env:IAM_LLM_MAX_CALLS = '10'
.\scripts\dev.ps1 -Service backend
```

## Change workflow

Own a narrow module; use bounded searches; update the API guide and frontend contract together for schema changes. Use fresh seeded evaluation when model/data behavior changes. Review generated metrics rather than manually improving reported numbers. Keep `docs/STATUS.md` small enough to be useful after context compaction.
