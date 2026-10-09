# Development

Run commands from the repository root. See [README](../README.md) for installation and two-terminal startup.

## Everyday commands

| Task | Command on Windows |
| --- | --- |
| Install | `.\scripts\setup.ps1` |
| API | `.\scripts\dev.ps1 -Service backend` |
| UI | `.\scripts\dev.ps1 -Service frontend` |
| Full checks | `.\scripts\verify.ps1` |
| Research checksums too | `.\scripts\verify.ps1 -Research` |
| Changed-file checks | `.\scripts\verify.ps1 -Changed` |
| Reproduce evaluation | `.venv\Scripts\python.exe experiments/evaluate.py` |
| Small project map | `python scripts/context.py` |

The portable runner is `python scripts/verify.py`, using your active interpreter. It runs Python state-transition/security tests, available experiment adapter tests, and the frontend typecheck/build. It never installs dependencies. Research evaluation is explicit because it trains models and rewrites measured artifacts.

## Git hooks

Enable the reviewable repo-local hooks with `git config --local core.hooksPath .githooks`. On Unix, also run `chmod +x .githooks/pre-commit .githooks/pre-push`. Git for Windows uses its bundled shell.

Pre-commit reads index bytes, so it evaluates the actual staged Python/JSON/TOML syntax and common key patterns without printing detected values. Pre-push checks the pushed diff when its remote base resolves, otherwise it runs full checks. New branches run full checks. These lightweight secret checks are a guardrail, not exhaustive secret discovery.

Hooks do not stage, commit or push anything. Local `.env`, SQLite databases, model artifacts, dependency folders and logs are ignored.

## Codex agents and token economy

The project has compact root/scoped `AGENTS.md`, a bounded `scripts/context.py`, and focused `.codex/agents/` profiles. Agents inherit your selected model and reasoning setting. The concurrency limit is three spawned agents excluding the main thread; use narrower delegation when work overlaps. Subagents themselves consume tokens, so summaries and targeted reads matter.

`SessionStart` matches `startup|resume|clear|compact` and supplies at most 4,000 characters of curated file map plus `docs/STATUS.md`. It does not read transcripts, environment files, source datasets, or full papers. Compaction restoration uses the documented `SessionStart` context contract; `PostCompact` has no documented additional-context contract.

Project `.codex/` config and non-managed hooks must be reviewed and trusted using `/hooks`. Changed definitions need review again. No trust-bypass flag is used. Templates remain under `config/codex/` for review and recovery. Consult the [official hooks](https://learn.chatgpt.com/docs/hooks) and [custom agents](https://learn.chatgpt.com/docs/agent-configuration/subagents) documentation for current behavior.

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
