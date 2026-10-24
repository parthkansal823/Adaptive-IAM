# Code and research review

24 October 2026. This review combines manual inspection of security and research paths with repository-wide verification. It records concrete fixes and their limits; passing tests cannot establish that every line is defect-free or replace independent security and scientific review. Existing frontend/documentation work and all original research assets were preserved.

## Corrected findings

| Area | Finding and correction | Regression evidence |
| --- | --- | --- |
| Console identity | A session could expire or be revoked between token lookup and the security guard. The guard reloads live session authority and current server-owned identity roles. | Backend identity expiry, revocation and role-refresh tests. |
| Website permissions | An app, token, source session or resource mapping could change after dependency authentication. Permission checks reload authority within the grant transaction and recheck credential deadlines after chain calls. Detected step-up transitions persist even when access is denied. | OAuth disable/revoke/mapping races, delayed checks and durable step-up tests. |
| Factor enrollment | An outstanding demo challenge could still succeed after a real factor was enrolled. Demo verification now requires that no factor is enrolled. | Outstanding-demo-challenge enrollment regression. |
| Advisory language model | The optional BERT path accepted low-support labels despite the documented abstention rule. It now returns `uncertain` below 0.65 support. | Local BERT confidence boundary tests; no new BERT performance claim. |
| OIDC SDK lifetime | Fetching signing keys and UserInfo restarted the local access-token lifetime. Both SDKs anchor `expires_in` before the token request and reject a token expiring during verification. | Delayed verification tests in Node and Python. |
| Python website | Duplicate callback fields and Unicode state were handled inconsistently; logout/expiry during a pending permission call could leave a response authorized by a stale local session. Callbacks reject ambiguous/error responses, and protected responses recheck session presence and grant expiry. | Isolated HTTP callback, logout-race and exact-deadline fixtures. |
| Console requests | Consent could retain an old URL request or redirect after its identity/view was replaced; delayed callback diagnostics and risk assessments could describe edited inputs. Request identity/revision tracking discards stale results and redirects. Pending sign-in controls and synchronous submission guards prevent duplicate factor attempts. | Browser fixtures for history, identity replacement, edits during pending work and duplicate submission. |
| Console confirmations | A pending member-removal confirmation could follow a later organization selection and target the wrong organization. Confirmations capture the original organization and visibly identify both it and the member. | Cross-tab organization-selection/removal fixture. |
| Console expiry and evidence | Local console state could remain after the server session deadline, enrollment-only sessions appeared fully active, and missing risk components appeared as zero. Deadlines clear local authority; enrollment and unavailable probability values display accurately. | Browser session-deadline, enrollment-state and risk-display fixtures. |
| Keyboard navigation | Mobile menu focus could escape its controls or remain on hidden navigation after closing the current page. Keyboard containment and focus restoration now follow menu/view changes. | Keyboard Tab/Shift+Tab, close/reopen and current-page activation fixtures. |
| RBA methodology | Equal-timestamp events could influence peer histories and cross chronological partition boundaries. `rba-evaluation-v2` scores whole time groups against strictly earlier history, keeps ties together and drops a final group cut by the row limit. | Same-time permutation, history, partition, row-cap and provenance fixtures. |
| Research provenance | Cached external reports did not bind the corrected protocol. New runs require its identifier and default to `experiments/output/rba-evaluation-v2/`. | Cache compatibility and end-to-end provenance fixtures. |
| LANL accounting | Selected scan totals could include the deliberately discarded incomplete final second. New metadata separates acquired rows from evaluated complete groups and checks partition totals. | Selected-final-second and source-group accounting fixtures. |
| Asset verification | Full project verification omitted original-asset checksums; malformed or truncated manifests could weaken standalone checks. All verifier modes now check asset integrity, with manifest structure, count, duplicate and path checks. | Manifest failure fixtures and checksum verification of all 31 assets. |
| QBFT identity preservation | A retry after interrupted initialization could overwrite keys before a final genesis marker existed. Any partial retained state now stops initialization, and creation uses exclusive writes. | Interrupted/truncated-state preservation, complete reuse and real key creation/decryption fixtures. |
| Registry recovery | A malformed/missing metadata file or retained deployment without matching chain code could trigger a new registry deployment. Metadata errors and chain mismatches stop recovery; absent metadata permits deployment only for an unused writer with zero confirmed and pending transactions. | Missing-versus-malformed/foreign/oversized metadata, pending/confirmed nonce fixtures and an actual EVM writer transaction. |
| Deployment configuration | The optional QBFT console omitted the default stack's `IAM_DEMO_MODE` forwarding, so an operator's private-mode setting was ignored. Both stacks now honor it. | Docker Compose rendering verified with both `true` and `false`; no services or retained volumes were changed. |
| Development tooling | Valid non-object JSON could crash the context hook; a development child killed by a signal could make the launcher report success. Hook input is normalized, and signaled child failure stops the sibling and returns failure. | Hook input boundaries and isolated execution of the real launcher with controlled child exits. |

## Evidence and reproducibility

The corrected RBA protocol has **no newly measured accuracy results** in this review. Existing RBA reports remain historical evidence from the earlier implementation, with the newly identified tie-ordering limitation documented in [Research](RESEARCH.md) and the [experiment guide](../experiments/README.md). Reusing their scores as measurements of version 2 would be invalid. A future evaluation must record its own source/sample hashes, protocol identifier, complete-group counts, configuration, fitted artifacts and validation/test results, including regressions.

LANL scan accounting is corrected for future prefixes. The frozen study remains unchanged; its discarded final source second contained no selected events. This review did not reacquire raw datasets, refit scientific models, overwrite measured reports or alter the preserved original assets.

Reproduce the integrated verification with the installed project dependencies:

```powershell
npm run check:complete
```

The command runs source/secret checks, preserved-asset integrity, backend, script, research, Python/Node SDK and contract tests, an ephemeral live-chain API suite, the frontend production build and browser fixtures. Its live-chain state is temporary; existing IAM databases and retained chains are not test targets.

The complete verifier passed, followed by focused SDK/registry checks and final complete script, contract/RPC and browser reruns after their respective fixes:

| Check | Result |
| --- | --- |
| Backend | 159 cases; 151 passed, 8 opt-in live-chain skips |
| Scripts and adapters | 119 cases; 118 passed, 1 Windows symlink-privilege skip |
| Research invariants | 63 passed |
| Python SDK and website | 18 passed |
| Node SDK and website | 50 passed |
| Contract/RPC/state recovery | 25 passed |
| Isolated live-chain API | 31 passed, including the opt-in chain flows |
| Browser fixtures | 30 passed using installed Edge |
| Frontend production build | TypeScript and Vite passed |
| Preserved original assets | All 31 checksum/size checks passed |
| Additional source parsing | All 31 JavaScript modules and 3 PowerShell scripts passed |

Source syntax/secret inspection covered 246 project text files; Git whitespace checks passed. The installed Starlette/httpx test integration emits a deprecation notice, and Ganache uses its JavaScript transport fallback on this Node build; these runs are functional checks, not transport benchmarks. [STATUS.md](STATUS.md) summarizes the current project state.

## Review boundaries

Manual review covered all 16 `backend/app` implementation modules, identity/session transitions, OAuth permissions, grants/audit boundaries and advisory models. Further file-by-file passes covered every console source file and stylesheet, OIDC clients/examples/session stores, Solidity/QBFT operations, Docker/CI configuration, every Python implementation/test under `experiments/` and `scripts/`, and all script launchers. Backend and frontend tests were read where relevant to those paths, and automated source inspection and suites cover the broader first-party codebase. This does not claim every test line was manually audited. Dependencies, binary assets, private environment files, local databases, raw datasets and fitted models were excluded from the source audit.

The local verification environment uses Windows, Python 3.11 and portable Node 24. Docker/CI target Python 3.13 on Linux. This review does not add fresh Docker image, hardware-authenticator, independent OIDC-conformance, multi-host session or real Besu-outage measurements. Prior dated evidence remains identified separately in the relevant guides.

Research still needs independently collected organizational labels, representative sampling, trusted telemetry, independent language annotation and prospective validation. Human access votes are authorization decisions, not attack labels. The SQLite chain provides local tamper evidence; four validators on one host do not establish independently administered trust. Existing Ganache dependency findings remain documented in [Security](SECURITY.md).
