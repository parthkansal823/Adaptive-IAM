# Claim and evidence map

## What changed from the supplied reports?

### Takeaway

The reports provide a useful architecture proposal, but performance projections and broad security language must be replaced with the implementation's actual evidence. Original assets remain preserved.

### Cited Findings

- The supplied reports describe risk scoring, LLM-assisted review, weighted voting, time-limited grants and blockchain-inspired logs. They also list Keycloak, simulated SHA-256 logging and several potential future integrations; these descriptions are not evidence of a working implementation. — [Detailed report extract](../../docs/research/report-final.txt), [Original-asset index](../../docs/RESEARCH_INDEX.md)
- The implementation uses Python/FastAPI, SQLite, React, server-enforced identity/session policy, human quorum, optional local model assistance and a constrained OAuth/OIDC provider. Client tokens cannot vote in the console. — [Architecture](../../docs/ARCHITECTURE.md), [API](../../docs/API.md), [Website integration](../../docs/INTEGRATION.md)
- Human review requires owner approval, at least two eligible votes and a strict majority of all selected reviewer weight; owner denial vetoes and unresolved requests expire after 48 hours. — [Server policy](../../backend/app/store.py), [API behavior](../../docs/API.md)

### Inferences

- Present these as implementation decisions that strengthen the original proposal's authority boundary. Do not describe human approvals as attack ground-truth labels or LLM suggestions as authority.
- Document local hash-chain behavior and optional EVM behavior separately. A completed real local contract integration is stronger implementation evidence than a simulated ledger, but neither establishes independent distributed trust on a single host.

### Gaps

- The original report's related-work references beyond the verified reading list were not independently checked. Their numerical results must not be copied into the new paper.
- Authors and affiliation for the new manuscript must be confirmed by the user; preserve the repository's existing copyright without inventing a new author list.

## What results can the new paper report?

### Takeaway

Report the calibration/error and friction gains alongside the detection regressions. This is a reproducible simulation study, not evidence of a universally better authentication system.

### Cited Findings

- Primary risk experiment: seed 20261009, 10,000 synthetic events; training 6,000, calibration 1,000, selection 1,000, test 2,000. Suspicious test prevalence is 17.5%. Classification threshold 0.26 and challenge threshold approximately 0.10533 were selected before test evaluation. — [Protocol and results](../../experiments/results.json)
- Raw paper blend versus calibrated candidate: accuracy 74.9% to 81.5%; F1 0.471579 to 0.483240; ROC-AUC unchanged at 0.774324; Brier loss 0.174673 to 0.116540. An always-legitimate classifier achieves 82.5% accuracy with zero suspicious recall. — [Measured comparison](../../experiments/results.json)
- Authentication policy: suspicious challenge/block recall decreases 86.8571% to 84%; direct suspicious allowance increases 13.1429% to 16%; legitimate challenge/block friction decreases 56.4848% to 51.4545%; benign high-risk block fraction decreases 4.1818% to zero on this test partition. Calibration with unchanged 0.3/0.7 cutoffs is explicitly rejected because detection falls to 41.1429%. — [Policy and rejected ablation](../../experiments/results.json)
- Paired class-stratified bootstrap, 1,000 replicates: candidate-minus-baseline F1 difference +0.011661, 95% percentile interval [-0.017844, +0.041213]; Brier difference -0.058133 [-0.062601, -0.053871]; policy detection difference -0.028571 [-0.045714, -0.011429]; legitimate friction difference -0.050303 [-0.060000, -0.039394]. Five further 2,000-event seeded batches use a frozen model, not retraining. — [Robustness artifact](../../experiments/robustness.json)
- Independent model-family study: seed 20261509, 12,000 events split 7,200/1,200/1,200/2,400; validation selects the calibrated original blend over interaction logistic regression and histogram gradient boosting. Its new held-out policy detection is 78.4689%, below the 80% validation target; legitimate friction is 46.3169%. Runtime replacement is false. — [Candidate study](../../experiments/candidate-study.json)
- Text experiment: 2,000 generated requests split by template groups into 1,200/400/400. The retained original threshold-0.5 baseline has 60.25% accuracy and 0.625% suspicious recall (one of 160). Exploratory reanalysis selects a 0.16 threshold on validation, producing 81% accuracy, 52.5% recall and F1 0.688525 on the previously reported test groups. A word/character logistic candidate is rejected on worse validation macro F1 and 50% benign flagging despite perfect scores on the tiny held-out template sample. This is not a new untouched language test; runtime abstention, lexical flags and BERT are excluded. — [NLP results and validation gate](../../experiments/results.json)
- Frozen runtime diagnostic: 32 manually authored cases include negation, quoted threats, prompt injection and Hindi/Hinglish. Runtime flags 12/16 author-suspicious cases and 2/16 author-benign cases, with seven abstentions and 78.125% definitive coverage. These are author expectations, not independently verified attack labels; their outcomes do not retune the model. — [Case study](../../experiments/case-study.json)

### Inferences

- Accuracy alone is misleading under imbalance. The slight F1 gain has inconclusive conditional uncertainty; do not claim a statistically established F1 improvement.
- The candidate meets its selection target on validation but can regress on fresh test events. This is useful evidence about threshold transfer, not a failure to hide.
- Bootstrap intervals are conditional on one model and the simulator, with correlated comparisons and no multiplicity adjustment. They do not establish population-level significance or retraining stability.

### Gaps

- No independently sourced CSV result is present. `scripts/evaluate_rba.py` is an adapter with past-event-only features and chronological splits, not an already completed external-data benchmark.
- The generator is unchanged across seed replications. These runs do not measure domain shift, new-user generalization, incident-response labels or real attacks.
- No measured optional BERT/LLM benefit, demographic fairness, user study or operational throughput is available.

## What would strengthen a submission next?

### Takeaway

Freeze a prespecified research protocol and collect evidence that adds independent validity. Infrastructure and protocol tests support reproducibility but should not be substituted for model validity.

### Cited Findings

- The adapter records CSV SHA-256, rejects future/out-of-order history and excludes the current login outcome from current features. Missing VPN, travel, resource sensitivity and prior-risk signals use disclosed constants; chronological splits retain known users across periods. — [Adapter](../../scripts/evaluate_rba.py), [Leakage tests](../../scripts/tests/test_rba.py)
- Node/Python relying-party tests exercise real signed fixture tokens and reject invalid identity/resource bindings and unavailable permission checks. They are local security tests, not certification or production-scale interoperability evidence. — [Node tests](../../integrations/node/tests/client.test.mjs), [Python tests](../../integrations/python/tests/test_client.py)

### Inferences

- Candidate follow-up protocol: independently sourced login data with documented rights and provenance; chronological and user-disjoint evaluations; verified attack labels; fixed baselines including Freeman-style RBA; calibration reliability bins and error; matched detection/friction operating points; repeated retraining seeds; subgroup uncertainty; availability and revocation failure tests.
- For text, obtain an independent, consented, task-specific human-labeled corpus and evaluate recall/precision by request class before giving models any additional responsibility.
- For Web3, measure transactions, gas, sync latency, checkpoint consistency, expiry/revocation and outage behavior separately. Test independently administered nodes before making distributed-integrity claims.

### Gaps

- Collection rights, independent annotations, organization policies and an independently administered deployment are not supplied. These require additional research inputs rather than invented results.
