# Adaptive IAM: Evaluating calibrated authentication policy and human-reviewed authorization with local EVM grants

**Research manuscript draft — 10 October 2026. Authors and affiliations: to be confirmed.** This draft reports the checked-in simulation artifacts and implementation, not production deployment results. Original supplied papers and reports remain unchanged. Bibliography: [references.bib](references.bib); supporting reading notes: [verified readings](../../research_notes/Adaptive%20IAM%20evidence%20study/readings.md).

## Abstract

Adaptive authentication combines probabilistic risk estimates with decisions that affect both attack detection and legitimate-user burden. We implement an Adaptive IAM research prototype that separates contextual authentication from human-reviewed resource authorization and exposes those decisions through an OAuth/OIDC website integration. An optional Solidity registry anchors audit hashes and time-limited grants on a private local Ethereum development chain; permission checks require live local and contract authority. On 10,000 seeded synthetic login events, a validation-selected sigmoid-calibrated logistic-regression/random-forest blend reduces held-out Brier loss from 0.1747 to 0.1165 and legitimate-user challenge/block friction from 56.48% to 51.45%. Suspicious-event challenge/block recall decreases from 86.86% to 84.00%, while ROC-AUC remains 0.7743. Paired bootstrap uncertainty does not establish a nonzero F1 improvement. An independent 12,000-event model-family study retains the calibrated blend on validation, yet its held-out detection falls to 78.47%, below the validation target. Exploratory text-threshold reanalysis improves recall from 0.625% to 52.5% on previously reported template groups; it does not establish independent language generalization. The study provides reproducible tradeoff and failure analysis, with independent telemetry, protocol conformance, verified MFA and distributed-chain resilience left unestablished. ([Main results](../../experiments/results.json), [Robustness](../../experiments/robustness.json), [Candidate study](../../experiments/candidate-study.json))

**Keywords:** risk-based authentication; identity and access management; calibration; human authorization; OpenID Connect; Solidity; reproducibility.

## 1. Introduction

The supplied project reports motivate a combined pipeline of contextual risk, natural-language justification, human voting and auditable timed permission. This implementation makes the proposal executable while replacing unsupported accuracy projections and broad blockchain guarantees with measured artifacts and explicit trust boundaries. The research questions are whether calibration changes classification and authentication policy differently, whether a validation detection target transfers to fresh test events, and how identity, reviewer authority and grant enforcement can be composed without allowing an advisory model to grant access. ([Supplied report extract](../research/report-final.txt), [Implementation research map](../RESEARCH.md))

NIST's zero-trust architecture separates authentication and authorization and emphasizes resource-specific decisions. This motivates a login decision followed by an independent, expiring resource grant. It does not establish NIST compliance for the prototype. ([NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final))

Our contribution is a reproducible implementation and exploratory evaluation: an explicit authority boundary, distinct classification and authentication thresholds, retained rejected candidates, conditional uncertainty and live local EVM permission checks. We make no first-system or universal superiority claim.

## 2. Related work and standards

Wiefling and colleagues analyze RBA configurations using large-scale service data and provide a synthesized corpus. Their work motivates service-specific historical evaluation and detection/friction reporting; this project does not reproduce their original service measurements. The author manuscript dates to 2022, with the final TOPS volume listed in 2023. ([Primary study](https://arxiv.org/html/2206.15139v2), [Bibliographic metadata](https://arxiv.org/abs/2206.15139))

LLMAC demonstrates LLM-based policy reasoning and reports 98.5% accuracy on its own synthetic scenarios. The different task, model and label construction prevent direct numerical comparison with our login or justification experiments. We retain language models as constrained advisers. ([Zisad and Hasan, 2026](https://arxiv.org/abs/2602.09392))

OAuth security guidance and PKCE motivate exact callbacks, transaction-bound code redemption and confidential-client protection. OIDC supplies ID-token identity semantics, including issuer, audience, expiry and nonce validation. Our provider implements a limited code-flow subset and is not certified for complete conformance. ([RFC 7636](https://www.rfc-editor.org/info/rfc7636/), [RFC 9700](https://www.rfc-editor.org/info/rfc9700/), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html))

## 3. System and threat boundary

The React console submits bounded inputs to a FastAPI service backed by SQLite. The service verifies password credentials, stores hashed opaque sessions, enforces risk challenges and locks repeated failures. Public bootstrap credentials and displayed challenge codes permit local demonstrations; they are not independently verified MFA. Much context is tester-selected rather than trusted telemetry. Resource sensitivity and recent credential failures are controlled by the service. ([API](../API.md), [Security boundary](../SECURITY.md))

Each resource request uses the session identity and server-selected eligible reviewers. The owner has weight 1.5; each other reviewer has weight 1.0. For eligible set R and approving set A, approval requires an owner approval, at least two submitted votes and:

$$\sum_{r\in A}w_r > \frac{1}{2}\sum_{r\in R}w_r.$$

The denominator includes uncast reviewer weight. Owner denial vetoes; unresolved requests expire after 48 hours. The requester cannot self-vote. LLM output must satisfy reviewer eligibility and falls back to deterministic selection when invalid or unavailable. No model output can replace these checks. Approval expresses business authorization, not an attack label. ([Server policy](../../backend/app/store.py), [Architecture](../ARCHITECTURE.md))

The relying-party website registers exact callbacks, scopes and resource IDs, then performs Authorization Code with S256 PKCE. The website holds state, nonce, verifier, access token and confidential secret on its server, with random HttpOnly cookie keys identifying its sessions. It validates signed identity and calls a client/subject/resource-bound permission endpoint before each protected response. Login consent supplies no resource grant and website tokens carry no console authority. ([SDKs and examples](../INTEGRATION.md))

The SQLite audit log chains canonical SHA-256 event hashes. Optional `AccessGrantRegistry.sol` receives hash checkpoints and hashed subject/resource grants from a trusted writer on chain 31337. The retryable outbox mirrors grants only after anchored creation and verified owner/quorum. Live checks require local grant validity and the corresponding contract grant, denying on RPC failure, mismatch, expiry or revocation. Revocation removes local authority immediately even while chain synchronization is pending. This is real local contract execution; a single local administrator still controls its chain and host. ([Solidity contract](../../blockchain/contracts/AccessGrantRegistry.sol), [Web3 adapter](../../backend/app/blockchain.py))

The Docker stack keeps Ethereum RPC on an internal bridge and uses non-root users, read-only root filesystems, dropped capabilities and process/memory limits. Web services also join an edge bridge, which permits their outbound traffic. Console/API and optional website ports publish only on host loopback. Persistent IAM and chain state must remain consistent. These settings reduce exposed runtime surfaces; they do not establish independence from the host administrator or production isolation. ([Compose](../../compose.yaml), [Operations](../../deployment/README.md))

## 4. Experimental method

### 4.1 Synthetic login generation and partitions

The main dataset uses seed 20261009 and 10,000 events with ten normalized features: device unfamiliarity, location unfamiliarity, VPN use, failures, hour deviation, login velocity, account youth, travel distance, resource sensitivity and prior risk. Bernoulli, Poisson, beta and uniform generators construct the features. The latent logit contains linear terms and device/location and VPN/hour interactions. Labels are sampled as:

$$p(y=1\mid x)=0.015+0.97\,\sigma(z(x)),\qquad y\sim\mathrm{Bernoulli}(p).$$

The stochastic labels are not copied from runtime policy thresholds. Their construction still shares a designed relationship with the input features and does not reproduce real attack behavior. A seeded permutation produces a 6,000 training, 1,000 calibration, 1,000 selection and 2,000 test split. Suspicious prevalence in the test partition is 17.5%. Learned preprocessing fits only training data. ([Generator and training code](../../backend/app/risk.py), [Results protocol](../../experiments/results.json))

### 4.2 Models, calibration and threshold selection

The paper-inspired baseline is:

$$s(x)=0.4\,P_{LR}(y=1\mid x)+0.6\,P_{RF}(y=1\mid x).$$

Logistic regression uses standardized features, balanced class weights, C=0.7 and a 400-iteration cap. The forest has 100 trees, depth 10, minimum leaf size 12 and balanced weights. Pairwise interaction features are retained only if selection-partition ROC-AUC improves; they are rejected in the current artifact. A logistic sigmoid fitted to the raw probability logit on the calibration partition is retained only after selection-partition Brier loss improves. ([Risk implementation](../../backend/app/risk.py))

Classification uses the highest maximum-F1 selection threshold from a fixed 0.05–0.75 grid. Authentication policy uses a separately selected low challenge threshold meeting at least 80% suspicious detection on validation, with high block threshold 0.7. The implementation selects from the lower empirical suspicious-score quantile with a conservative floating-point boundary. Test data does not select these settings. The baseline classification threshold is 0.5 and its policy thresholds are 0.3/0.7. ([Recorded method](../../experiments/results.json))

For probability p, policy detection and legitimate friction are:

$$D=P(p\geq t_L\mid y=1),\qquad F=P(p\geq t_L\mid y=0).$$

Direct suspicious allowance is 1-D; benign high-risk blocking is P(p≥t_H | y=0). These differ from binary classification recall at threshold t_C. Brier loss is the mean squared probability error. It combines reliability and discrimination, so its reduction alone does not prove better calibration. ([Metric implementation](../../backend/app/risk.py), [Calibration reference](https://scikit-learn.org/stable/modules/calibration.html))

### 4.3 Conditional robustness and fresh candidate study

The bootstrap resamples the same test events in paired, class-stratified fashion for 1,000 repetitions, seed 20261109. It preserves each model's prediction pairing and reports percentile 95% intervals. Five independently generated 2,000-event batches test the frozen model without refitting. The independent candidate study uses seed 20261509, 12,000 events and a 7,200/1,200/1,200/2,400 split. It selects among calibrated blend, unweighted interaction logistic regression and histogram gradient boosting through validation Brier, ranking and friction/detection constraints, then records every test outcome. It does not replace the deployed model. ([Robustness protocol](../../experiments/robustness.json), [Candidate protocol](../../experiments/candidate-study.json))

### 4.4 Justification benchmark and environment

The text study generates 2,000 requests with disjoint template groups across 1,200 training, 400 validation and 400 test texts. The original TF-IDF/Multinomial Naive Bayes threshold-0.5 result is retained. An exploratory reanalysis selects the threshold maximizing validation macro F1 and compares a fixed-C=0.8 balanced logistic model with word/character TF-IDF. The new model is retained only if it improves validation macro F1 without increasing legitimate flagging. Only two template groups per label are held out, and their outcomes were already reported before this reanalysis. Runtime class support below 0.65 produces abstention; binary scores exclude abstentions, lexical flags and BERT. Every request still needs human authorization. Recorded analysis environment is Python 3.11.9, NumPy 2.4.6 and scikit-learn 1.9.1 on Windows. Hardware details are insufficient for hardware-normalized latency claims. ([Text method](../../backend/app/nlp.py), [Results](../../experiments/results.json), [Environment](../../experiments/robustness.json))

## 5. Results

### 5.1 Classification and probability error

| Held-out metric | Raw paper blend | Calibrated candidate |
| --- | ---: | ---: |
| Accuracy | 74.90% | 81.50% |
| Suspicious precision | 37.33% | 47.27% |
| Suspicious recall | 64.00% | 49.43% |
| F1 | 0.471579 | 0.483240 |
| ROC-AUC | 0.774324 | 0.774324 |
| Brier loss | 0.174673 | 0.116540 |
| Classification threshold | 0.50 | 0.26 |

Source: [main held-out artifact](../../experiments/results.json). The majority baseline achieves 82.50% accuracy and zero suspicious recall. Thus the candidate's increased accuracy does not establish uniformly improved attack detection. The unchanged ROC-AUC is consistent with the retained model and monotonic calibration.

### 5.2 Authentication policy and rejected ablation

| Held-out policy metric | Raw 0.3/0.7 | Candidate 0.10533/0.7 | Rejected calibrated 0.3/0.7 |
| --- | ---: | ---: | ---: |
| Suspicious challenge/block recall | 86.86% | 84.00% | 41.14% |
| Direct suspicious allowance | 13.14% | 16.00% | 58.86% |
| Legitimate challenge/block friction | 56.48% | 51.45% | 7.76% |
| Benign high-risk block fraction | 4.18% | 0.00% | 0.00% |

Source: [policy and ablation artifact](../../experiments/results.json). The apparent friction benefit of retaining old cutoffs after calibration corresponds to a large detection loss; it is not deployed. The selected candidate also trades lower detection for lower legitimate burden. Zero benign blocks occurs only on this test sample.

![Classification and authentication tradeoffs](../../experiments/figures/risk-comparison.png)

Figure 1. Separate classification and authentication outcomes on the 2,000-event synthetic test partition. [Vector export](../../experiments/figures/risk-comparison.svg).

### 5.3 Uncertainty and independent model-family outcome

| Candidate minus baseline | Estimate | 95% paired percentile interval |
| --- | ---: | ---: |
| F1 | +0.011661 | [-0.017844, +0.041213] |
| Brier loss | -0.058133 | [-0.062601, -0.053871] |
| Policy detection | -2.8571 percentage points | [-4.5714, -1.1429] percentage points |
| Legitimate friction | -5.0303 percentage points | [-6.0000, -3.9394] percentage points |

Source: [conditional bootstrap artifact](../../experiments/robustness.json). F1's interval includes zero. The other intervals preserve the error/friction benefit and detection regression for these events and model. Subgroup diagnostics and seed-batch results remain in the artifact and should be examined before any threshold transfer.

![Conditional paired uncertainty](../../experiments/figures/paired-uncertainty.png)

Figure 2. Candidate-minus-baseline conditional 95% percentile intervals. Positive values favor F1 and policy detection; negative values favor Brier loss and legitimate friction. [Vector export](../../experiments/figures/paired-uncertainty.svg).

In the fresh model-family study, validation retains the calibrated original blend. Its test accuracy is 79.83%, F1 0.447489, ROC-AUC 0.746683, Brier loss 0.120219, policy detection 78.47% and legitimate friction 46.32%. Detection misses the 80% validation target. Other candidates remain reported even when individual held-out metrics look favorable; test outcomes do not reverse selection. ([Independent candidate study](../../experiments/candidate-study.json))

### 5.4 Text-threshold gains remain exploratory

| Previously reported template test | Original NB | Validation-tuned NB | Rejected word/character logistic |
| --- | ---: | ---: | ---: |
| Accuracy | 60.25% | 81.00% | 100.00% |
| Suspicious recall | 0.625% | 52.50% | 100.00% |
| F1 | 0.012422 | 0.688525 | 1.000000 |
| Brier loss | 0.273871 | 0.273871 | 0.071570 |
| Threshold | 0.50 | 0.16 | 0.285 |

Source: [NLP artifact](../../experiments/results.json). The tuned model predicts TN=240, FP=0, FN=76 and TP=84; the old result was TN=240, FP=0, FN=159 and TP=1. Changing a decision threshold improves classification while leaving probability error unchanged. Reanalysis used validation for selection, but the benchmark was already observed, so these gains remain exploratory rather than a newly untouched test result.

The logistic candidate's perfect score on two held-out template groups per label does not override its failed validation gate. Validation macro F1 is 0.696970 versus 0.784727 for tuned NB, and legitimate flag rate is 50% versus 0.8333%. It is rejected. Runtime abstention and lexical flags are not included in the binary table and require separate measurement. No BERT or LLM improvement is measured. Independently labeled, task-specific language remains necessary before assigning any additional authority. ([Selection scores and limitations](../../experiments/results.json))

### 5.5 Runtime diagnostics reveal abstention and false flags

After freezing model and threshold, 32 manually authored cases probe different phrasing, negation, quoted threats, exfiltration, prompt injection and Hindi/Hinglish. Author expectations classify 16 as suspicious and 16 as benign. The complete runtime, including deterministic lexical flags, marks 12 of 16 author-suspicious cases as suspicious and falsely flags 2 of 16 author-benign cases. Seven of 32 receive `uncertain`, giving 78.125% definitive coverage. These counts are diagnostic case outcomes, not independently adjudicated attack labels or external-test accuracy. No model/threshold change was made from their outcomes. ([Frozen case study](../../experiments/case-study.json), [Case definitions](../../experiments/cases.py))

Runtime confidence represents uncalibrated selected-class support, not a calibrated authorization probability. The negation guard inspects a bounded lexical prefix; it is not general semantic understanding. All cases retain mandatory human review, including those labeled legitimate. This preserves a safe authority boundary while exposing multilingual, quotation and negation failure modes for subsequent independent annotation.

![Exploratory binary text scores and manually authored runtime diagnostics](../../experiments/figures/text-diagnostics.png)

Figure 3. Left: binary classifier scores from exploratory reanalysis of previously reported synthetic template groups, excluding runtime abstention and lexical flags. Right: full runtime labels for 32 manually authored cases, grouped by author expectations rather than independently verified attack truth. These panels use different evaluation units and must not be combined as one accuracy estimate. [Vector export](../../experiments/figures/text-diagnostics.svg).

### 5.6 Live EVM security tests exercise actual failure states

On 10 October 2026, the isolated Docker test environment passed 11 Python blockchain tests (six boundary tests and five real-RPC flows) and two grouped Solidity/EVM tests. The live cases cover expiry while SQLite still reports active, chain rollback, a fully recomputed database hash chain that passes local verification but fails its EVM checkpoint, fabricated grants without owner quorum, OIDC permission denial during outage and post-revocation denial. Contract assertions also exercise writer restrictions, wrong subject/resource, empty hashes, excessive duration, duplicate grants and unknown revocation. Tests use disposable state; they do not establish production throughput or distributed consensus. ([Python test source](../../backend/tests/test_blockchain.py), [EVM test source](../../blockchain/tests/contract.test.mjs), [Isolated runner](../../deployment/compose.web3-tests.yaml))

A separate live Docker provider smoke flow verified confidential-client PKCE, RS256 identity with nonce/audience/issuer checks, human approval, a confirmed EVM grant, subsequent revocation and client disable. The full project verifier also passed 60 backend tests with five optional live-RPC skips, four history-feature tests, 12 Python SDK tests, 13 Node SDK tests, two contract tests and the frontend build. This verifies the reported local implementation path without claiming protocol certification. ([Verification runner](../../scripts/verify.py), [Provider tests](../../backend/tests/test_oauth.py), [SDK integration](../INTEGRATION.md))

## 6. Validity, limitations and reproducibility

Synthetic generation can favor models that resemble its construction. Independent seeds still share the generator, and this is neither an external benchmark nor a distribution-shift study. Bootstrap intervals are conditional on one trained model and have no multiplicity correction. Validation is reused for several selection decisions, which introduces selection variance even while test data is excluded. The fresh study provides one additional split, not nested cross-validation or retraining uncertainty. No fairness conclusion follows from device/location diagnostic groups. ([Recorded limitations](../../experiments/robustness.json), [Candidate limitations](../../experiments/candidate-study.json))

The public RBA creator corpus is synthesized from service behavior with artificial feature values, not raw telemetry, and its creators caution against productive use. The supplied CSV adapter computes only historical features, records SHA-256 and splits chronologically 60/10/10/20, but no completed external result is present. VPN, travel, sensitivity and prior risk are unavailable, and known users can appear across periods. A future study should add user-disjoint cohorts and verified attack labels rather than treating human votes as ground truth. ([Creator provenance](https://github.com/das-group/rba-dataset), [Adapter](../../scripts/evaluate_rba.py))

Local SDK/provider tests and contract tests support functional failure-state verification, not OIDC certification, real attack resistance or distributed integrity. Single-host Ganache administration, unlocked development writers, guessable identifier hashes, demo MFA and client-selected context retain explicit trust limitations. No independently verified throughput, gas-economics or user-study result is claimed. ([Security limitations](../SECURITY.md), [Deployment](../../deployment/README.md))

Reproduce the simulation from the repository root after installing the pinned analysis requirements:

```sh
python experiments/evaluate.py
python experiments/robustness.py
python experiments/candidate_study.py
python experiments/plot_results.py
```

Start the complete local Web3 system with `docker compose up --build -d`. Follow [deployment operations](../../deployment/README.md) for retained state and grant confirmation, [integration setup](../INTEGRATION.md) for a connected website and [experiment documentation](../../experiments/README.md) for runtime-dependent analysis. Keep generated metrics, seeds, dataset digests, software versions and test logs with a submission snapshot; latency varies by environment.

The network-free analysis profile can reproduce each Python command in Linux, for example:

```sh
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm --build analysis python experiments/evaluate.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/robustness.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/candidate_study.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/cases.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/plot_results.py
```

## 7. Conclusion

Adaptive IAM makes a combined authentication/authorization idea measurable and reusable while retaining explicit model and administrator authority boundaries. The observed probability-error and friction gains coexist with lower suspicious detection; fresh test events further show that a validation target does not guarantee transfer. The next defensible contribution is an independently sourced, prespecified evaluation of detection/friction operating points and failure-state enforcement, rather than a claim of uniformly improved or production-ready IAM.

## References

The bibliography contains the verified sources used in the narrative. No unsupported numerical claim from the supplied report has been imported.

[1] S. Rose, O. Borchert, S. Mitchell and S. Connelly, *Zero Trust Architecture*, NIST SP 800-207, 2020. [DOI](https://doi.org/10.6028/NIST.SP.800-207).

[2] S. Wiefling, P. R. Jørgensen, S. Thunem and L. Lo Iacono, *Pump Up Password Security! Evaluating and Enhancing Risk-Based Authentication on a Real-World Large-Scale Online Service*, TOPS 26(1), Article 6; author version 2022, final volume 2023. [DOI](https://doi.org/10.1145/3546069), [author text](https://arxiv.org/html/2206.15139v2).

[3] N. Sakimura, J. Bradley and N. Agarwal, *Proof Key for Code Exchange by OAuth Public Clients*, RFC 7636, 2015. [Primary standard](https://www.rfc-editor.org/info/rfc7636/).

[4] T. Lodderstedt, J. Bradley, A. Labunets and D. Fett, *Best Current Practice for OAuth 2.0 Security*, RFC 9700, 2025. [Primary standard](https://www.rfc-editor.org/info/rfc9700/).

[5] OpenID Foundation, *OpenID Connect Core 1.0 incorporating errata set 2*. [Primary specification](https://openid.net/specs/openid-connect-core-1_0.html).

[6] S. N. Zisad and R. Hasan, *LLMAC: A Global and Explainable Access Control Framework with Large Language Model*, CCNC 2026, arXiv 2602.09392. [Primary record](https://arxiv.org/abs/2602.09392), [conference DOI](https://doi.org/10.1109/CCNC65079.2026.11366514).

[7] Scikit-learn developers, *Probability calibration*, version 1.9.1 documentation, accessed 10 October 2026. [Primary documentation](https://scikit-learn.org/stable/modules/calibration.html).

[8] DAS Group, *Login Data Set for Risk-Based Authentication*, accessed 10 October 2026. [Creator dataset](https://github.com/das-group/rba-dataset).

[9] Ethereum.org, *Introduction to smart contracts*, accessed 10 October 2026. [Primary documentation](https://ethereum.org/developers/docs/smart-contracts/).

[10] Docker, *Docker Engine security*, accessed 10 October 2026. [Primary documentation](https://docs.docker.com/engine/security/).
