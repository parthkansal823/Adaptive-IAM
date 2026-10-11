# Research implementation and evidence

Source: [final paper](../research/papers/final/FINAL_IEEE_Paper_Humanized_WithFormulas.docx), with [text extract](research/paper-final.txt). The user directed implementation to improve the idea, so weak assumptions may be changed with explicit rationale.

## Paper-to-code scope

| Paper concept | Prototype approach | Evidence boundary |
| --- | --- | --- |
| `0.4 * logistic regression + 0.6 * random forest` | Reproducible paper baseline and improved risk candidate | Synthetic held-out evaluation |
| Context and anomaly scoring | Contextual features, explicit policy guards, model explanations | Synthetic signal realism is limited |
| TF-IDF + Naive Bayes, BERT fallback | Baseline text classifier, improved candidate, optional configured BERT | BERT improvement must be separately measured |
| LLM-selected reviewers | Deterministic eligible selection; optional constrained Ollama recommendation | LLM does not establish authority |
| Owner weight 1.5; other weight 1.0 | Weighted human quorum with fixed eligible denominator | Votes express policy approval, not attack truth |
| 48-hour review deadline | Deny expired unresolved requests | Server time is authoritative |
| Smart-contract timed grants | Backend expiry plus optional deployed local Solidity registry | Real local EVM behavior; production resilience unestablished |
| SHA-256 permissioned blockchain | SQLite hash chain with optional Ethereum checkpoints | Single trusted local chain; no independent distributed consensus |

## Evaluation discipline

Paper figures of 85–92% risk accuracy and 83–89% NLP accuracy are projections drawn from related work, not observations from this implementation. Quote actual numbers only from a generated experiment report, with dataset size, seed, split, hardware and conditions.

Compare candidates on the same held-out examples. Tune models and calibration on training/validation data only. Keep the test split untouched by model selection. Report suspicious-class recall, precision, ROC-AUC, PR-AUC, Brier score/calibration, and latency alongside accuracy. For text, group generated templates before splitting so near-identical variants do not inflate the test result.

The risk report separates binary classification metrics from authentication policy. The paper baseline uses 0.3/0.7 boundaries; the candidate chooses a low challenge boundary on validation data to meet an 80% suspicious-detection target, while retaining high cutoff 0.7. Read `suspicious_challenge_or_block_recall`, `suspicious_direct_allow_rate` and `legitimate_friction_rate`: reduced friction can mean more suspicious logins proceed directly. The rejected ablation of calibrated probabilities with unchanged paper cutoffs makes that failure explicit. Calibration gains alone do not establish a stronger security policy. Always-legitimate and static-password baselines expose misleading accuracy under imbalance.

The NLP report preserves the original TF-IDF/Naive Bayes threshold-0.5 baseline (60.25% accuracy, 0.625% suspicious recall) and a validation-tuned threshold-0.16 result (81% accuracy, 52.5% recall, F1 0.688525). This is exploratory reanalysis of already reported template groups, not a new untouched language test. The word/character TF-IDF logistic candidate is rejected for worse validation macro F1 and a 50% legitimate flag rate, despite a perfect result on the tiny held-out template sample. Neither test outcome reverses the validation selection. Runtime lexical flags, support-based abstention and optional BERT are outside these binary classifier scores. No BERT benefit or general language performance is claimed.

`experiments/case-study.json` measures the separately frozen runtime on 32 manually authored cases, including negation, quoted threats, prompt injection and Hindi/Hinglish. It flags 12/16 author-suspicious cases, falsely flags 2/16 author-benign cases and abstains on 7/32. These author expectations are diagnostic labels rather than verified attack truth. No model/threshold was changed from these cases, and every case still requires human owner/quorum approval.

Synthetic labels are produced by a controllable simulation, so high scores demonstrate agreement with that simulation. They do not demonstrate resistance to real attackers or generalization to a company's users. Latency excludes unknown external network delays unless specifically measured.

Access-review votes must never be automatically converted into authentication attack labels. Approval of a legitimate business need does not show whether credentials were stolen; such a feedback loop could poison a risk model. Retraining requires separately verified outcomes and provenance.

## Measured uncertainty and candidate rejection

`experiments/robustness.json` contains 1,000 paired class-stratified bootstrap replicates and five fresh 2,000-event batches with a frozen model. The F1 difference's 95% interval crosses zero. Brier loss and legitimate friction decrease, while suspicious challenge/block recall also decreases. These are conditional simulator comparisons, not retraining stability or real-world significance.

`experiments/candidate-study.json` compares three model families on an independent 12,000-event seeded sample. Validation retains the calibrated original blend. The selected model's new test policy detection is 78.47%, below its 80% validation target. The study does not replace the runtime model or choose a candidate from test results. Rejected candidates and poorer outcomes remain visible.

The [original evidence report](../reports/Adaptive%20IAM%20evidence%20study.md), [validation-control report](../reports/Adaptive%20IAM%20validation%20controls.md) and [manuscript draft](paper/MANUSCRIPT.md) explain the protocols, actual results and research limitations. The bibliography contains verified primary readings rather than all claims copied from the original report.

## Completed validation upgrades

`experiments/risk-protocol.json` fully retrains five prespecified seeds and gives raw/calibrated probability representations equal validation operating-point tuning. Classification, challenge and mapped-block decisions are identical for both controls in every run. Mean Brier loss improves 0.180707→0.113446 and fixed ten-bin ECE 0.248165→0.021704; average precision remains 0.495279 and F1 remains 0.462163 for both tuned controls. Mean matched-policy detection/friction are 86.99%/58.93% for both. Thus calibration does not explain an improved ranking or matched-policy outcome. The separate 80%-validation target achieves only 77.00% mean test detection, range 70.00–81.49%. Per-run values, reliability counts, sample SD and ranges remain visible; no model is selected from these tests or replaces the runtime.

`experiments/external-study.json` completes provenance, eligibility and two fresh-fit studies of 200,000 public creator-synthesized events. Only three takeover-positive rows exist: takeover studies fail class eligibility and report no invented metrics. Attack-IP proxy chronological F1 improves 0.087257→0.140454, while user-disjoint F1 regresses 0.155654→0.154626. This proxy is not takeover truth. Unchanged calibrated 0.3/0.7 policy allows every test event in both proxy studies; that failure remains an explicit ablation, not a deployment recommendation. Prefix sampling, incomplete archive verification, user overlap/time overlap and missing feature defaults limit interpretation.

`experiments/multilingual-results.json` records 18 translated author diagnostics: 5/9 suspicious flagged, 4/9 benign falsely flagged, six abstentions (every Hindi item), and warm case latency around 0.75–0.77 ms in the recorded environment. The blind [annotation workflow](ANNOTATION.md) validates complete labels from at least two distinct named human attestations and third-person disagreement adjudication, with agreement statistics. Independent human labels are still pending; editable attestations do not prove identity/independence. No BERT performance is claimed.

The optional [four-validator QBFT study](WEB3_NETWORK.md) measures real local consensus crash outages with an authenticated isolated signer. It permits access/new checkpoints with one node stopped, denies both with two stopped and confirms recovery/revocation. Six sequential confirmations have median 1010.445 ms (769.14–1415.76 ms). Four containers on one host remain under one administrator; no Byzantine, wide-area or independently administered result is claimed. Authentication now has [cryptographically verified passkey/TOTP APIs](AUTHENTICATION.md), software-authenticator tests and observed-context session step-up. Hardware usability, trusted device telemetry and production assurance remain unestablished.

## Improving research validity next

1. Obtain independently verified organizational outcomes with enough positives for each prespecified partition; the completed public prefix still lacks eligible takeover labels.
2. Combine user separation with a later-time test where feasible, report class imbalance and test distribution shift. Existing user-disjoint cohorts overlap in time.
3. Collect independently labeled human justifications through the completed blind workflow; judgments remain distinct from attack outcomes and authorization votes.
4. Extend the matched calibration controls to independent populations with uncertainty and false-positive burden; current repeated seeds share a simulator.
5. Benchmark optional BERT and LLM components independently before claiming gains.
6. Test privacy-preserving features, fairness across groups, and data retention.

The final Word/PDF research assets remain unchanged. The obsolete remote `ProjectInfo.md` proposed a different unfinished stack; the implemented Python/React architecture supersedes that scaffold. Verified primary readings and a claim-evidence map live in [research notes](../research_notes/Adaptive%20IAM%20evidence%20study/readings.md) and [gap analysis](../research_notes/Adaptive%20IAM%20evidence%20study/gap-analysis.md). A new manuscript must cite measured artifacts, distinguish simulations from external evidence, and avoid unsupported first-system or unified-novelty claims.
