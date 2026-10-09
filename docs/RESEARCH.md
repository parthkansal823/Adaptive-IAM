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
| Smart-contract timed grants | Backend-enforced expiry in local storage | No deployed smart contract |
| SHA-256 permissioned blockchain | Canonical local SQLite hash chain and integrity verification | No distributed consensus or immutable storage |

## Evaluation discipline

Paper figures of 85–92% risk accuracy and 83–89% NLP accuracy are projections drawn from related work, not observations from this implementation. Quote actual numbers only from a generated experiment report, with dataset size, seed, split, hardware and conditions.

Compare candidates on the same held-out examples. Tune models and calibration on training/validation data only. Keep the test split untouched by model selection. Report suspicious-class recall, precision, ROC-AUC, PR-AUC, Brier score/calibration, and latency alongside accuracy. For text, group generated templates before splitting so near-identical variants do not inflate the test result.

The risk report separates binary classification metrics from authentication policy. The paper baseline uses 0.3/0.7 boundaries; the candidate chooses a low challenge boundary on validation data to meet an 80% suspicious-detection target, while retaining high cutoff 0.7. Read `suspicious_challenge_or_block_recall`, `suspicious_direct_allow_rate` and `legitimate_friction_rate`: reduced friction can mean more suspicious logins proceed directly. The rejected ablation of calibrated probabilities with unchanged paper cutoffs makes that failure explicit. Calibration gains alone do not establish a stronger security policy. Always-legitimate and static-password baselines expose misleading accuracy under imbalance.

The default NLP report measures the held-out TF-IDF/Naive Bayes classifier. Runtime lexical safety flags and optional BERT are not independently measured by that classifier report. Report poor held-out suspicious recall explicitly instead of using training performance or the paper's projected scores as a substitute.

Synthetic labels are produced by a controllable simulation, so high scores demonstrate agreement with that simulation. They do not demonstrate resistance to real attackers or generalization to a company's users. Latency excludes unknown external network delays unless specifically measured.

Access-review votes must never be automatically converted into authentication attack labels. Approval of a legitimate business need does not show whether credentials were stolen; such a feedback loop could poison a risk model. Retraining requires separately verified outcomes and provenance.

## Improving research validity next

1. Evaluate independent risk-based authentication data with documented provenance. The optional public RBA adapter uses a creator-synthesized dataset, not raw organizational telemetry.
2. Split login data by user/time, report class imbalance, and test distribution shift.
3. Validate reviewer/justification decisions with independently labeled human examples.
4. Run calibration and threshold ablations; include confidence intervals and false-positive burden.
5. Benchmark optional BERT and LLM components independently before claiming gains.
6. Test privacy-preserving features, fairness across groups, and data retention.

The final Word/PDF research assets remain unchanged. The obsolete remote `ProjectInfo.md` proposed a different unfinished stack; the implemented Python/React architecture supersedes that scaffold. Verified primary readings and a claim-evidence map live in [research notes](../research_notes/Adaptive%20IAM%20evidence%20study/readings.md) and [gap analysis](../research_notes/Adaptive%20IAM%20evidence%20study/gap-analysis.md). A new manuscript must cite measured artifacts, distinguish simulations from external evidence, and avoid unsupported first-system or unified-novelty claims.
