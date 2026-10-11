# Adaptive IAM validation controls

Prepared 10 October 2026. Narrow update for the new validation artifacts; not a comprehensive literature search, novelty claim, or replacement for the earlier evidence report. Local artifact links identify the exact measured sources. SHA-256 snapshots below bind this reading to file bytes; they do not attest that measurements were independently audited. The coordinator generated and visually checked the standalone [validation figure PNG](<D:/Projects/Adaptive IAM/experiments/figures/validation-controls.png>) and [SVG](<D:/Projects/Adaptive IAM/experiments/figures/validation-controls.svg>) from these results.

## What do the repeated training controls establish?

### Takeaway

Five complete retraining runs improve probability calibration while preserving every matched raw/calibrated decision. The controlled result supports better probability estimates on this synthetic generator; it does not support attributing better ranking or matched access decisions to calibration. [Measured protocol](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>)

### Cited Findings

| Claim | Completed evidence | Limit |
| --- | --- | --- |
| Calibration was evaluated separately from threshold tuning | Five prespecified seeds, fresh generation and full fitting for each, separate train/calibration/selection/test partitions, identical-score operating-point controls | One synthetic generator; no organizational transfer evidence. [Protocol](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>) |
| Ranking and matched decisions did not improve | Raw and calibrated matched classification, challenge-or-block, and high-risk block decisions are identical in all five runs | Improved F1 against the fixed paper threshold can arise from threshold selection. [Runs](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>) |
| Independent generator data was actually acquired | 200,000 public author-synthesized rows, prefix sample, separate chronological and user-disjoint studies | All values remain artificial; takeover partitions are ineligible. [Provenance](<D:/Projects/Adaptive IAM/experiments/external-data.json>), [study](<D:/Projects/Adaptive IAM/experiments/external-study.json>) |
| Multilingual diagnostics expose a gap | 18 author items across six shared semantic groups; all six Hindi runtime assessments abstain | No independent human corpus or BERT experiment. [Diagnostics](<D:/Projects/Adaptive IAM/experiments/multilingual-results.json>) |
| Multi-validator execution and crash outages were measured | Four distinct Besu validators, narrow authenticated signer, one/two-node outages, recovery and revocation | One host/administrator, not measured Byzantine resilience or independent administration. [QBFT results](<D:/Projects/Adaptive IAM/experiments/qbft-results.json>) |

The retraining seeds are **20261020–20261024**. Every run uses **6,000 training / 1,000 calibration / 1,000 selection / 2,000 held-out test** rows. Calibration is retained only for a positive sigmoid slope and lower selection-partition Brier loss; it was retained in all five runs. Test scores do not select the runtime model or thresholds. [Protocol](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>)

Five-run held-out means, rounded to six decimal places:

| Metric | Fixed paper baseline | Raw validation-matched control | Calibrated validation-matched |
| --- | ---: | ---: | ---: |
| Classification F1 | 0.449909 | 0.462163 | 0.462163 |
| ROC-AUC | 0.766156 | 0.766156 | 0.766156 |
| Average precision (PR-AUC definition) | 0.495279 | 0.495279 | 0.495279 |
| Brier loss | 0.180707 | 0.180707 | 0.113446 |
| Ten fixed-bin ECE | 0.248165 | 0.248165 | 0.021704 |
| Suspicious challenge-or-block recall | 0.881372 | 0.869890 | 0.869890 |
| Legitimate challenge-or-block friction | 0.607881 | 0.589273 | 0.589273 |

Source for every table entry: [risk-protocol.json, summary](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>). Means/sample standard deviations/ranges describe five prespecified synthetic runs, not population confidence intervals. The separate validation-targeted 80% policy attains held-out mean recall **0.770041**, range **0.700000–0.814925**, and mean legitimate friction **0.405905**; the validation target does not guarantee test recall. [Same artifact](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>)

### Inferences

- The clean attribution is calibration quality versus operating-point choice. Mapping the high cutoff through a monotone calibrator deliberately isolates identical block decisions. This agrees with the official documentation's account of sigmoid calibration preserving ranking. [Protocol](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>), [scikit-learn calibration](https://scikit-learn.org/stable/modules/calibration.html)
- More reliable synthetic probabilities can support clearer risk interpretation, but lower Brier/ECE alone does not establish stronger attack detection or safer production authorization. [Protocol limitations](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>)

### Gaps

- Real organizational telemetry, confirmed deployment attack labels, independent replication, and cross-organization validity remain unmeasured. No runtime replacement follows from this study. [Protocol limitations](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>)

## What do the external and multilingual evaluations show?

### Takeaway

The public sample adds a second generator and split sensitivity, not real deployment validation. Language diagnostics currently establish abstention and error observations; the implemented annotation workflow still needs actual independently collected human submissions. [External study](<D:/Projects/Adaptive IAM/experiments/external-study.json>), [annotation protocol](<D:/Projects/Adaptive IAM/docs/ANNOTATION.md>)

### Cited Findings

The authors describe the public RBA dataset as synthesized from original service behavior, with artificial values, and discourage productive use. `Is Attack IP` means an IP found in known attacker data; it is distinct from the source's `Is Account Takeover` field. The license is CC BY 4.0 and requests citation of Wiefling et al. (2022), DOI **10.1145/3546069**. [Author README](https://github.com/das-group/rba-dataset), [license](https://github.com/das-group/rba-dataset/blob/main/LICENSE)

The acquired prefix contains **200,000 rows, 3 takeover labels, and 18,564 Attack-IP labels**. It was sorted by login timestamp. Only **8,424,171** archive bytes were retrieved from a **1,093,700,330**-byte archive through bounded HTTPS ranges; the entire archive checksum and completed CSV member CRC were **not verified**. The retained sample has its own SHA-256. [Acquisition manifest](<D:/Projects/Adaptive IAM/experiments/external-data.json>)

Takeover evaluation refuses both splits: chronological positives are **3/0/0/0** across training/calibration/selection/test; user-disjoint positives are **1/0/1/1**. The evaluator requires both classes in every partition and fabricates no score. [External study](<D:/Projects/Adaptive IAM/experiments/external-study.json>)

| Attack-IP proxy metric | Chronological baseline → candidate | User-disjoint baseline → candidate |
| --- | ---: | ---: |
| Held-out rows / positives | 40,000 / 3,514 | 96,890 / 10,976 |
| Train/test overlapping users | 2,033 | 0 |
| Validation-selected classification threshold | 0.5 → 0.13 | 0.5 → 0.075 |
| F1 | 0.087257 → 0.140454 | 0.155654 → 0.154626 |
| Recall | 0.075413 → 0.223392 | 0.255284 → 0.211097 |
| ROC-AUC | 0.582818 → 0.582818 | 0.503869 → 0.503869 |
| Brier loss | 0.177771 → 0.080476 | 0.197026 → 0.104216 |

Source for every entry: [external-study.json](<D:/Projects/Adaptive IAM/experiments/external-study.json>). Keeping calibrated policy cutoffs at **0.3/0.7** gives **zero challenge/block recall and zero friction** in both proxy studies: every test event falls in the allow tier. This is an explicitly unchanged-cutoff ablation, **not the deployed policy**. Chronological splitting permits repeated users; the user-disjoint study has overlapping time periods. [Same artifact](<D:/Projects/Adaptive IAM/experiments/external-study.json>)

The multilingual run records **no independent human labels**, **no BERT measurement**, and **no model/threshold changes**. Against author expectations, classifier agreement is **9/18 = 0.5**. Runtime advisory agreement, retaining abstentions in the definite-reference denominator, is **7/18 = 0.388889**; definite coverage is **12/18 = 0.666667**. It flags **5/9** author-suspicious items and **4/9** author-legitimate items. All **6 Hindi** items abstain; English agreement is **4/6**, Hinglish **3/6**. Median case warm CPU latency is **0.773837 ms English**, **0.750130 ms Hindi**, **0.750937 ms Hinglish**, from five sequential warm assessments per item, excluding initialization. [Multilingual results](<D:/Projects/Adaptive IAM/experiments/multilingual-results.json>)

The annotation pipeline freezes a digest, blinds author/model outcomes, requires at least two distinct named human attestations, exact complete unique case coverage, valid labels and substantive rationales; disagreements require a third distinct human adjudicator and complete disputed-case resolution. It reports agreement and pairwise Cohen's kappa, including `null` for undefined kappa. Editable attestations cannot prove identity or independence. Human intent labels would still differ from verified account compromise and access votes. [Annotation protocol](<D:/Projects/Adaptive IAM/docs/ANNOTATION.md>)

### Inferences

- Chronological F1 gain cannot justify a general external improvement claim: user-disjoint F1 and recall regress, near-chance ranking persists, and the fixed-cutoff policy misses all proxy positives. [External study](<D:/Projects/Adaptive IAM/experiments/external-study.json>)
- Hindi abstention avoids pretending unsupported language confidence, but supplies no evidence of successful Hindi intent detection. Translations share six semantic groups, so the 18 rows are not 18 independent semantic samples. [Multilingual limitations](<D:/Projects/Adaptive IAM/experiments/multilingual-results.json>)

### Gaps

- Independently supervised human collection, signed collection records, reconciled labels, and independent language evaluation remain pending. No independent kappa or BERT benefit is currently measured. [Annotation protocol](<D:/Projects/Adaptive IAM/docs/ANNOTATION.md>), [diagnostic status](<D:/Projects/Adaptive IAM/experiments/multilingual-results.json>)
- More representative data with adequate takeover positives, consented deployment outcomes, matched external policy controls, and multi-organization holdouts are still needed. The prefix is a convenience sample. [External study limitations](<D:/Projects/Adaptive IAM/experiments/external-study.json>)

## What does the Web3 study establish, and which readings support interpretation?

### Takeaway

The chain evidence is actual local four-validator execution with controlled crash outages and narrow signer boundaries. It strengthens execution evidence while leaving independent administration, Byzantine faults, wide-area behavior, and production service levels untested. [QBFT results](<D:/Projects/Adaptive IAM/experiments/qbft-results.json>), [network runbook](<D:/Projects/Adaptive IAM/docs/WEB3_NETWORK.md>)

### Cited Findings

Four **Besu 26.9.0** validators on one Docker Desktop Linux host use chain **31337**, distinct validator keys and synthetic IAM state. RPC is unpublished; the API does not receive the writer key. The authenticated signer is restricted to the registry's checkpoint/grant/revoke operations. An encrypted writer keystore and its password co-reside in the signer volume, so this is container isolation rather than HSM protection against the host administrator. [Results](<D:/Projects/Adaptive IAM/experiments/qbft-results.json>), [key boundaries](<D:/Projects/Adaptive IAM/docs/WEB3_NETWORK.md>)

- Baseline: four responsive validators, identity-bound approved grant, no unlocked accounts. One validator stopped: three responsive validators, existing grant allowed, new checkpoint confirmed. Two stopped: access/new anchors denied and height stayed **21** during a **4-second** observation. Recovery restored access, and signed revocation denied the formerly valid grant. [Measured phases](<D:/Projects/Adaptive IAM/experiments/qbft-results.json>)
- Six sequential confirmed transactions took **1086.81, 934.08, 775.06, 1415.76, 1092.14, 769.14 ms**; median **1010.445 ms**, range **769.14–1415.76 ms**. Recovery plus final revocation took **44.552 seconds**, including startup/polling/revocation. These measurements exclude human review and are not throughput or production SLO evidence. [Latency and phases](<D:/Projects/Adaptive IAM/experiments/qbft-results.json>), [measurement definition](<D:/Projects/Adaptive IAM/docs/WEB3_NETWORK.md>)
- Access additionally requires three responsive validators agreeing on a recent common block with fresh heads; the guard is uncached. Signer writes currently submit through validator 1, whose outage can interrupt writes despite remaining consensus quorum. [Live authority runbook](<D:/Projects/Adaptive IAM/docs/WEB3_NETWORK.md>)

Primary readings verified on 10 October 2026, and their narrow relevance:

| Primary source | Relevance | What it does not establish here |
| --- | --- | --- |
| [Guo et al., 2017, PMLR 70:1321–1330](https://proceedings.mlr.press/v70/guo17a.html), [PDF §2 / pp. 2–3](https://proceedings.mlr.press/v70/guo17a/guo17a.pdf) | Calibration/reliability diagrams and finite-bin ECE support separately reporting probability quality | Neural-network image/document experiments do not verify this IAM blend or deployment validity |
| [scikit-learn probability calibration](https://scikit-learn.org/stable/modules/calibration.html), §§1.16.2–1.16.3 | Separate fitting/calibration data; sigmoid's strictly monotone transformation preserves ranking | Calibration alone does not justify safer unchanged access thresholds |
| [Artstein & Poesio, 2008, CL 34(4):555–596](https://aclanthology.org/J08-4004/), [PDF §§2.1–2.4 / pp. 556–560](https://aclanthology.org/J08-4004.pdf) | Chance-corrected agreement and distinction between reliable coding and valid labels | High agreement cannot guarantee truth, independent annotators, or actual compromise |
| [RBA author repository](https://github.com/das-group/rba-dataset), [CC BY 4.0 license](https://github.com/das-group/rba-dataset/blob/main/LICENSE) | Data provenance, artificial values, separate Attack-IP/takeover semantics and attribution | A 200,000-row prefix is not representative raw production data |
| [Besu QBFT tutorial](https://docs.besu-eth.org/private-networks/tutorials/qbft/), [consensus reference](https://docs.besu-eth.org/private-networks/how-to/configure/consensus/qbft) | Four-validator setup, quorum and timeout context; tutorial warns that an isolated private network alone is not secure | The current crash experiment does not demonstrate Byzantine fault tolerance under attack |

Snapshot SHA-256 values for the local evidence read here:

| Artifact | SHA-256 |
| --- | --- |
| `experiments/risk-protocol.json` | `0a0c772530351d81dc79d7108b1682a9e426cbdb50e0752ebcaebe718a9ccfc8` |
| `experiments/multilingual-results.json` | `e29d311e9d9bc9cfc62dd68a2e9cf983ab654fefa86ee2554ba3facdf24924a0` |
| `experiments/external-study.json` | `116f64ecb48484b291f7819e9508e7b7769b2260d78c33a8137007b998171949` |
| `experiments/external-data.json` | `7ee29900e820e30c812954b0a3228475d84b489021d111cc522551da757f4c7c` |
| Retained external sample (manifest) | `f89528874e282776c60db26dd2f3c2cb28cec53ed87cc53c9d33633b0d8e18e3` |
| `experiments/qbft-results.json` | `d6764687d5dee7e67d9047ae2161b35b8600f957ad53cb03fb2e549a792cc501` |
| `docs/ANNOTATION.md` | `c70c9d9be5f3307e950c4d8cd654d469e0ff14fbc6b57d9db1d4f6152379f00f` |
| `docs/WEB3_NETWORK.md` | `bcee14d3e131d8f522265caa678f745feb7c8cc3149ac57aafd1fe04f2424f61` |

### Inferences

- The defensible research contribution is a reproducible evaluation/control package that exposes gains, regressions and incomplete evidence while preserving server-enforced human authorization. Neither chain use nor a calibration curve establishes model accuracy improvements. [Risk limitations](<D:/Projects/Adaptive IAM/experiments/risk-protocol.json>), [Web3 limitations](<D:/Projects/Adaptive IAM/experiments/qbft-results.json>)

### Gaps

- Independent operators/multi-host deployment, Byzantine and wide-area fault injection, governance/key rotation, backups, HSM/secret-store operations, and larger latency/throughput studies remain external work. The exporter prepares public configuration packages but deploys no independent operators. [Operator runbook](<D:/Projects/Adaptive IAM/docs/WEB3_NETWORK.md>)
- No exhaustive related-work search was performed in this narrow update; novelty and publishability require separate review. This note's primary readings provide methodological context only.
