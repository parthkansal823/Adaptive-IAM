# Reproducible research evidence

The new [uncertainty and conservative verification study](../docs/UNCERTAINTY_STUDY.md) is separate from the original model evaluation below. Run `npm run research:uncertainty` from the project root to reproduce five fresh fits and four fixed test conditions; `python experiments/plot_uncertainty.py` exports its SVG/PNG figure using the analysis requirements. The [measured JSON](uncertainty-study.json) retains source/split hashes, per-seed rates/counts/intervals and detection/friction regressions. The console reads the same frozen report. No live model or authorization rule is replaced.

From the repository root, run `python experiments/evaluate.py`. Install `backend/requirements.txt` first. The command retrains from the seeded generator and writes `experiments/results.json`; it does not reuse the running API's cached model. CPU latency varies between machines and runs. Classification metrics are deterministic with the pinned environment.

The login data contains 10,000 synthetic events: 6,000 training, 1,000 calibration, 1,000 model/threshold selection, and 2,000 held-out test events. Splitting precedes learned preprocessing. Models fit training data only. Sigmoid calibration fits calibration data only. The selection partition decides whether to retain an interaction-feature candidate, whether calibration improves Brier error, and the maximum-F1 classification threshold. Test data never decides these settings. The interaction candidate was rejected by validation, so the deployed ensemble preserves the original `0.4 × LR + 0.6 × RF` model.

| Held-out synthetic metric | Original blend | Calibrated blend |
| --- | ---: | ---: |
| Accuracy | 74.90% | 81.50% |
| Suspicious precision | 37.33% | 47.27% |
| Suspicious recall | 64.00% | 49.43% |
| F1 | 0.4716 | 0.4832 |
| ROC AUC | 0.7743 | 0.7743 |
| Brier error (lower is better) | 0.1747 | 0.1165 |
| Classification threshold | 0.50 | 0.26 |

This is a calibration and friction tradeoff: classification suspicious recall decreases, and ranking performance remains unchanged. Always predicting legitimate achieves 82.50% accuracy on this imbalanced test set while detecting no suspicious events. Accuracy alone does not establish security value. The JSON includes this majority baseline, a conceptual static credential policy, confusion matrices, and authentication-policy metrics. The 0.26 evaluation classification threshold is separate from authentication policy.

The deployed challenge threshold is selected on validation to detect at least 80% of suspicious events while minimizing legitimate friction. It is **0.105330**, with the high-risk blocking cutoff kept at **0.7**. Held-out challenge/block recall is 84.00%, compared with 86.86% for the original uncalibrated 0.3/0.7 policy; legitimate friction falls from 56.48% to 51.45%. Blocking of legitimate test events falls from 4.18% to zero. This remains a security/usability tradeoff rather than an across-the-board improvement. The unchanged calibrated 0.3/0.7 policy was rejected because challenge/block recall would fall to 41.14%; that ablation remains in the JSON. The validation target does not guarantee test or real-world detection.

Justification evaluation uses 2,000 synthetic texts with disjoint template groups across training (1,200), validation (400), and test (400). The TF-IDF/Naive Bayes classifier has weak held-out suspicious recall (0.625%), with 60.25% accuracy. This is recorded rather than replaced with the paper's projected 83–89%. Handwritten runtime flags can mark overt bypass/exfiltration language for reviewers, but they are not evaluated BERT inference or proof of generalization. All justifications require human review regardless of classifier confidence. No BERT benchmark is claimed.

## Equal operating-point controls and full retraining

`python experiments/risk_protocol.py` independently regenerates and fully refits five prespecified seeds (20261020–20261024), each with the same 6,000/1,000/1,000/2,000 partitions. This differs from `robustness.py`, which applies one frozen model to bootstrap samples and fresh batches. Positive-slope sigmoid calibration is retained only for lower selection-partition Brier loss. Both raw and calibrated models receive identical exact validation-score F1 tuning and the same validation detection target, derived from the raw baseline policy. Mapping the raw high cutoff through the sigmoid also controls block decisions.

| Five-run held-out mean | Paper baseline | Raw matched control | Calibrated matched control | Calibrated 80% validation target |
| --- | ---: | ---: | ---: | ---: |
| F1 | 0.449909 | 0.462163 | 0.462163 | 0.462163 |
| Brier loss | 0.180707 | 0.180707 | 0.113446 | 0.113446 |
| Average precision | 0.495279 | 0.495279 | 0.495279 | 0.495279 |
| Challenge/block detection | 88.14% | 86.99% | 86.99% | 77.00% |
| Legitimate friction | 60.79% | 58.93% | 58.93% | 40.59% |

Raw/calibrated controls make **identical classification, challenge and mapped-block decisions in all five runs**. Calibration improves probability error; equal tuning explains why ranking, F1 and matched-policy outcomes are unchanged. Mean ten-bin ECE falls from 0.248165 to 0.021704, with individual counts/gaps retained. ECE depends on binning and sample size and is not a population guarantee. The 80%-validation policy attains only 70.00–81.49% test detection across runs. `risk-protocol.json` includes per-seed values, sample standard deviations/ranges, full-fit time, digests and environment. No runtime model is replaced.

## External generator and eligibility failure

`external-data.json` records a 200,000-row prefix from the [creator-synthesized public RBA corpus](https://github.com/das-group/rba-dataset), independent of this project's generator and licensed [CC BY 4.0](https://github.com/das-group/rba-dataset/blob/main/LICENSE). It remains artificial data, not raw production telemetry. Bounded HTTP ranges retrieve the compressed prefix; the sample SHA-256 is checked, while full archive checksum and member CRC are explicitly unverified. Do not describe the convenience prefix as representative.

Only three `Is Account Takeover` positives occur, so both chronological and user-disjoint four-partition studies reject takeover evaluation. No takeover scores are invented. Separately labeled **Attack-IP proxy** studies are measured in `external-study.json`: chronological F1 0.087257→0.140454; user-disjoint F1 0.155654→0.154626 (regression). These compare fresh fits, not a deployed model's transfer to a new organization. Chronological train/test overlap is 2,033 users; user-disjoint overlap is zero, with overlapping time periods and event counts 77,498/12,558/13,054/96,890.

The calibrated **unchanged 0.3/0.7 policy ablation allows every test event in both proxy studies**, detecting none. It is not a deployment recommendation. Classification tuning, probability-error improvement and authentication security are distinct. Acquisition and adapter commands are documented by `python scripts/acquire_rba_sample.py --help` and `python scripts/evaluate_rba.py --help`.

## Language collection and measured diagnostics

`python experiments/multilingual.py` evaluates 18 new author diagnostic items in six translated semantic groups. Runtime flags 5/9 author-suspicious cases and falsely flags 4/9 author-benign cases; all six Hindi cases abstain. English/Hinglish each falsely flag 2/3 benign examples. Warm median case latency is approximately 0.75–0.77 ms in the recorded Linux container, excluding initialization. These small counts expose failure modes; they are not independent accuracy estimates. No BERT model was available.

The [annotation protocol](../docs/ANNOTATION.md) and `scripts/annotation_eval.py` support frozen blind exports, at least two distinct named human attestations, exact digest/completeness checks, pairwise Cohen's kappa and a third independent adjudicator for every disagreement. The tool rejects declared model annotations and partial labels; it cannot prove a JSON submitter's identity or independence. **Independent human labels remain pending.** The optional evaluator consumes and revalidates the original annotation files. Artificial unit fixtures are never measured research data.

## Isolated reproduction and figures

The analysis service has no network, a read-only root filesystem, dropped capabilities and a non-root user. After building its image, current source mounts must match the analyzed version. New scripts run with:

```sh
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm --build analysis python experiments/risk_protocol.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/multilingual.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python experiments/plot_protocol.py
docker compose -f compose.yaml -f deployment/compose.analysis.yaml --profile analysis run --rm analysis python -m unittest discover -s experiments/tests
```

`plot_protocol.py` exports `figures/validation-controls.svg` and `.png`: pooled fixed-bin reliability, five-run policy means ± descriptive sample SD and the multilingual counts. Inspect artifacts before submission. The [new evidence report](../reports/Adaptive%20IAM%20validation%20controls.md) separates these results from earlier experiments and real deployment claims.

The source paper presents expected performance, not a measured implementation dataset. These results assess the supplied synthetic generator, not enterprise attack detection. A real-data study needs independently labeled events, temporal/user-separated splits, a frozen external test set, threshold sensitivity, subgroup checks, and repeated seeds. Access approval votes are not malicious-login ground truth and must not automatically retrain this risk model.
