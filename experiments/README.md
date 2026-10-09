# Reproducible research evidence

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

This is a calibration and friction tradeoff: suspicious recall decreases, and ranking performance remains unchanged. Always predicting legitimate achieves 82.50% accuracy on this imbalanced test set while detecting no suspicious events. Accuracy alone does not establish security value. The JSON includes this majority baseline, a conceptual static credential policy, confusion matrices, and authentication-policy metrics at the actual 0.3/0.7 tier thresholds. The 0.26 evaluation classification threshold does not change authentication policy.

Justification evaluation uses 2,000 synthetic texts with disjoint template groups across training (1,200), validation (400), and test (400). The TF-IDF/Naive Bayes classifier has weak held-out suspicious recall (0.625%), with 60.25% accuracy. This is recorded rather than replaced with the paper's projected 83–89%. Handwritten runtime flags can mark overt bypass/exfiltration language for reviewers, but they are not evaluated BERT inference or proof of generalization. All justifications require human review regardless of classifier confidence. No BERT benchmark is claimed.

The source paper presents expected performance, not a measured implementation dataset. These results assess the supplied synthetic generator, not enterprise attack detection. A real-data study needs independently labeled events, temporal/user-separated splits, a frozen external test set, threshold sensitivity, subgroup checks, and repeated seeds. Access approval votes are not malicious-login ground truth and must not automatically retrain this risk model.
