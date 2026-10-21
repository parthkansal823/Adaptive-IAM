# Synthetic uncertainty and conservative step-up study

This separate experiment asks whether uncertainty sets can reduce direct allows of simulator-suspicious events, what extra legitimate-user challenge burden that costs, and how coverage behaves when test conditions change. It adds a reproducible synthetic stress study; it does not replace the running risk model or authorize access. The method is an application of established conformal prediction, not a claim to a new conformal algorithm or the first adaptive IAM system.

The measured artifact is [`experiments/uncertainty-study.json`](../experiments/uncertainty-study.json); the executable protocol is [`experiments/uncertainty_study.py`](../experiments/uncertainty_study.py). Original papers, existing result files, runtime model artifacts and research assets remain unchanged.

## Protocol fixed before the first run

Five new seed identifiers are fixed: `20261101` through `20261105`. These integers are identifiers, not data-collection dates. Each run generates 12,000 events with the existing probabilistic ten-feature simulator and uses disjoint positional splits:

| Partition | Rows | Purpose |
| --- | ---: | --- |
| Training | 6,000 | Fit the fixed standardized LR/RF blend |
| Probability calibration | 1,000 | Fit a sigmoid on raw logit scores |
| Selection | 1,000 | Retain sigmoid only with positive slope and lower Brier loss; select baseline low threshold |
| Conformal calibration | 2,000 | Fit marginal and class-conditional nonconformity quantiles |
| IID test | 2,000 | Evaluate all fixed methods without selection or refitting |

The blend uses the existing `experiments.risk_protocol.fit_blend`: weight 0.4 on standardized logistic regression and 0.6 on a 100-tree random forest, including its existing class weights and hyperparameters. Each seed fits independently; no polynomial interaction search is added. The selection rule chooses the largest observed suspicious score attaining at least 80% detection on selection data. It cannot guarantee 80% detection on another sample. Held-out and shifted labels never fit probabilities, thresholds, nonconformity quantiles or method choice. Alpha is fixed at `0.1`; no result-dependent sensitivity sweep or retry-seed selection is performed. This is local prespecification in code and documentation, not external preregistration.

For the observed label, nonconformity is `1 - p(true label)`. With `n` calibration scores, use the exact order statistic at rank `ceil((n+1)*(1-alpha))`; unavailable ranks yield `q=1`, including an absent calibration class. Include a label when its nonconformity is `<= q`, preserving ties. Marginal prediction sets share one quantile; class-conditional sets use one quantile per label. Sets may contain zero, one or both labels, and all cases remain in reported denominators. [Angelopoulos and Bates](https://arxiv.org/abs/2107.07511) explain the construction, class-conditional extension and exchangeability requirement. A nominal 90% coverage statement averages calibration/test randomness; it is not a probability that every individual event is safe.

Compare four fixed rules: the validation-selected baseline, baseline plus a marginal-set gate, baseline plus a class-conditional-set gate, and always-challenge. Either gate directly allows only when the baseline would allow **and** the set is exactly `{legitimate}`. Empty sets, both-label sets and suspicious singletons require step-up. Therefore these gates can only add challenges relative to the baseline; they cannot broaden direct allows. For a suspicious event, a direct allow implies true-label set miscoverage. This implication is an algebraic property of the rule, not evidence about real compromises. The study counts any baseline challenge/block or added step-up as a challenge; it does not estimate high-risk blocks separately or simulate the success of an actual MFA challenge. Actual resource authorization remains server enforced.

## Test conditions

Each method evaluates the same rows within a condition and seed:

| Condition | Prespecified construction | Interpretation |
| --- | --- | --- |
| IID | Untouched 2,000-row test partition | Same simulator distribution as calibration |
| Remote-work covariate shift | Fresh 40,000-row pool; accept with probability `(1+3*x0+2*x1+2*x2+2*x4)/10`; retain first 2,000 | Enrich unknown device/location, VPN and unusual hours using features alone; preserve the simulator's conditional labels |
| Missing telemetry | Copy IID test and zero columns `0,1,2,7,9` for exactly 50% of randomly selected rows | Corrupt observed telemetry while retaining original latent labels; pair directly with IID rows |
| Suspicious-prevalence shift | Fresh 40,000-row pool; accept suspicious rows with probability 1 and legitimate rows with probability 0.25; retain first 2,000 | Pure label-based sampling preserves feature distribution conditional on label |

Generator, rejection and mask seed offsets are recorded. A rejection pool with fewer than 2,000 accepted rows fails the study rather than silently changing the design. Candidate-pool and accepted-row hashes are retained. No shifted population is added to training or calibration.

Unweighted conformal coverage need not survive remote-work or telemetry changes. [Tibshirani, Barber, Candes and Ramdas](https://arxiv.org/abs/1904.06019) motivate weighted conformal under covariate shift; this study does not implement their correction. Class-conditional coverage can transfer under the deliberately pure label-shift assumption because sampling preserves `X|Y`. This assumption is constructed here, not verified for real changes in attack prevalence. Marginal coverage does not generally carry over to label shift. The experiment tests those boundaries without promoting observed finite-sample coverage into a universal guarantee.

## Reporting and reproduction

Each run reports class counts, suspicious direct-allow/detection rates, legitimate friction, overall challenge rate, extra detection/friction relative to baseline and their numerators/denominators. Conformal methods also disclose overall/per-class coverage, mean set size, empty sets, both-label sets and each singleton count. Always-challenge supplies the trivial 100% detection and 100% legitimate-friction control; additional challenge is a cost, not an unqualified benefit.

Per-run rate intervals are descriptive Wilson 95% intervals conditional on a fitted rule. They omit training/calibration uncertainty, are not simultaneous intervals and are not paired-difference significance tests. Methods share samples; missing telemetry also shares rows and labels with IID. Across the five fits, the artifact reports equal-weight means, sample standard deviations and ranges rather than pooling events into an apparent independent deployment sample or claiming population confidence from five seeds.

Telemetry masking assigns exactly half of the rows without replacement, so its mixed-condition counts are not identically distributed independent Bernoulli trials. Wilson bounds there remain descriptive summaries; no exact binomial or nominal interval-coverage claim is made for that fixed allocation.

The report stores source hashes, every split hash, test/pool hashes, class counts, selected thresholds, sigmoid selection evidence, conformal quantiles, package versions and protocol assumptions. Hashes bind shape/dtype plus canonical little-endian numeric bytes, avoiding machine byte-order differences. CPU/library differences can still affect fitted predictions. Reproduce from the project root:

```powershell
.venv\Scripts\python.exe scripts/run_tests.py -s experiments/tests -p test_uncertainty_study.py
.venv\Scripts\python.exe experiments/uncertainty_study.py
.venv\Scripts\python.exe scripts/run_tests.py -s experiments/tests -p test_uncertainty_study.py
```

On Linux use `.venv/bin/python`. Tests cover finite-sample ranks/ties, true-label scoring, split isolation, conservative authority, unchanged masked labels, rejection sampling, count/interval denominators and the frozen artifact's consistency. A report generated by an earlier local revision can be preserved with `--output` to a different path; do not retune the fixed protocol after inspecting its test outcomes.

The same author simulator supplies every outcome. No organization, device trust, human approval, attack ground truth, hardware usability, real breach rate or independent deployment benefit is established. Follow-up work needs independent trusted outcomes, new environments and explicit challenge-cost/usability measurement. Coverage and detection regressions under shift belong in the conclusions alongside improvements.

## First measured results, 21 October 2026

All five fixed seeds and all four conditions completed on Python 3.11.2, NumPy 2.4.6 and scikit-learn 1.9.1. The artifact's `protocol.study_date` records the protocol date, 20 October 2026, rather than the measurement date. Every source hash matches the saved implementation. Dataset/split hashes and shifted samples reproduce independently without refitting. No model, threshold-selection rule, alpha, condition or seed was changed after measuring these results. The initial run completed the same five seeds but the sandbox denied its final file write; the identical rerun saved the artifact without inspecting or selecting intermediate outcomes.

Values below are equal-weight means across the five independent fits. Detection counts simulator-suspicious events requiring a challenge; friction counts simulator-legitimate events requiring one. Neither metric measures successful authentication or a prevented real compromise.

| Condition | Baseline detection / friction | Class-conditional gate detection / friction | Added detection / added friction |
| --- | ---: | ---: | ---: |
| IID | 79.21% / 46.82% | 88.89% / 62.56% | +9.68 / +15.74 percentage points |
| Remote-work shift | 91.30% / 66.22% | 96.01% / 79.32% | +4.71 / +13.10 percentage points |
| Missing telemetry | 45.07% / 26.33% | 58.44% / 40.09% | +13.37 / +13.76 percentage points |
| Prevalence shift | 81.25% / 45.88% | 89.43% / 62.36% | +8.18 / +16.48 percentage points |

The marginal gate made exactly the same decisions as the baseline for every condition and seed: it added no detection and no friction. The class-conditional gate added detection at substantial legitimate-user challenge cost. Always-challenge reached 100% detection and 100% friction in every run. These comparisons do not identify a superior deployment method without a justified cost model.

Set coverage shows why aggregate results and distribution changes need explicit reporting:

| Condition | Marginal overall / suspicious-class coverage | Class-conditional overall / suspicious-class coverage |
| --- | ---: | ---: |
| IID | 90.46% / 44.21% | 89.67% / 88.89% |
| Remote-work shift | 89.54% / 59.51% | 84.89% / 96.01% |
| Missing telemetry | 87.03% / 22.49% | 88.89% / 58.44% |
| Prevalence shift | 75.22% / 44.36% | 89.67% / 89.43% |

Marginal IID coverage near 90% hid poor coverage of the minority suspicious class. Class-conditional calibration reduced that disparity on IID data but did not survive missing telemetry: its suspicious coverage and detection fell to 58.44%, with 41.56% of simulator-suspicious events directly allowed. Remote-work shift reduced its legitimate-class coverage to 81.46% and overall coverage to 84.89%, despite higher suspicious detection. The deliberately pure prevalence shift retained approximately 90% coverage for each class (legitimate 89.88%, suspicious 89.43%); this supports only the constructed label-shift case. Marginal coverage fell to 75.22% under that same condition.

Finite-sample variation also matters. IID baseline detection ranged from 71.29% to 85.59%, although every selection split attained the fixed 80% target. IID class-conditional detection ranged from 87.10% to 90.72% (sample SD 1.44 percentage points); its friction ranged from 61.07% to 66.81% (SD 2.39). Under masking its detection ranged from 54.12% to 64.07%. Observed IID means below the nominal 90% level do not contradict a marginal-in-calibration-randomness guarantee and do not establish conditional-on-this-fit coverage. The report retains every per-seed result, interval, count and set-size breakdown, including these regressions.

The practical research contribution is a reproducible uncertainty and stress-evaluation extension to this prototype: it exposes an unhelpful marginal gate, quantifies the cost of a more conservative class-conditional gate, and demonstrates failure under missing telemetry. It establishes no production benefit, new conformal algorithm, deployment recommendation or permission to relax the existing server policy.
