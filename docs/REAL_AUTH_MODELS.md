# Fixed real-authentication model challengers

This offline experiment tests a more informative cold-user score and time-decaying familiarity on two real LANL authentication releases. The [aggregate report](../experiments/real-auth-model-study.json) contains the frozen protocol and every fixed method's measurements. No model is promoted into the IAM policy engine.

## What improves and what remains a hypothesis

The lifetime frequency baseline always gives an entirely new user a score of zero, even on a globally rare computer. The challenger backs off to the computer's **strictly prior global rarity**. Its decayed version also reduces the influence of old observations, using a fixed 24-hour half-life. These are explicit changes to scoring behavior. Whether they improve detection or operating cost is an empirical question; every method is reported even when results regress.

All models observe exactly the same `(relative second, user, destination computer)` fields. This common baseline avoids comparing a destination-only challenger against an earlier source-and-destination edge model with different information. Source computers from LANL2015 are retained only for exact exercise-reference matching. Authentication outcomes, red-team labels and current/future events never enter the scores.

For a candidate computer, let `G` be the prior global event count, `Gc` its prior global computer count, `U` the prior user count and `Uc` that user's prior computer count:

| Fixed method | Score |
| --- | --- |
| Lifetime user/computer | `ln(1 + U) - ln(1 + Uc)` |
| Hierarchical static | `-ln((Uc + 8*pG)/(U + 8))`, with `pG = (Gc + 1)/(G + 2)` |
| Hierarchical decay | Same backoff formula, with all four counts decayed by `exp(-ln(2)*elapsed_seconds/86400)` |

The global formula is a smoothed **marginal Bernoulli propensity** for that computer. The user formula is empirical-Bayes-style backoff toward this propensity. Scores are not a normalized categorical distribution, a full Bayesian posterior, calibrated attack probabilities or permissions. A completely empty system starts at `ln(2)`; a new user's score thereafter reflects the computer's global rarity. Scores are floored into fixed 0.001 bins, with a numerical propensity floor of `1e-12`.

## Frozen protocol

Protocol hash `5795a726e0d1383dafd84d44cdb038659ebb7086683a1e22c00ee20c73ef021a` was persisted before computing new model results. The report records its UTC freeze time. The initial protocol freeze did **not** capture an evaluator source hash; evaluator hash `c1182da4dac8ad8a254f20bda445be50935f7489d66808b139edd3146379cd11` was recorded before evaluation and is the implementation that produced both datasets' saved measurements. Its exact pre-evaluation recording time was not retained. The later provenance-only correction adds per-dataset execution identities without rerunning or changing measured scores. The report separately identifies the source revision that made this metadata correction; that revision must not be presented as the measured implementation. Hyperparameters, bin resolution, all three methods and the following rules were fixed beforehand:

- Chronological elapsed-time windows: 50% warmup, 25% validation, 25% test.
- Entire equal-second groups are scored before any group events update counts. Lazy decay evaluates every numerator and denominator at the same source second. No current-event update occurs inside scoring.
- A fixed 1% validation alert budget determines each method's threshold without labels. All tied binned scores are retained together; if the highest tie exceeds the budget, alerts are disabled.
- History continues to update from earlier observations in validation and test. Labels never affect updates or thresholds.
- Incomplete compressed inputs lose their entire final source-second group. Every method receives the same remaining events. Raw input hashes link each dataset to acquisition provenance.
- Test strata use a shared lifetime history: cold user, known user on new computer, and familiar user/computer. The report gives stratum counts, mean binned scores, zero-score counts and alert burden.

Validation budgets do not guarantee matching test burden. A method with greater exercise recall at greater burden does not establish superiority. Cold-user behavior, detection and alert cost must be evaluated separately; fixing a forced zero score does not guarantee fewer missed attacks.

## Data and scope

The [LANL2015 study](LANL_STUDY.md) already inspected the targeted prefix and its ten selected test exercise tuples. Reusing that prefix here is **retrospective diagnostic evaluation**, not untouched confirmation. Its earlier source/destination baseline and this common user/computer baseline have different information and must not be ranked as direct model substitutions.

The additional LANL2014 release contains real user/computer authentication associations but **no attack labels**. It supports operational novelty and burden measurements only. Both releases come from the same institution. The publication years do not prove independent collection periods: calendar dates are undisclosed and overlap cannot be ruled out. The releases also have different event collection and selection conventions, so shifted burden is not an isolated causal effect of model design.

Unlisted LANL2015 events are unlabeled, not proven benign. Exact exercise tuple recall is reported only where selected reference tuples exist, with separate authentication-row and unique-tuple counts. No accuracy, precision, false-positive rate or AUROC is inferred. LANL2014 has no detection recall. Correlated exercise users/hosts and tiny positive counts prevent broad superiority claims.

Decay can forget legitimate infrequent access and raise alert costs. Every model can learn unlabeled compromise into its history. The experiment does not evaluate evasion resistance, trusted telemetry, live interventions, independent institutions or production IAM outcomes.

## Actual measurements

The shared evaluation includes 4,394,776 selected LANL2015 events and 4,909,698 LANL2014 events. Both raw samples are bounded prefixes with their final source-second group removed. The model parameters and thresholds were not adjusted after seeing these results.

| Fixed method | LANL2015 exercise tuples recalled | LANL2015 unlabeled alerts / 886,214 | LANL2015 unlabeled burden | LANL2014 alerts / 1,543,498 unlabeled events | LANL2014 burden |
| --- | ---: | ---: | ---: | ---: | ---: |
| Lifetime user/computer | 6 / 10 | 8,412 | 0.9492% | 17,581 | 1.1390% |
| Hierarchical static | 7 / 10 | 5,780 | 0.6522% | 24,451 | 1.5841% |
| Hierarchical decay | 7 / 10 | 5,669 | 0.6397% | 23,528 | 1.5243% |

All three validation burdens stay at or below the fixed 1% budget. Test burdens differ. The backoff methods recall one more listed tuple with fewer unlabeled alerts in the previously inspected 2015 window. On the unlabeled 2014 release they issue **more** alerts than the common lifetime control: decay adds 5,947 alerts. This is a burden regression, with no labels to establish whether additional alerts concern attacks or legitimate activity. The experiment therefore provides a candidate and a counterexample to a universal improvement claim.

Cold-user strata make the change concrete:

| Test stratum | Lifetime zero scores | Challenger zero scores | Challenger cold-user alerts |
| --- | ---: | ---: | ---: |
| LANL2015: 126 cold-user events | 126 / 126 | 0 / 126 for both | Static 36 / 126; decay 38 / 126 |
| LANL2014: 492 cold-user events | 492 / 492 | 0 / 492 for both | 484 / 492 for both (98.37%) |

This verifies removal of the forced zero score on these real cold-user events. It also exposes concentrated cold-user alert burden. None of the 2015 cold-user events match the provided exercise tuples, and 2014 has no attack labels; improved cold-start **detection** remains unmeasured. Separate onboarding policies or additional trustworthy signals would need independent evaluation before runtime use.

The older reports use different observables or unbinned scores, so their exact baseline numbers need not match this fixed common-feature, 0.001-bin comparison. All three methods here use identical data, groups, partitions and quantization.

The [SVG research figure](../experiments/figures/real-auth-models.svg) and [PNG companion](../experiments/figures/real-auth-models.png) plot these saved measurements. With the analysis requirements installed, regenerate both using `python experiments/plot_real_auth_models.py`.

## Reproduce

Using previously acquired ignored raw data:

```powershell
python scripts/evaluate_real_auth_models.py freeze
python scripts/evaluate_real_auth_models.py evaluate --lanl-auth data/lanl/study/auth.txt.gz.prefix --lanl-redteam data/lanl/study/redteam.txt.gz --additional-auth data/lanl2014/lanl-auth-dataset-1-00.bz2.prefix --additional-provenance data/lanl2014/provenance.json
python -m unittest experiments.tests.test_real_auth_models -v
```

New protocol freezes capture the evaluator hash immediately. Each evaluation records the execution commitment before scanning inputs and attaches its implementation identity to each dataset it actually evaluates. A partial rerun preserves retained datasets' original execution hashes; if source versions differ, the top-level summary marks mixed implementations and has no single shared hash. A failed run retains a pending commitment without relabeling old results as newly measured. Evaluation requires explicit inputs even if the report already contains results.

The command refuses altered protocol contents, input/provenance hash mismatches and evaluated counts inconsistent with linked source metadata. Use a new `--output` path for a new separately frozen protocol. The research report contains aggregate values and hashes; identifiers stay in ignored raw downloads. See each source study for bounded acquisition, licensing, partial-archive integrity and selection limitations.
