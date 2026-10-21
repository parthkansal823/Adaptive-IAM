# Trained models on observed authentication data

This study actually fits and saves unsupervised IsolationForest estimators on
past features from genuine enterprise authentication records. It adds a fixed
learned baseline, a bounded chronological hyperparameter search and fair count
controls. It does not create benign labels from missing attack annotations,
claim production accuracy or replace the running IAM policy.

The aggregate artifact is [real-auth-training.json](../experiments/real-auth-training.json).
Actual fitted weights stay in ignored `data/real-auth-models/`. The console can
display/export aggregate evidence without loading those executable artifacts.
See [the earlier count-model study](REAL_AUTH_MODELS.md) for the simpler models.

## Sources and study population

| Study key | Observed source | Evaluation purpose |
| --- | --- | --- |
| `lanl2015_retrospective` | LANL 2015 corporate-network authentication, human-source LogOn selection | Alert burden and sparse exercise-tuple recall; already inspected, retrospective diagnostic |
| `lanl2014_month00` | LANL 2014 successful user/computer authentication, first published monthly file prefix | Unlabeled workload and history coverage; already inspected |
| `lanl2014_month01` | Same 2014 release, second monthly file prefix acquired before this training run | Another source-relative time slice; unlabeled workload only |

The [2015 primary source](https://csr.lanl.gov/data/cyber1/) and
[2014 primary source](https://csr.lanl.gov/data/auth/) describe actual LANL
telemetry. Public files come from the openly linked
[Imperial institutional mirror](https://lanl.ma.ic.ac.uk/data/). No contact
details or credentials are submitted. Acquisition limits, selection criteria,
licensing, compressed-prefix hashes and incomplete-archive limitations are in
[LANL_STUDY.md](LANL_STUDY.md), [LANL2014_STUDY.md](LANL2014_STUDY.md) and
[LANL_MONTH01.md](LANL_MONTH01.md).

All are historic releases from **one institution**. Two monthly files are not
two independently operated organizations. Their source-relative windows differ,
but calendar dates are undisclosed and overlap with the other release cannot be
excluded. None of these records contains the runtime IAM's complete features or
verified authorization decisions. The creator-synthesized external RBA corpus
remains a separate evidence class and is not used to fit these forests.

The 2015 prefix was originally targeted after consulting the first public
exercise time. It is label-informed feasibility sampling, not an untouched or
representative external test. The present protocol was fixed before these new
candidate outcomes, but that does not undo previous inspection. Month00 also
has prior model results. Month01 is new to this training extension; its missing
attack labels still prevent confirmation of detection quality.

## What is learned

[IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
fits randomized partitioning trees. Observations isolated with shorter paths
receive more unusual scores. This study uses the negative of `score_samples`,
then floors it to bins of width 0.0001. A large score means unusual relative to
the training feature distribution; it is not a probability of attack.

The fixed forest has 100 trees, `max_samples=256`, `max_features=1.0`,
`contamination='auto'`, `bootstrap=False`, `random_state=20261021` and `n_jobs=1`.
The library's automatic offset is not the operational alert threshold: this
study calibrates its own validation threshold. Every dataset/month fits its own
weights. There is no cross-dataset transfer claim.

### Nine strictly prior features

For a row at source second `t`, let `G`, `U`, `P` and `C` be the number of prior
events globally, for its user, for its user/computer pair and for its computer.
Let `D` be that user's number of distinct previously observed computers. Counts
include only **earlier seconds**. The forest receives these nine numbers:

| Feature | Definition |
| --- | --- |
| User rarity | `-ln((U+1)/(G+2))` |
| Pair rarity within user | `-ln((P+1)/(U+2))` |
| Computer rarity | `-ln((C+1)/(G+2))` |
| Prior global event rate | `ln(1 + G/max(1,t-first_observed_second))`; zero before any history |
| User/computer diversity | `(D+1)/(U+2)` |
| Unseen user | `1` when `U=0`, else `0` |
| Unseen pair | `1` when `P=0`, else `0` |
| User recency | `ln(1+min(86400,t-last_user_second))/ln(86401)` |
| Pair recency | Same transformation for the pair's last source second |

Unseen recencies equal one. Relative frequencies and event rate replace raw
cumulative count features to reduce a trivial history-length proxy. This is a
reasoned feature design, not a demonstrated stationarity guarantee. Traffic
composition, diurnal rates and account behavior can still shift. No scaler is
fitted on validation/test, and no identifier, current success/failure outcome,
exercise annotation or future count is an input feature.

Every event in a complete equal-second group sees identical prior history.
Only after feature construction does the whole group update history. Repeated
user/computer rows share a feature vector, but retain their multiplicities in
reservoir sampling, thresholds and metrics. Canonical ordering of pairs inside
each second makes within-second input reordering immaterial. Identifiers serve
only as history keys and stable ordering keys; they are not embedded in model
features or published in reports.

## Training, tuning and final test

The frozen protocol is embedded in the report. Its SHA-256 is
`52e21b5b223b0bf7b86634eb12dc986d60301ae1bd35270cac15df2255f1e9a1`.
The complete final timestamp group of every partial archive is excluded.
Elapsed source time defines 50% warmup, 25% validation and 25% test. These are
time fractions, so event counts need not be 50/25/25. Entire second groups stay
together.

1. Build features sequentially in warmup and retain at most 30,000 event rows
   using uniform Algorithm R with seed 20261021. Repeated rows are eligible
   separately. The stream is never shuffled across time partitions.
2. Fit every candidate on exactly that reservoir. Validation and test rows do
   not enter fitting. Weights remain frozen from the warmup boundary onward.
3. Divide the validation source-time interval into an earlier calibration half
   and a later selection half, keeping whole source seconds. Calibrate a
   conservative 1% upper-tail alert budget on the earlier half.
4. Evaluate candidate budget stability on the later half. Select the eligible
   candidate minimizing `abs(selection_alert_fraction - 0.01)`. Eligibility
   requires nonempty halves, at least two earlier score bins and an enabled
   earlier threshold. Ties prefer smaller `max_samples`, then smaller
   `max_features`, then stable candidate ID. If none is eligible, disclose a
   fallback to the fixed 256/1.0 forest.
5. Recalibrate the chosen candidate's threshold using all validation. This
   reuses validation after parameter selection, so it is not an independent
   calibration guarantee. Freeze the resulting threshold before test.
6. Evaluate the fixed forest, selected forest and all three count controls on
   the future test window. Report every method and regression. Do not select a
   deployment winner from these outcomes.

For sparse future inputs, an empty calibration half makes every candidate
ineligible: its calibration threshold and calibration alert fraction are null,
and the fixed forest fallback is disclosed. An empty selection half is likewise
ineligible. Provided some validation events exist, the fallback still calibrates
its final threshold on all validation. A wholly empty validation window fails
with a clear error instead of inventing a threshold. All three measured slices
had events in both halves; none used this fallback.

The actual search uses
[`sklearn.model_selection.ParameterGrid`](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.ParameterGrid.html):
`max_samples in {128,256,512}` crossed with `max_features in {0.75,1.0}`,
for six configurations. All other estimator settings stay fixed. With nine
features, the 0.75 setting samples six feature dimensions per tree. Selection
optimizes one stated operational criterion: validation alert-budget stability.
It **does not identify best attack accuracy**, because the missing negative
labels cannot support that objective.

Conservative thresholds include all scores tied at a retained bin. If the top
tie alone exceeds the allowed count, alerts are disabled. No fractional tied
groups or post-test budget adjustments are used. Future workload can exceed
or fall below 1%. Feature/count histories continue to update from all observed
events during validation and test, independent of alerts and labels. The forest
itself is not refitted. Unlabeled compromise may therefore contaminate both
warmup weights and subsequent history.

### Fair count controls

All five methods observe the same user/computer projection and timestamp groups.
The controls are lifetime pair surprise, hierarchical static backoff and
hierarchical backoff with a one-day exponential half-life. Their frozen scores
and 0.001 binning match the earlier count study; their full-validation thresholds
use the same 1% budget. The older source/destination edge baseline observes a
different feature projection and is not a like-for-like learned-model control.

## Measured outcomes

Measured on **21 October 2026**, using Python 3.11.2, scikit-learn 1.9.1,
NumPy 2.4.6 and joblib 1.5.3 on Windows. Source calendar dates are undisclosed;
the measurement date and date-shaped random seed are not collection dates.
The run processes **14,275,164 selected observed events**, with **3,874,417**
held-out test events across the three slices. Each of the six forests per slice
is fitted on its **30,000-row warmup reservoir**, rather than on all 14 million
rows. All prior events still contribute to causal feature histories.

| Slice | Warmup events | Validation events | Test events | Reservoir rows | End-to-end seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2015 targeted prefix | 2,030,503 | 1,478,049 | 886,224 | 30,000 | 201.547 |
| 2014 monthly file 00 | 2,589,367 | 776,833 | 1,543,498 | 30,000 | 145.532 |
| 2014 monthly file 01 | 2,648,897 | 877,098 | 1,444,695 | 30,000 | 149.703 |

Timings include parsing, feature/history updates, all six fits, validation
search, final test scoring and artifact writes. They are not isolated search
benchmarks or deployment latency measurements. Per-candidate wall times were
not measured. The actual run saved **18 fitted 100-tree estimators**; every
artifact SHA-256 and fitted tree count was checked after completion.

### Actual parameter search

All six candidates were eligible in all three slices, so no fallback was used.
The table shows later-validation alert fractions under thresholds learned from
the earlier validation half. The objective is proximity to **1%**; these are
not accuracy scores.

| `max_samples` | `max_features` | 2015 selection alerts | File 00 selection alerts | File 01 selection alerts |
| ---: | ---: | ---: | ---: | ---: |
| 128 | 0.75 | **0.65006%** | **0.89779%** | 0.69741% |
| 256 | 0.75 | 0.62780% | 0.80850% | 0.75981% |
| 512 | 0.75 | 0.60688% | 0.76304% | **0.91902%** |
| 128 | 1.00 | 0.57452% | 0.71244% | 0.76512% |
| 256 | 1.00 | 0.61454% | 0.82149% | 0.74086% |
| 512 | 1.00 | 0.52745% | 0.83881% | 0.67685% |

The selected configurations are 128/0.75 for 2015 and file 00, and 512/0.75
for file 01. All retain 100 trees and the fixed seed. Their final thresholds,
recalibrated on all validation, are respectively **0.6157**, **0.5700** and
**0.5675**. These values are best only for the stated six-candidate validation
objective. The actual future behavior below demonstrates why they cannot be
advertised as universally best model parameters.

### Previously inspected 2015 exercise window

There are ten distinct exactly matched exercise tuples, each matching one
authentication row here, and 886,214 unlabeled test events.

| Method | Total test alerts | Alerts on unlabeled events | Unlabeled alert fraction | Known exercise tuples recalled |
| --- | ---: | ---: | ---: | ---: |
| Fixed forest, 256/1.0 | 3,539 | 3,533 | 0.39866% | 6 / 10 |
| Validation-selected forest, 128/0.75 | 3,514 | 3,507 | 0.39573% | 7 / 10 |
| Lifetime pair surprise | 8,418 | 8,412 | 0.94921% | 6 / 10 |
| Hierarchical static | 5,787 | 5,780 | 0.65221% | 7 / 10 |
| Hierarchical decay | 5,676 | 5,669 | 0.63969% | 7 / 10 |

The selected forest recalls seven of ten listed tuples with fewer unlabeled
alerts than the two hierarchical controls in this particular window. It still
misses three known tuples. Missing negative labels and the tiny clustered
reference prevent an accuracy or general detection-superiority claim. The
older eight-of-ten edge result uses source/destination edges and different
features; it cannot be presented as a direct same-observable comparison.

### Unlabeled monthly test windows and regressions

Every event in these two columns is unlabeled. Each cell gives the alert count
and fraction of that slice's test population. No attack recall or false-positive
rate can be computed.

| Method | File 00: 1,543,498 test events | File 01: 1,444,695 test events |
| --- | ---: | ---: |
| Fixed forest, 256/1.0 | 26,948 (1.74590%) | 28,880 (1.99904%) |
| Validation-selected forest | 30,574 (1.98083%) | 33,576 (2.32409%) |
| Lifetime pair surprise | 17,581 (1.13904%) | 19,630 (1.35876%) |
| Hierarchical static | 24,451 (1.58413%) | 24,594 (1.70237%) |
| Hierarchical decay | 23,528 (1.52433%) | 23,712 (1.64132%) |

All full-validation alert fractions were at most 1%, yet both learned methods
exceed that budget on both monthly tests. The selected forest creates **3,626
more** alerts than the fixed forest on file 00 and **4,696 more** on file 01.
Thus the better later-validation budget objective does **not** improve future
budget adherence here. The normalized features and parameter search do not
solve distribution shift. Lower count-model burden could also hide attacks;
with no labels it is not evidence that a control is more accurate. These
regressions are retained without changing the grid, features, budget or test
window after measurement.

## Metrics and permissible conclusions

Overall alert fraction is `test_alerts / test_events`. For 2015, unlisted events
remain unlabeled; their separate burden is `unlabeled_alerts / unlabeled_events`.
Exact exercise tuples match `(second,user,source,destination)`, even though the
model sees only user/computer history. Multiple authentication rows can match
one reference tuple, so the report retains both matched row counts and unique
tuple recall. A recall field is null whenever no selected test tuple exists.

For both monthly prefixes every event is unlabeled. Successful authentication
does not establish benign intent. Accuracy, false-positive rate, precision,
AUROC, legitimate-user friction and attack recall are unavailable there. A lower
burden could indicate useful filtering or missed attacks; this experiment alone
cannot distinguish them. Ten clustered known exercise tuples in a previously
inspected 2015 window do not establish broad sensitivity or statistical
superiority. No independent-event confidence interval is offered for this
temporally dependent traffic.

Shared test strata disclose cold users, known users reaching a new computer and
familiar pairs. They measure history coverage and where alerts occur, not
confirmed attack categories. Forest and count scores are research diagnostics;
server identity checks, policy and timed grants remain the authorization path.

## Reproduce and inspect

Use the pinned project environment installed from `backend/requirements.txt`.
The measured environment is recorded in the report; exact reproduction should
match Python, scikit-learn, NumPy and joblib versions. Acquisition is separate
from fitting and refuses to overwrite an existing frozen sample.

```powershell
# Acquire genuine prefixes if not already present; see each acquisition guide.
python scripts/evaluate_lanl.py fetch --output-dir data/lanl/study --max-mib 256 --max-seconds 600 --stop-second 200000
python scripts/evaluate_lanl2014.py fetch --output-dir data/lanl2014 --max-mib 16 --max-seconds 300
python scripts/fetch_lanl_month.py

# Verify protocol mechanics, then freeze before observing candidate results.
.venv/Scripts/python.exe scripts/run_tests.py -s experiments/tests -p test_real_auth_training.py
.venv/Scripts/python.exe scripts/train_real_auth.py freeze
.venv/Scripts/python.exe scripts/train_real_auth.py train

# A single named dataset can also be reproduced without loading other sources.
.venv/Scripts/python.exe scripts/train_real_auth.py train --datasets lanl2014_month01 --output experiments/local-training.json --artifacts data/local-real-auth-models
```

`train` validates the actual compressed input against frozen provenance,
preflights final report/model write locations before the expensive loop,
records an execution commitment, and saves each dataset on completion. Missing
raw inputs fail explicitly. `freeze` rejects incompatible existing protocol
settings. Reusing an output with the same protocol can retain other completed
datasets; per-dataset execution hashes identify their actual implementation.
For a clean replication use a new output and artifact directory and retain
earlier evidence. Original assets under `research/` are never modified.

Scoring batches up to 8,192 distinct within-second vectors; multiplicity
preserves event-level metrics. Each batch carries immutable feature snapshots,
so later history updates cannot alter earlier scores. Reservoir memory and
score histograms are bounded; history dictionaries still grow with distinct
observed accounts/pairs, and the finite source prefix bounds this run's scope.
Compressed inputs are streamed rather than expanded into tracked datasets.

## Saved artifacts and schema

The JSON report uses `schema_version='real-auth-training-v1'`, `synthetic=false`,
`protocol`, `protocol_sha256`, `datasets`, implementation/environment metadata
and an explicit limitations list. Each dataset contains:

| Field | Evidence |
| --- | --- |
| `source`, `scan` | URLs, source bytes/hashes and selected-event population |
| `partitions`, `partition_cutoffs` | Event counts, complete timestamp ranges and canonical selected-stream digests |
| `training` | Actual warmup count, reservoir size, nine dimensions, float64 tensor hash, fitted tree count and model path/hash |
| `training.tuning` | Six complete calibration/selection outcomes, eligibility, objective, chosen parameters, fallback and candidate artifact hashes |
| `methods` | Fixed/tuned forests and three controls, frozen validation thresholds, test workload and eligible sparse tuple recall |
| `test_strata` | Shared lifetime-history coverage and each method's alert counts |
| `implementation_sha256`, `execution_environment` | Actual execution identity retained per dataset |

Every candidate produces a real compressed joblib estimator in ignored local
storage, including candidates that were not selected. The report hashes the
serialized weights and the canonical little-endian float64 training reservoir.
Stream digests hash canonical `(second,user,computer,multiplicity)` rows without
publishing their identifiers. Seeds support repeatability; hashes identify this
specific run rather than promising bitwise equality on different libraries.

For this measured run, the training module's execution SHA-256 is
`9b55f8987e5701416a0453cc7d54718fab47b916896dfbf2051df9568b6ed2fa`.
The report also records an import/CLI dependency manifest captured while the
actual run was in progress, before its first dataset result was saved, and
verified unchanged after all three finished. Its collection timestamp and
semantics are explicit: it is **not** a claimed pre-start dependency commitment.
The report's execution commitment predates all measured candidate outcomes;
the later manifest annotation changes provenance metadata only.

A subsequent compatibility fix handles the sparse-validation cases described
above. It was made **after** measurement and did not retrain the real models.
Before editing, the exact executed source was preserved at ignored local
`data/real-auth-models/real_auth_training.executed.py` and checked against the
execution hash. That local audit snapshot is not distributed as a tracked file.
The report's `execution_source_snapshot` identifies it; actual execution hashes
in `implementation`, per-dataset metadata and the historical dependency manifest
continue to identify the original run.

The current compatibility revision has source SHA-256
`eda7bb6706ce03af32bb6a8e74423da3f2851da340fc9f7405d3427a98aaf4ab`.
Its separate `post_measurement_compatibility_revision` metadata gives the
revision time, reason and before/after canonical hashes of each entire dataset
payload. All three payloads are identical, including trained-weight hashes,
parameters, thresholds, timings and measured metrics. Protocol, feature
definitions and search settings are unchanged. The new source hash is not
represented as the implementation that produced the frozen measurements.

[Scikit-learn's persistence guidance](https://scikit-learn.org/stable/model_persistence.html)
explains that joblib uses executable pickle semantics. Only load a trusted
locally produced artifact whose SHA-256 matches the report, with compatible
software. Checksums identify files; they do not make untrusted pickle safe.
The IAM API serves aggregate JSON only and does not load research estimators.
Weights do not include the live feature-history dictionaries and cannot alone
reconstruct sequential inference: a future inference integration would need
the same source selection, ordered history, feature definitions and threshold,
plus independent validation and a separate policy decision.

## Checks and next evidence

All **19** focused training tests pass. They cover history/recency semantics, bounded deterministic reservoir,
actual estimator round-trip, fixed search/tie/fallback behavior, label exclusion,
future-test independence, group-order/batch invariance, count-control agreement,
split and stratum denominators, source mismatch, protocol freezing and sparse
calibration/selection fallback with clear empty-validation failure. Small
invented fixtures test mechanics; they are never reported as real measurements.

The next research step is a genuinely independent institution or later
untouched labelled period with a frozen operational objective, adjudicated
negative examples, complete telemetry and prospective analyst-cost evaluation.
Until then, neither a tuned forest nor a favorable historic tuple count should
be promoted to a production accuracy claim or an automatic access decision.
