# Real enterprise authentication: LANL study

This study uses **real, deidentified enterprise authentication records**, with a separate reference of controlled red-team exercise compromise events. It is an offline novelty experiment, not evidence of production account-takeover accuracy. The generated aggregate report is [experiments/lanl-study.json](../experiments/lanl-study.json).

## Source and permission

Alexander D. Kent's [LANL Comprehensive, Multi-Source Cyber-Security Events (2015)](https://csr.lanl.gov/data/cyber1/) describes 58 consecutive days from LANL's internal corporate network. Authentication records cover Windows hosts and Active Directory. Calendar dates are intentionally undisclosed; the study uses the source's relative seconds. Citation: A. D. Kent, *Comprehensive, Multi-Source Cybersecurity Events*, Los Alamos National Laboratory, 2015, [DOI 10.17021/1179829](https://doi.org/10.17021/1179829).

The source dedicates its copyright and neighboring rights to the public domain. The [Imperial College institutional mirror](https://lanl.ma.ic.ac.uk/data/cyber1/) openly links the original-format authentication and red-team archives, with the same citation and rights waiver. The implementation downloads these public links directly. It does not submit a contact form, use credentials, or bypass access restrictions. This differs from the separately documented RBA dataset: that dataset's creator describes its records as synthesized; LANL's background records come from actual enterprise logs.

Only authentication and the small compromise reference are used. The original research assets under `research/` are unchanged. Acquired records stay under ignored `data/lanl/`; tracked output contains counts, relative times, hashes and metrics, without user or computer identifiers.

## Bounded acquisition and provenance

The initial 8 MiB pilot scanned 1,336,434 source records and reached relative second 13,650. A subsequent sequential capture was capped at **256 MiB compressed** and **600 seconds**, targeting completion of source second 200,000. The download checks the wall-clock deadline before each bounded read; a stalled request can additionally take up to its 30-second socket timeout to fail. It never downloads the 7.6 GB authentication archive in full.

The targeted endpoint was selected after consulting the public red-team example time (151,648). The downloaded complete reference actually begins at second 150,885. This is **label-informed feasibility sampling**, not an externally preregistered, representative or untouched evaluation period. Scoring rules, chronological split fractions and the 1% alert-budget target were fixed before computing the study results; test outcomes do not tune them. Broader time windows, independent institutions and more complete labels are needed before generalization claims.

The capture on 21 October 2026 retained 262,602,752 original compressed bytes and reached relative second 200,020. The final source-second group is excluded wholesale from evaluation because a compressed prefix can end within that group. Whole earlier second groups remain intact. The scan count describes acquired complete lines; partition counts describe evaluated complete time groups, so they can differ. In this capture the discarded source second has no selected human events.

The source gzip is incomplete: **its full-archive checksum/trailer is not verified**. A SHA-256 identifies the exact acquired compressed prefix; it is not proof of full archive integrity or equivalence to a separately acquired copy. Complete preceding text lines are decoded incrementally, and malformed records, oversized lines, gzip corruption and reverse timestamps are rejected. Concatenated gzip members and trailing bytes are explicitly unsupported and rejected. The complete 4,858-byte red-team archive is gzip-verified. The report embeds both hashes, file byte counts, exact URLs, retrieval time, transfer bounds and stop reason, plus finalized evaluator-source hash and Python/platform versions. Relative raw-file names avoid publishing local machine paths.

## Protocol

The selection retains source users matching the deidentified human-account pattern `U[0-9]+@domain`, `LogOn` orientation, and known source and destination computers. Both successful and failed events are retained. Machine accounts, services, other orientations and missing computers are excluded; this selection does not represent all authentication workloads. The source itself excludes failures for users without a successful authentication anywhere in its full dataset, another selection bias.

Missing computers include both `?` and empty fields. After adding explicit empty-field exclusion, a separate streaming check of the exact acquired prefix found zero adjacent-comma pairs across all 2,539,418,347 decompressed bytes, including output-chunk boundaries. An empty computer field would require such a pair. This establishes that the hardening changes no selected records or reported metrics; the report records this proof and the updated evaluator hash.

Source-relative time defines 50% warmup, 25% validation and 25% test windows. Equal-second groups stay in one window. All selected events in a second are scored using only counts from earlier seconds, then update history together. Updating continues prequentially through validation and test, without labels or success/failure outcomes. History never reads the current outcome or future events.

Three transparent baselines are compared:

| Method | Score from earlier seconds |
| --- | --- |
| New user/source | 1 for a previously unseen user and source-computer pair, otherwise 0 |
| New user/destination | 1 for a previously unseen user and destination-computer pair, otherwise 0 |
| Edge frequency surprise | `ln(1 + user event count) - ln(1 + user/source/destination count)` |

Validation score histograms choose a conservative threshold with at most 1% validation alerts, without using the red-team reference. Thresholds include all equal scores; if the highest-score tie alone exceeds the allowance, the method produces no alerts. Test traffic can shift, so the test burden can exceed or fall below the validation budget. No baseline is selected as a winner or retuned after inspecting test results.

These baselines have explicit weaknesses: frequency surprise is zero for an entirely new user, and unlabeled compromise activity can enter the prequential history and become familiar. A high recall on this targeted exercise window would not resolve cold starts, history poisoning or alert drift. Their purpose is to establish a reproducible real-log baseline before introducing more complex models.

Reference matching requires the exact tuple `(relative second, source user@domain, source computer, destination computer)`. A tuple can match several authentication records because the reference omits authentication type, orientation and outcome. The report distinguishes matching authentication rows from distinct matched reference tuples and measures recall over distinct tuples.

Events absent from the reference are **unlabeled**, not verified benign. Reported measurements are overall alert burden, alert burden among unlabeled events, and recall of listed exercise tuples in the selected test subset. No accuracy, precision, false-positive rate or AUROC is justified by these incomplete negative labels. If a local sample contains no exact selected test reference tuple, detection metrics are explicitly ineligible and recall fields are `null`.

## Measured targeted-prefix results

The acquired prefix contains **37,752,359 authentication records**, of which **4,394,776** meet the fixed human-source selection. Warmup contains 2,030,503 selected events, validation 1,478,049 and test 886,224. The complete reference contains 715 distinct exercise tuples; exactly ten match selected test events in this prefix. All ten match one authentication row each here; the adapter separately handles duplicate rows.

| Baseline | Listed exercise tuples recalled | Alerts on 886,214 unlabeled test events | Unlabeled alert burden | Total test alerts |
| --- | ---: | ---: | ---: | ---: |
| New user/source | 3 / 10 | 469 | 0.0529% | 472 |
| New user/destination | 0 / 10 | 0 | 0% | 0 |
| Edge frequency surprise | 8 / 10 | 7,484 | 0.8445% | 7,492 |

New-destination novelty's highest-score validation tie exceeded the 1% budget, so the conservative tie rule disabled all alerts for that baseline. Frequency surprise's validation burden was 0.9994% at threshold 5.9402073011, and overall test burden was 0.8454%. This exposes a limitation: binary destination novelty cannot meet this budget while retaining all tied positive scores. The experiment reports this outcome without adjusting the budget after seeing test results.

Eight of ten exercise tuples recalled is a small descriptive result on a deliberately targeted historical window. It is not 80% production attack-detection accuracy. The ten tuples may share users, hosts or exercise procedures and should not be treated as independent samples. No positive/negative population accuracy or deployment benefit is inferred.

## Reproduce

From the repository root, using an installed Python 3.11+ interpreter; no additional dependencies are required:

```powershell
python scripts/evaluate_lanl.py fetch --output-dir data/lanl/study --max-mib 256 --max-seconds 600 --stop-second 200000
python scripts/evaluate_lanl.py evaluate --auth data/lanl/study/auth.txt.gz.prefix --redteam data/lanl/study/redteam.txt.gz --prefix --provenance data/lanl/study/provenance.json --output experiments/lanl-study.json
python -m unittest scripts.tests.test_lanl -v
```

The same commands reproduce the method, while network throughput or source changes may produce a different bounded prefix; compare embedded hashes before claiming byte-identical replication. The evaluator also accepts complete locally acquired `.gz` or text files: omit `--prefix` for complete inputs. Complete gzip input is trailer-verified. Plain text does not receive a gzip-integrity claim. The evaluator is offline; it does not fetch additional data.

These logged observables have no authority in the running IAM service. The study neither validates live device telemetry nor changes authorization, reviewer eligibility, grants or credentials. Controlled exercise compromises are useful labeled examples, but do not establish detection of every real attack or independent institutional performance.
