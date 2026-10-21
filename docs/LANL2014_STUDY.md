# Additional observed authentication dataset: LANL 2014 release

This offline study adds a second genuinely observed authentication release. It
measures alert workload and novelty; it cannot measure attack detection because
the source provides no attack labels. Runtime IAM policy is unchanged.

## Source and acquisition

The primary [LANL dataset description](https://csr.lanl.gov/data/auth/) describes
708,304,516 successful user-to-computer authentications across nine continuous
months, anonymized as `time,user,computer`. The actual collection dates are not
disclosed. Some centralized computers and associated events were removed. The
release DOI is [10.11578/1160076](https://doi.org/10.11578/1160076), with LANL's
waiver of copyright and neighboring rights. The public
[Imperial institutional mirror](https://lanl.ma.ic.ac.uk/data/auth/) openly links
the compressed monthly files and their full-file checksums. The acquisition did
not submit contact forms, credentials or email addresses.

Before downloading or measuring outcomes, this project fixed a practical
**16 MiB** compressed cap on the sequential prefix of the first monthly file,
`lanl-auth-dataset-1-00.bz2`, and a 300-second transfer deadline. The hard command
limit is 128 MiB. No label-dependent or score-dependent window search took place.
The 16 MiB sample contains **4,909,753** complete source records from relative
seconds **1–136,526**. The final source timestamp is potentially incomplete, so
all **55** records at that timestamp are discarded, leaving **4,909,698** events.

The frozen compressed prefix SHA-256 is
`961ed2e81f75e58920c85299684e61dd1d85b367345954038ab672d0c6dd81f3`.
This is a prefix checksum, not the mirror's full-file checksum. The final bzip2
CRC/trailer and full-archive checksum have **not** been verified; available block
checksums are still enforced by the decoder. Raw anonymized identifiers stay in
ignored `data/lanl2014/`; tracked artifacts contain aggregates and provenance.

## Fixed protocol

The evaluator divides elapsed source time into 50% warmup, 25% validation and
25% held-out test. Entire equal-second groups belong to one partition and see
the same history: every row in a group is scored before any row in that group
updates counts. All prior rows update history, independently of alerts. This
is online adaptation without using future events or inferred attack labels.

Two transparent baselines are measured:

- `new_user_computer`: one when the user-computer pair has never appeared.
- `user_computer_surprise`: `log(1 + prior_user_count) − log(1 + prior_pair_count)`,
  rounded to six decimals before calibration and decisions.

Each method selects a conservative threshold using only the validation score
histogram and a 1% maximum alert budget. Tied score groups are never split or
randomized. If the highest-score tie exceeds the allowance, the threshold is
null and the method emits no alerts. Thresholds remain frozen throughout test;
test counts can drift away from the validation allowance.

The tracked [baseline report](../experiments/lanl2014-study.json) includes
partition event counts, cold-start frequencies, source checksums, evaluator
checksum, Python/platform metadata, thresholds and measured workload. The
separate [model comparison](../experiments/real-auth-model-study.json) compares
the shared hierarchical candidates across both observed releases; its protocol
and limitations govern those additional model results.

## Measured baseline results, 21 October 2026

| Partition | Events | Relative seconds |
| --- | ---: | --- |
| Warmup | 2,589,367 | 1–68,263 |
| Validation | 776,833 | 68,264–102,394 |
| Held-out test | 1,543,498 | 102,395–136,525 |

| Method | Validation alert fraction | Test alerts | Test alert fraction |
| --- | ---: | ---: | ---: |
| New user-computer pair | 0.07788% | 8,006 | 0.51869% |
| User-computer surprise | 0.99996% | 17,596 | 1.14001% |

The surprise threshold is 5.309411. Its held-out workload exceeds the 1%
validation allowance, demonstrating that a calibrated budget does not guarantee
a future workload cap. The new-pair method uses threshold 1: it cannot fill an
arbitrary alert budget because its two-valued scores have large ties.

In test, 492 events (0.03188%) involve a user with no prior observed event;
7,514 events (0.48682%) involve a new pair for an already observed user. These
counts describe history coverage, not attacks or erroneous access decisions.

## Interpretation limits

Successful authentication does not prove benign intent. Every event is
unlabeled with respect to maliciousness. Accuracy, false-positive rate,
precision, attack recall and legitimate-user friction are unavailable and must
not be inferred from the alert fraction. A low workload can include missed
attacks; a new pair can be routine authorized work.

This is another historic release from **the same institution**, with unknown
cohort/time overlap with the 2015 release. It is not independent organization
validation, an attack-detection replication, or contemporary production evidence.
The approximately 1.58-day early-file prefix does not represent all nine months.
Untrusted prior events can also contaminate the adapting count history. Neither
the baselines nor candidate models can grant or revoke access.

## Reproduce

Only the Python standard library is required. Download and evaluate separately:

```powershell
python scripts/evaluate_lanl2014.py fetch --max-mib 16 --max-seconds 300
python scripts/evaluate_lanl2014.py evaluate --auth data/lanl2014/lanl-auth-dataset-1-00.bz2.prefix --prefix --provenance data/lanl2014/provenance.json
python scripts/run_tests.py -s scripts/tests -p test_lanl2014.py
```

Fetching refuses to replace an existing frozen sample. The evaluator rejects
out-of-order or malformed rows, bounds decompression, excludes incomplete tail
groups, rejects corrupt available bzip2 blocks and verifies the supplied prefix
provenance hash. The small invented test fixtures establish protocol mechanics;
they are not the reported observed-data measurements.
