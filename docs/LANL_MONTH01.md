# Additional real authentication slice: monthly file 01

This acquisition adds **4,970,690 usable observed authentication events** from
the second published monthly file of the LANL 2014 release. It expands the time
coverage available for offline training and testing. It is another time slice
from the **same institution and release**; it is not a third independent dataset
or an independently labelled deployment.

## Source, license and schema

The [primary LANL description](https://csr.lanl.gov/data/auth/) documents an
anonymized enterprise dataset of successful user-to-computer authentications,
with DOI [10.11578/1160076](https://doi.org/10.11578/1160076). The source provides
`time,user,computer` rows: time is a relative integer second and the identifiers
are anonymized. The actual collection dates are deliberately undisclosed. Some
centralized computers and their associated events were removed. LANL waived
copyright and related or neighboring rights for this dataset.

The public [Imperial institutional mirror](https://lanl.ma.ic.ac.uk/data/auth/)
links `lanl-auth-dataset-1-01.bz2` directly, alongside a
[full-archive checksum list](https://lanl.ma.ic.ac.uk/data/auth/checksums.txt).
The helper uses that openly linked file. No source contact form, email address,
credentials or access gate was submitted.

The source describes the numbered files as 30-day files. This study preserves
the **observed release-relative offsets** and does not infer calendar dates or
assume that a file number defines an exact calendar month.

## Fixed acquisition protocol

Before downloading or inspecting this slice, the project fixed the next file
index (`01`) and the first **16 MiB compressed prefix**. No model score, attack
label or measured outcome was used to select its window. This is a practical
resource-bound choice, not an externally preregistered or representative sample.

`scripts/fetch_lanl_month.py` uses a sequential HTTP 200 response with identity
encoding. It caps compressed input at 16 MiB and decompressed output at 512 MiB.
It checks a 300-second transfer deadline before every read; a pending read has
at most a ten-second socket timeout. Local parsing occurs after the transfer
and is bounded separately by the decompressed byte limit. On this run the
compressed byte cap ended the transfer, and transfer plus validation took
**16.547 seconds**.

The parser validates the three-field schema and nondecreasing timestamps. A
partial archive can end midway through a timestamp group. Therefore **every
row at its final observed timestamp is excluded**, even when the available
last line is syntactically complete. Only earlier complete timestamp groups
are available to the trained evaluation.

All final output and temporary paths are checked before network access; all
temporary files are reserved before downloading. Existing outputs are refused.
Publication uses a same-filesystem hard link that fails if the destination
already exists. Errors remove only temporary files reserved by this invocation.
Frozen evidence is never silently overwritten.

## Measured acquisition

The frozen aggregate artifact is
[`experiments/lanl2014-month01-data.json`](../experiments/lanl2014-month01-data.json).
Raw records and their anonymized identifiers remain in ignored
`data/lanl2014-month01/`.

| Quantity | Measured value |
| --- | ---: |
| Compressed prefix bytes | 16,777,216 |
| Complete source records decoded | 4,970,711 |
| Source first relative second | 2,419,201 |
| Source last relative second | 2,550,400 |
| Entire final timestamp group excluded | 21 records |
| Usable events | 4,970,690 |
| Usable relative seconds | 2,419,201-2,550,399 |
| Server-reported full file bytes | 186,894,953 |

The prefix SHA-256 is:

```text
6ed7d219f1b7d385d76d6aa0daeb2cfa908e1b5745cab9a87c22de4a879b113f
```

The mirror lists the following SHA-256 for the **entire** source archive:

```text
3329d782da62084238c4e349754e7feb77768768d6bd05c18c2b7407f5afddc3
```

These hashes apply to different byte sequences. The full-file SHA-256 and final
bzip2 CRC/trailer were **not verified**, because only the prefix was acquired.
Available bzip2 block checksums remain enforced by the decoder; prefix mode
does not waive a detected block corruption.

The previously frozen file `00` prefix covers relative seconds **1-136,526**,
with its last group excluded from use. The new file `01` prefix starts at
**2,419,201**. Thus these acquired windows do not overlap in the release's
relative time coordinate. This does not establish independent users, devices,
organizations, or collection-date independence from other LANL releases.

## Training interpretation

The acquisition artifact describes data availability and provenance, not model
quality. The [learned-model study](REAL_AUTH_TRAINING.md) consumes this sample
alongside the existing LANL samples and creates its own chronological training,
validation and test partitions. Its fitted-model measurements are frozen in
[`experiments/real-auth-training.json`](../experiments/real-auth-training.json).
Scores for an equal-second group must be computed from prior groups
before any event in that group updates the history. Hyperparameters, fitting
and thresholds must not use held-out outcomes.

This successful-only source supplies **no attack labels**. Successful login is
not proof of legitimate intent, so even training data may contain undisclosed
malicious activity. Alert fraction can measure analyst workload. It cannot be
renamed false-positive rate, accuracy, precision, attack recall or legitimate
user friction. A lower alert fraction is not sufficient evidence that a model
detects attacks better. Runtime server authorization is unchanged.

## Reproduce and validate

From the repository root, use Python with the project's dependencies installed.
Use a new ignored directory so frozen acquisition evidence remains intact:

```powershell
.venv/Scripts/python.exe scripts/fetch_lanl_month.py --output-dir data/lanl2014-month01-reproduction --report data/lanl2014-month01-reproduction/acquisition-report.json
.venv/Scripts/python.exe scripts/run_tests.py -s scripts/tests -p test_lanl_month.py
```

The first command uses the same fixed 16 MiB and 300-second settings. It prints
only aggregate counts. Both commands work in a shell with the equivalent Python
path on other operating systems. Repeating acquisition into an existing output
fails intentionally; choose a fresh directory. The frozen report also records
the helper and shared parser source hashes, acquisition URL, limits, retrieval
time, tail treatment and explicit integrity limitations.

Seven invented-fixture checks cover relative-offset preservation, full-tail
exclusion, malformed/nonchronological input, prefix hashes and aggregate-only
exports, immutable output checks, writable-output preflight, bounded settings
and owned-temporary cleanup. These fixtures verify protocol mechanics; they
are not additional real-world performance measurements.
