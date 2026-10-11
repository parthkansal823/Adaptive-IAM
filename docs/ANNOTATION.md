# Independent language annotation protocol

The pipeline is ready; **no independently collected human annotations are currently present**. The checked-in 18 English/Hindi/Hinglish cases have author expectations and six shared semantic groups. They are useful diagnostics, not an independent attack benchmark. Every assessment remains advisory and cannot create a grant or vote.

## Freeze and blind the input

Run `python scripts/annotation_eval.py export --output experiments/multilingual-blind.json`. The export excludes author expectations and model predictions, includes a digest of case IDs/text/language/groups, and remains unchanged throughout collection. Enlarge or replace the catalog before a new study, then export a new digest; do not modify it after annotators begin. A digest binds labels to texts, not to human identity.

Choose at least two distinct human annotators with relevant language knowledge. Each independently reads every case, without seeing model results, author expectations or the other person's labels. Label the stated intent as `legitimate`, `suspicious` or `uncertain`; record a substantive rationale. This judgment does not establish whether an account was actually compromised. Collection supervision, consent, compensation and identity verification happen outside the tool. Generated model labels must not be submitted as human evidence.

Keep named input files in ignored `experiments/output/`, rather than publishing annotator names. Each file has this JSON structure, with every frozen case included once:

```json
{
  "catalog_sha256": "copy the frozen export digest",
  "annotator": {
    "id": "stable-pseudonym",
    "name": "actual human name in private input",
    "method": "human",
    "independence_attested": true
  },
  "cases": [
    {"case_id": "en_business", "label": "legitimate", "rationale": "The request states a bounded business purpose and requires owner approval."}
  ]
}
```

The snippet illustrates the schema, **not a completed annotation file**. A one-row submission fails completeness checks. Store signed collection records separately; an editable JSON attestation cannot prove identity or independence.

## Reconcile before evaluating

```sh
python scripts/annotation_eval.py reconcile --annotations experiments/output/person-one.json experiments/output/person-two.json --output experiments/output/reconciled.json
```

The validator requires distinct named human attestations, exact digest, valid labels, substantive rationales and complete unique case coverage. It rejects declared model annotations, partial labels and duplicate annotators. It reports unanimous agreement and pairwise Cohen's kappa over all three categories. Kappa is undefined when expected agreement equals one and is recorded as `null`; high agreement alone does not establish label validity. Agreement methodology and interpretive limitations are discussed by [Artstein and Poesio (2008)](https://aclanthology.org/J08-4004/).

Every disagreement requires a third distinct human adjudicator. Supply `--adjudication experiments/output/adjudication.json`. This file uses the same digest, an `adjudicator` object with the same person fields, and `cases` containing exactly the disputed IDs, final labels and rationales. Partial resolution fails. `uncertain` is a valid adjudicated outcome; it must not be silently assigned to a convenient class.

## Run the frozen runtime

```sh
python experiments/multilingual.py --annotations experiments/output/person-one.json experiments/output/person-two.json --adjudication experiments/output/adjudication.json --output experiments/output/independent-language-results.json
```

Omit `--adjudication` if labels agree completely. Use the isolated analysis Docker profile documented in [experiments](../experiments/README.md), with the input paths visible to that container. The evaluator revalidates original submissions, reports binary classifier decisions separately from runtime flags/abstentions, retains abstentions in definite-reference agreement denominators, and reports per-language warm CPU latency. No model or threshold is selected from these results. No BERT score is claimed without an actually configured local labeled model.

Run `python experiments/multilingual.py` without annotation inputs to reproduce the existing **author diagnostic** report. That mode explicitly records independent human labels as pending; artificial unit-test annotations are never used as measured research data.
