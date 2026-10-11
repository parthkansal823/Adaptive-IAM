"""Blind export and strict human annotation reconciliation; no invented labels.

This validates annotator attestations and complete labels, not the identity or
truthfulness of a human. Independently supervise collection before publication.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LABELS = {"legitimate", "suspicious", "uncertain"}


def catalog(path):
    packet = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = packet["cases"]
    ids = [case["id"] for case in cases]
    if not cases or len(ids) != len(set(ids)):
        raise ValueError("Catalog must have nonempty unique case IDs")
    return cases


def digest(cases):
    blind = [{k: case[k] for k in ("id", "language", "semantic_group", "text")} for case in cases]
    return hashlib.sha256(json.dumps(blind, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def blind_export(cases):
    return {"schema_version": 1, "catalog_sha256": digest(cases), "independent_labels_collected": False,
            "instruction": "At least two named human annotators independently label every case without seeing predictions, author expectations or each other's labels. Judge text intent; these are not observed attack outcomes. Preserve disagreements for a third named human adjudicator.",
            "labels": sorted(LABELS), "cases": [{k: c[k] for k in ("id", "language", "semantic_group", "text")} for c in cases]}


def person(packet, key):
    row = packet.get(key, {})
    identifier, name = row.get("id", ""), row.get("name", "")
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{3,64}", identifier):
        raise ValueError(f"{key} requires a stable 3-64 character ID")
    if not isinstance(name, str) or len(name.strip()) < 3 or name.strip().lower() in {"unknown", "anonymous", "test", "placeholder", "chatgpt", "codex", "llm", "ai"}:
        raise ValueError(f"{key} requires the actual named human, retained in the private input file")
    if row.get("method") != "human" or row.get("independence_attested") is not True:
        raise ValueError("Explicit human method and independence attestation required; generated annotations are prohibited")
    return identifier, name.strip()


def kappa(a, b):
    observed = sum(x == y for x, y in zip(a, b))/len(a)
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[label]*cb[label] for label in LABELS)/len(a)**2
    return {"agreement": observed, "cohen_kappa": (observed-expected)/(1-expected) if expected < 1 else None,
            "kappa_undefined": expected == 1}


def reconcile(cases, packets, adjudication=None):
    ids = [case["id"] for case in cases]
    checksum = digest(cases)
    if len(packets) < 2:
        raise ValueError("At least two independently collected human annotation files required")
    collected, names = {}, set()
    for packet in packets:
        identifier, name = person(packet, "annotator")
        if identifier in collected or name.casefold() in names:
            raise ValueError("Annotators must be distinct named humans with distinct IDs")
        names.add(name.casefold())
        if packet.get("catalog_sha256") != checksum:
            raise ValueError("Annotation catalog digest does not match the frozen blind catalog")
        rows = packet.get("cases", [])
        labels = {}
        for row in rows:
            cid, label, reason = row.get("case_id"), row.get("label"), row.get("rationale", "")
            if cid in labels or cid not in ids or label not in LABELS or not isinstance(reason, str) or len(reason.strip()) < 10:
                raise ValueError("Every unique catalog case requires a valid label and substantive rationale")
            labels[cid] = label
        if set(labels) != set(ids):
            raise ValueError("Partial or extra annotation sets are rejected")
        collected[identifier] = labels
    disagreement = [cid for cid in ids if len({rows[cid] for rows in collected.values()}) > 1]
    resolved, adjudicator_id = {}, None
    if disagreement:
        if adjudication is None:
            raise ValueError(f"{len(disagreement)} disagreements require separate human adjudication")
        adjudicator_id, adjudicator_name = person(adjudication, "adjudicator")
        if adjudicator_id in collected or adjudicator_name.casefold() in names:
            raise ValueError("Adjudicator must be a third distinct human")
        if adjudication.get("catalog_sha256") != checksum:
            raise ValueError("Adjudication catalog digest mismatch")
        for row in adjudication.get("cases", []):
            cid, label, reason = row.get("case_id"), row.get("label"), row.get("rationale", "")
            if cid not in disagreement or cid in resolved or label not in LABELS or not isinstance(reason, str) or len(reason.strip()) < 10:
                raise ValueError("Adjudication must resolve each disagreement once with a rationale")
            resolved[cid] = label
        if set(resolved) != set(disagreement):
            raise ValueError("Partial adjudication is rejected")
    elif adjudication is not None:
        raise ValueError("No disagreements exist; unnecessary adjudication is rejected")
    gold = {cid: resolved.get(cid, next(iter(collected.values()))[cid]) for cid in ids}
    pairs = []
    for a, b in itertools.combinations(collected, 2):
        pairs.append({"annotator_ids": [a, b], **kappa([collected[a][cid] for cid in ids], [collected[b][cid] for cid in ids])})
    return {"catalog_sha256": checksum, "cases": [{"case_id": cid, "label": gold[cid]} for cid in ids],
            "annotation": {"named_human_attestations": len(collected), "identity_and_independence_externally_verified": False,
                           "annotator_ids": list(collected), "adjudicator_id": adjudicator_id,
                           "unanimous_agreement_rate": (len(ids)-len(disagreement))/len(ids), "disagreements": len(disagreement), "pairwise_agreement": pairs},
            "limitation": "Tool validates completeness and attestations; it cannot establish human identity, independence or correctness. Text-intent judgments are not attack labels or authorization votes."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["export", "reconcile"])
    parser.add_argument("--catalog", type=Path, default=ROOT/"experiments/multilingual_cases.json")
    parser.add_argument("--annotations", type=Path, nargs="*", default=[])
    parser.add_argument("--adjudication", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = catalog(args.catalog)
    result = blind_export(cases) if args.command == "export" else reconcile(cases,
        [json.loads(path.read_text(encoding="utf-8")) for path in args.annotations],
        json.loads(args.adjudication.read_text(encoding="utf-8")) if args.adjudication else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "cases": len(result["cases"]), "mode": args.command}))


if __name__ == "__main__":
    main()
