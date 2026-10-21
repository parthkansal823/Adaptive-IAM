# Audit batches and portable inclusion evidence

Adaptive IAM can seal up to 256 consecutive local audit events into a Merkle root, export a small proof containing only hashes and sequence numbers, and optionally anchor that root in its configured EVM registry. A verifier can check inclusion without receiving actor names, event payloads, requests, credentials or tokens. This is an evidence feature; it creates no login, vote, grant or access permission.

The construction uses the SHA-256 leaf/internal-node domain separation and unbalanced binary tree shape described in [RFC 9162 section 2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1). It is an established algorithm with a project-specific leaf encoding, not a new cryptographic primitive or a Certificate Transparency implementation.

## Commitment format

For each event, `event_hash` is the existing 32-byte SHA-256 hash of its canonical audit record. The leaf input is its positive audit sequence encoded as eight big-endian bytes followed by `event_hash`:

```text
leaf = SHA256(0x00 || uint64_be(sequence) || event_hash)
node = SHA256(0x01 || left_hash || right_hash)
```

A one-event tree is its leaf hash. For larger trees, split at the largest power of two strictly below the number of leaves and recursively hash both sides. There is no duplicated padding. A 256-event batch needs at most eight sibling hashes. Sequences are currently limited to SQLite's positive signed 64-bit range; Solidity accepts the same values as `uint64`. The isolated QBFT signer also requires JSON sequence integers to be JavaScript-safe (at most `2^53-1`), rejecting larger values rather than rounding them. This narrower operational bound requires a separately reviewed decimal-string protocol before very large sequence values can be used through that signer.

`audit_batches` records `id`, `start_sequence`, `end_sequence`, `root`, `previous_root`, `audit_end_hash` and `created_at`. The first batch starts at sequence 1 with a zero previous root; every subsequent batch follows the previous range. Application update/delete triggers prevent accidental replacement. Each root is recomputed from the original event hashes when history is verified. The previous-root link provides ordered checkpoint metadata; the tree root itself commits to event leaves, and does not separately hash the batch metadata.

Sealing runs under SQLite `BEGIN IMMEDIATE`. It streams and verifies the complete canonical event chain and every earlier batch in the same database snapshot before inserting a new batch and an `audit_batch` outbox entry. This serializes concurrent sealers and rejects gaps, overlaps, rewritten events or mismatching roots. The `audit_batch_sealed` audit event is appended after the committed range, so the root does not depend on its own sealing action. Subsequent batches can include earlier sealing events. Proof export verifies the complete retained history in a read snapshot before returning evidence.

Verification currently scans all retained audit events; it is not a constant-time database operation or a pruning implementation. Batches bound proof size and tree working memory. There is no performance benchmark or throughput claim for this extension.

## API and authorization

All four routes require an authenticated console session whose current server-owned role is `security_reviewer`. An ordinary audit reader or resource owner cannot export proofs for the global ledger. Existing role-filtered `/api/audit` behavior remains in effect.

| Route | Request / result |
| --- | --- |
| `GET /api/audit/batches?limit=50` | Latest batches, verified event count, sealed end, head and unsealed count; limit 1–100. `anchor_checked:false` means local evidence only. |
| `POST /api/audit/batches/seal` | JSON `{"max_events":256}`; integer 1–256, default 256; extra fields rejected. Returns the new `batch` and local trust context. |
| `GET /api/audit/proofs/{sequence}` | Hash-only `audit-inclusion-v1` bundle for a sealed event. |
| `POST /api/audit/batches/{batch_id}/anchor` | Explicitly tries/retries anchoring the next batch, or verifies an existing anchor. A successful response includes `anchor_checked:true`, live chain ID/address and optional receipt. |

Unauthenticated requests return 401, other roles 403, malformed bounds 422, and missing/unsealed evidence 404. Local history corruption returns 409 for local reads/sealing. Anchoring returns 409 when an earlier batch or the existing per-event audit prefix must be synchronized first; disabled Web3, legacy registry capability, RPC failure or failed live verification return 503. Provider exception details and event payloads are not returned.

A bundle has exactly these fields:

```json
{
  "schema_version": "audit-inclusion-v1",
  "algorithm": "sha256-rfc9162-domain-separated-v1",
  "batch": {
    "id": 1,
    "start_sequence": 1,
    "end_sequence": 1,
    "event_count": 1,
    "root": "<64 lowercase hexadecimal characters>",
    "previous_root": "<64 lowercase hexadecimal characters>",
    "audit_end_hash": "<64 lowercase hexadecimal characters>"
  },
  "leaf": {
    "sequence": 1,
    "audit_event_hash": "<64 lowercase hexadecimal characters>"
  },
  "siblings": [],
  "trust": {
    "root_origin": "local_sqlite",
    "external_anchor_checked": false
  }
}
```

This is a schema illustration; replace placeholders with an actual API export. Siblings are ordered from the leaf toward the root as `{"side":"left"|"right","hash":"..."}`. Their directions and count must match the tree shape inferred from the sequence/range; supplying arbitrary direction bits cannot change that shape. Unknown members, duplicate JSON keys, noncanonical hashes, invalid ranges and excessive paths are rejected by the offline verifier.

## Offline verification and external trust

Save the authenticated proof response to `proof.json`. Run from the repository with the backend dependencies installed:

```powershell
.venv/Scripts/python.exe scripts/verify_audit_bundle.py proof.json
.venv/Scripts/python.exe scripts/verify_audit_bundle.py proof.json --expected-root <independently-obtained-64-character-root>
```

The CLI reads at most 16 KiB and makes no network request. It reports these separate facts:

- `inclusion_valid`: the leaf and siblings reconstruct the supplied root.
- `trusted_root_match`: `null` without an expected root, otherwise whether the expected root matches.
- `trusted_inclusion`: inclusion is valid and the independently supplied expected root matches.
- `anchor_checked`: always `false` for this offline command.

Exit 0 means inclusion verified and any supplied expected root matched. Without `--expected-root`, a successful exit does **not** establish external trust. Exit 1 covers malformed evidence, failed inclusion or an expected-root mismatch. Obtain the expected root through a separately trusted channel or a trusted live reader of the intended chain ID and registry address. Copying `batch.root` from the same untrusted bundle into `--expected-root` does not create independence. A fabricated history and its fabricated root can form a perfectly valid self-consistent proof.

The bundle proves inclusion of an event **hash**. It does not prove the truth of the original event, reveal/verify its payload, or independently prove the complete previous-root history. A party with the original canonical event can separately recompute its event hash. Bundle metadata is fully checked against the live registry only by the authenticated anchor operation; offline root comparison alone does not authenticate every batch metadata field.

## Optional EVM anchoring and retry semantics

The registry exposes `AUDIT_BATCH_VERSION = keccak256("AdaptiveIAM.AuditBatch.v1")`, `auditBatchCount`, `auditBatchHead`, `auditBatchEnd`, `auditBatches(id)` and writer-only `anchorAuditBatch(start,end,root,auditEndHash,previousRoot)`. It enforces contiguous ranges, no more than 256 events, a nonzero root and the previous batch root. The batch's ending event must already exist in the original per-event registry with the same event hash. `verifyAuditBatchInclusion(batchId,sequence,eventHash,path)` verifies the same custom leaf and tree shape on-chain without direction flags.

Synchronize `/api/blockchain/sync` before anchoring a newly sealed prefix. Anchor batches in order. The backend verifies the complete local history, the live original audit head, every retained live batch tuple and every corresponding original end hash. It uses the existing signer/transaction machinery under the chain lock, then reconnects and verifies live contract state after writing. A confirmed receipt or persisted outbox entry alone never establishes `anchored`. Existing matching anchors are idempotently verified rather than resent. Failed capability, integrity or live checks persist a generic retryable failure; retry the explicit anchor endpoint after diagnosis. The ordinary per-event/grant sync does not automatically dispatch batch entries.

Existing deployed registries need an explicitly reviewed new deployment to support the added capability. There is no automatic migration, chain reset, grant remirroring or silent fallback that weakens access checks. Existing registry/version checks and per-event/grant APIs remain in place. The isolated QBFT signer accepts only its bounded `audit_batch` action; backend live confirmation still requires the configured fresh validator quorum.

Per-event anchoring continues. This implementation does not replace it, reduce its transaction count, or claim gas savings. A later root-only design would require a separately reviewed grant/audit authority migration.

## Threat model, storage and evidence limits

The database owner can remove triggers and rewrite local tables. An independently retained expected root or trusted live anchor is needed to detect such a rewrite externally. Hashes and sequence numbers can still reveal activity volume, correlation and guesses about low-entropy events; proof export remains restricted. No raw events or personal identifiers are added to the new contract batch records.

Ganache's writer is a public development account. The four-validator Besu network and signer are controlled by one host administrator, so they do not establish independently operated Byzantine trust. A compromised host/reader, stolen writer authority, reconstructed chain or stale exported root remains a trust boundary. Fresh live verification detects RPC failure and mismatching retained history; it cannot turn the host into a tamper-proof service or recover a deleted external anchor.

The [offline backup tool](BACKUP.md) captures all SQLite tables, including batches, outbox state and triggers. It does not restore chain state. After a restore, diagnose and compare live registry history before retrying anchors; a locally valid snapshot can be older than an external checkpoint. Never treat the restored outbox's `confirmed` status as live confirmation.

Focused tests cover domain separation, all positions in balanced/unbalanced trees through 256 leaves, strict bounded parsing, expected-root trust, simultaneous sealing, append-only enforcement, mutated audit/batch rejection, role restrictions, hash-only export, unsupported capability and forged-receipt/RPC/live-prefix failures. The isolated live-Web3 verifier additionally exercises the authenticated HTTP route against a fresh temporary EVM registry and checks Python and Solidity proof agreement. These are local correctness/security tests, not production deployment evidence.
