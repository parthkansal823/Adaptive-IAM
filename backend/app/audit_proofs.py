"""Hash-only audit inclusion evidence; never an identity or access authority."""
from __future__ import annotations

import hashlib
import hmac
import json
import re

from fastapi import Depends, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field

from .blockchain import CHAIN_ID, function
from .store import canonical, stamp

ZERO = "0" * 64
MAX_EVENTS = 256
MAX_BUNDLE_BYTES = 16 * 1024
SCHEMA = "audit-inclusion-v1"
ALGORITHM = "sha256-rfc9162-domain-separated-v1"
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
BATCH_ABI = [
    function("AUDIT_BATCH_VERSION", outputs=["bytes32"]),
    function("auditBatchCount", outputs=["uint256"]),
    function("auditBatchHead", outputs=["bytes32"]),
    function("auditBatchEnd", outputs=["uint64"]),
    function("auditBatches", ["uint256"], ["uint64", "uint64", "bytes32", "bytes32", "bytes32"]),
    function("anchorAuditBatch", ["uint64", "uint64", "bytes32", "bytes32", "bytes32"], mutability="nonpayable"),
]


def _hash(value):
    if not isinstance(value, str) or not HASH_PATTERN.fullmatch(value):
        raise ValueError("Expected a lowercase SHA-256 digest")
    return bytes.fromhex(value)


def _integer(value, minimum=1, maximum=2**63-1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("Integer outside the supported range")
    return value


def leaf_hash(sequence, audit_event_hash):
    return hashlib.sha256(b"\x00" + _integer(sequence).to_bytes(8, "big") + _hash(audit_event_hash)).digest()


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(count):
    return 1 << ((count - 1).bit_length() - 1)


def merkle_root(leaves):
    if not 1 <= len(leaves) <= MAX_EVENTS:
        raise ValueError("A batch must contain 1 to 256 events")
    if len(leaves) == 1:
        return leaves[0]
    split = _split(len(leaves))
    return _node(merkle_root(leaves[:split]), merkle_root(leaves[split:]))


def inclusion_path(leaves, index):
    _integer(index, 0, len(leaves)-1)
    if len(leaves) == 1:
        return []
    split = _split(len(leaves))
    if index < split:
        return inclusion_path(leaves[:split], index) + [{"side": "right", "hash": merkle_root(leaves[split:]).hex()}]
    return inclusion_path(leaves[split:], index-split) + [{"side": "left", "hash": merkle_root(leaves[:split]).hex()}]


def _path_sides(count, index):
    if count == 1:
        return []
    split = _split(count)
    if index < split:
        return _path_sides(split, index) + ["right"]
    return _path_sides(count-split, index-split) + ["left"]


def _keys(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError("Unsupported audit proof schema")


def verify_bundle(bundle, expected_root=None):
    """Verify structure and inclusion; a self-supplied root supplies no external trust."""
    _keys(bundle, ("schema_version", "algorithm", "batch", "leaf", "siblings", "trust"))
    if bundle["schema_version"] != SCHEMA or bundle["algorithm"] != ALGORITHM:
        raise ValueError("Unsupported audit proof algorithm or version")
    batch, leaf, path = bundle["batch"], bundle["leaf"], bundle["siblings"]
    _keys(batch, ("id", "start_sequence", "end_sequence", "event_count", "root", "previous_root", "audit_end_hash"))
    _keys(leaf, ("sequence", "audit_event_hash"))
    _keys(bundle["trust"], ("root_origin", "external_anchor_checked"))
    if bundle["trust"] != {"root_origin": "local_sqlite", "external_anchor_checked": False}:
        raise ValueError("A portable bundle cannot assert external anchor verification")
    batch_id = _integer(batch["id"])
    start, end = _integer(batch["start_sequence"]), _integer(batch["end_sequence"])
    count = _integer(batch["event_count"], 1, MAX_EVENTS)
    if end-start+1 != count:
        raise ValueError("Batch range and event count disagree")
    root = _hash(batch["root"])
    _hash(batch["previous_root"])
    _hash(batch["audit_end_hash"])
    if batch_id == 1 and (start != 1 or batch["previous_root"] != ZERO):
        raise ValueError("First batch must begin the audit history")
    if batch_id > 1 and (start < batch_id or batch["previous_root"] == ZERO):
        raise ValueError("Batch metadata cannot follow a contiguous nonempty history")
    sequence = _integer(leaf["sequence"], start, end)
    current = leaf_hash(sequence, leaf["audit_event_hash"])
    if sequence == end and leaf["audit_event_hash"] != batch["audit_end_hash"]:
        raise ValueError("Last leaf does not match the audit end hash")
    if not isinstance(path, list) or len(path) > 8:
        raise ValueError("Inclusion path exceeds the batch depth")
    sides = _path_sides(count, sequence-start)
    if len(path) != len(sides):
        raise ValueError("Inclusion path does not match the tree shape")
    for sibling, expected_side in zip(path, sides):
        _keys(sibling, ("side", "hash"))
        if sibling["side"] != expected_side:
            raise ValueError("Inclusion direction does not match the tree shape")
        other = _hash(sibling["hash"])
        current = _node(other, current) if expected_side == "left" else _node(current, other)
    inclusion_valid = hmac.compare_digest(root, current)
    trusted_root_match = None if expected_root is None else hmac.compare_digest(root, _hash(expected_root))
    return {"schema_version": SCHEMA, "inclusion_valid": inclusion_valid,
            "trusted_root_match": trusted_root_match, "anchor_checked": False,
            "trusted_inclusion": inclusion_valid and trusted_root_match is True,
            "sequence": sequence, "root": batch["root"],
            "limitation": "A proof binds an audit event hash to a root. Obtain the expected root independently; a self-supplied root is not external trust. This does not verify the original event payload, full history, or a live chain."}


def decode_bundle(data):
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError("Audit proof exceeds 16 KiB")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result
    def reject(value):
        raise ValueError("Non-finite JSON value")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Invalid bounded audit proof JSON") from error


def batch_dto(row):
    return {key: row[key] for key in ("id", "start_sequence", "end_sequence", "root", "previous_root", "audit_end_hash")} | {"event_count": row["end_sequence"]-row["start_sequence"]+1}


def verify_snapshot(db):
    """Stream canonical events and batch commitments within the caller's snapshot."""
    batches = iter(db.execute("SELECT * FROM audit_batches ORDER BY id"))
    batch = next(batches, None)
    previous_event = previous_root = ZERO
    batch_number, sealed_end, checked = 0, 0, 0
    leaves = []
    for row in db.execute("SELECT * FROM audit ORDER BY id"):
        checked += 1
        record = {key: row[key] for key in ("id", "timestamp", "event_type", "actor_id", "previous_hash")}
        try:
            record["payload"] = json.loads(row["payload"])
            digest = hashlib.sha256(canonical(record).encode()).hexdigest()
            if row["id"] != checked or row["previous_hash"] != previous_event or not hmac.compare_digest(digest, row["hash"]):
                raise ValueError("Audit chain mismatch")
            _hash(row["hash"])
            if batch is not None:
                if not leaves:
                    if (batch["id"] != batch_number+1 or batch["start_sequence"] != sealed_end+1
                            or batch["previous_root"] != previous_root
                            or not 1 <= batch["end_sequence"]-batch["start_sequence"]+1 <= MAX_EVENTS):
                        raise ValueError("Audit batch history mismatch")
                leaves.append(leaf_hash(row["id"], row["hash"]))
                if row["id"] == batch["end_sequence"]:
                    root = merkle_root(leaves).hex()
                    if root != batch["root"] or row["hash"] != batch["audit_end_hash"]:
                        raise ValueError("Audit batch commitment mismatch")
                    previous_root, sealed_end = root, row["id"]
                    batch_number += 1
                    leaves = []
                    batch = next(batches, None)
            previous_event = row["hash"]
        except (ValueError, TypeError, OverflowError) as error:
            raise ValueError("Local audit or batch integrity verification failed") from error
    if batch is not None:
        raise ValueError("Audit batch extends beyond the retained audit history")
    return {"checked_events": checked, "sealed_end": sealed_end, "batch_count": batch_number, "batch_head": previous_root}


class SealInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_events: int = Field(default=MAX_EVENTS, strict=True, ge=1, le=MAX_EVENTS)


def seal_batch(store, max_events, actor_id):
    _integer(max_events, 1, MAX_EVENTS)
    with store.connection(write=True) as db:
        snapshot = verify_snapshot(db)
        rows = db.execute("SELECT id,hash FROM audit WHERE id>? ORDER BY id LIMIT ?", (snapshot["sealed_end"], max_events)).fetchall()
        if not rows:
            raise HTTPException(409, "No unsealed audit events")
        root = merkle_root([leaf_hash(row["id"], row["hash"]) for row in rows]).hex()
        batch_id = snapshot["batch_count"]+1
        db.execute("INSERT INTO audit_batches VALUES (?,?,?,?,?,?,?)", (batch_id, rows[0]["id"], rows[-1]["id"], root, snapshot["batch_head"], rows[-1]["hash"], stamp()))
        db.execute("INSERT INTO blockchain_outbox (kind,local_id,status,updated_at) VALUES ('audit_batch',?,'pending',?)", (str(batch_id), stamp()))
        # The sealing action belongs to the next prefix, avoiding a circular commitment.
        store.audit(db, "audit_batch_sealed", actor_id, {"batch_id": batch_id, "start_sequence": rows[0]["id"], "end_sequence": rows[-1]["id"], "root": root})
        return batch_dto(db.execute("SELECT * FROM audit_batches WHERE id=?", (batch_id,)).fetchone())


def proof_bundle(store, sequence):
    with store.connection() as db:
        db.execute("BEGIN")
        verify_snapshot(db)
        batch = db.execute("SELECT * FROM audit_batches WHERE start_sequence<=? AND end_sequence>=?", (sequence, sequence)).fetchone()
        if batch is None:
            raise HTTPException(404, "Audit event is absent or not yet sealed")
        rows = db.execute("SELECT id,hash FROM audit WHERE id BETWEEN ? AND ? ORDER BY id", (batch["start_sequence"], batch["end_sequence"])).fetchall()
        index = sequence-batch["start_sequence"]
        leaves = [leaf_hash(row["id"], row["hash"]) for row in rows]
        return {"schema_version": SCHEMA, "algorithm": ALGORITHM, "batch": batch_dto(batch),
                "leaf": {"sequence": sequence, "audit_event_hash": rows[index]["hash"]},
                "siblings": inclusion_path(leaves, index),
                "trust": {"root_origin": "local_sqlite", "external_anchor_checked": False}}


def _contract_batch_matches(values, batch):
    return (len(values) == 5 and int(values[0]) == batch["start_sequence"] and int(values[1]) == batch["end_sequence"]
            and bytes(values[2]).hex() == batch["root"] and bytes(values[3]).hex() == batch["audit_end_hash"]
            and bytes(values[4]).hex() == batch["previous_root"])


def anchor_batch(store, chain, batch_id):
    """Retry a sequential anchor and verify live state rather than trusting its receipt."""
    if not chain.enabled:
        raise HTTPException(503, "Optional audit batch anchoring requires configured Web3")
    with chain.lock:
        try:
            w3, legacy, writer = chain.connect()
            contract = w3.eth.contract(address=legacy.address, abi=BATCH_ABI)
            if contract.functions.AUDIT_BATCH_VERSION().call() != w3.keccak(text="AdaptiveIAM.AuditBatch.v1"):
                raise RuntimeError("Audit batch capability unavailable")
            snapshot_audit_count = legacy.functions.auditCount().call()
            if type(snapshot_audit_count) is not int or snapshot_audit_count < 0:
                raise RuntimeError("Invalid live audit history size")
            with store.connection() as db:
                db.execute("BEGIN")
                snapshot = verify_snapshot(db)
                local_batches = [batch_dto(row) for row in db.execute("SELECT * FROM audit_batches ORDER BY id")]
                target = next((item for item in local_batches if item["id"] == batch_id), None)
                if target is None:
                    raise HTTPException(404, "Audit batch not found")
                event = db.execute("SELECT hash FROM audit WHERE id=?", (snapshot_audit_count,)).fetchone()
                snapshot_audit_head = event["hash"] if event else ZERO
            def live_prefix():
                audit_count = legacy.functions.auditCount().call()
                # A concurrent external writer changing the per-event prefix requires a
                # fresh snapshot/retry, rather than retaining every event in memory.
                if (type(audit_count) is not int or audit_count != snapshot_audit_count
                        or not 0 <= audit_count <= snapshot["checked_events"]
                        or bytes(legacy.functions.auditHead().call()).hex() != snapshot_audit_head):
                    raise RuntimeError("Live audit history mismatch")
                count = contract.functions.auditBatchCount().call()
                if type(count) is not int or not 0 <= count <= len(local_batches):
                    raise RuntimeError("Live audit batch history mismatch")
                for item in local_batches[:count]:
                    if (item["end_sequence"] > audit_count or not _contract_batch_matches(contract.functions.auditBatches(item["id"]).call(), item)
                            or bytes(legacy.functions.auditHashes(item["end_sequence"]).call()).hex() != item["audit_end_hash"]):
                        raise RuntimeError("Live audit batch commitment mismatch")
                expected_root = local_batches[count-1]["root"] if count else ZERO
                expected_end = local_batches[count-1]["end_sequence"] if count else 0
                if (bytes(contract.functions.auditBatchHead().call()).hex() != expected_root
                        or contract.functions.auditBatchEnd().call() != expected_end):
                    raise RuntimeError("Live audit batch head mismatch")
                return count, audit_count
            count, audit_count = live_prefix()
            if batch_id > count+1:
                raise HTTPException(409, "Anchor earlier audit batches first")
            if target["end_sequence"] > audit_count:
                raise HTTPException(409, "Sync the existing per-event audit prefix before anchoring this batch")
            receipt = None
            if batch_id == count+1:
                receipt = chain.transact(w3, contract.functions.anchorAuditBatch(target["start_sequence"], target["end_sequence"], bytes.fromhex(target["root"]), bytes.fromhex(target["audit_end_hash"]), bytes.fromhex(target["previous_root"])), writer, "audit_batch", batch_id)
                # Reconnect also reapplies QBFT freshness/quorum checks after a write.
                w3, legacy, _ = chain.connect()
                contract = w3.eth.contract(address=legacy.address, abi=BATCH_ABI)
                if live_prefix()[0] < batch_id:
                    raise RuntimeError("Transaction receipt did not establish the expected batch")
            chain.update("audit_batch", batch_id, "confirmed")
            return {"batch": target, "status": "anchored", "anchor_checked": True, "chain_id": CHAIN_ID,
                    "contract_address": legacy.address, "receipt": receipt,
                    "limitation": "Live verification against the configured local registry; its writer and validator administration remain trusted."}
        except HTTPException:
            raise
        except Exception:
            chain.update("audit_batch", batch_id, "failed", error="Audit batch capability, integrity or live registry verification unavailable; retry only after diagnosis")
            raise HTTPException(503, "Audit batch capability, integrity or live registry verification unavailable. Legacy registries require an explicit new deployment; existing access policy is unchanged.") from None


def install_audit_proofs(api, authenticated):
    def reviewer(identity=Depends(authenticated)):
        if identity["user"]["role"] != "security_reviewer":
            raise HTTPException(403, "Only a security reviewer can inspect or seal global audit proofs")
        return identity

    def integrity_error():
        return HTTPException(409, "Local audit or batch integrity verification failed")

    @api.get("/api/audit/batches")
    def batches(limit: int = Query(default=50, ge=1, le=100), identity=Depends(reviewer)):
        with api.state.store.connection() as db:
            db.execute("BEGIN")
            try:
                snapshot = verify_snapshot(db)
            except ValueError:
                raise integrity_error() from None
            items = [batch_dto(row) for row in db.execute("SELECT * FROM audit_batches ORDER BY id DESC LIMIT ?", (limit,))]
            return {"items": items, **snapshot, "unsealed_events": snapshot["checked_events"]-snapshot["sealed_end"], "anchor_checked": False, "root_origin": "local_sqlite"}

    @api.post("/api/audit/batches/seal")
    def seal(body: SealInput, identity=Depends(reviewer)):
        try:
            return {"batch": seal_batch(api.state.store, body.max_events, identity["user"]["id"]), "anchor_checked": False, "root_origin": "local_sqlite"}
        except ValueError:
            raise integrity_error() from None

    @api.get("/api/audit/proofs/{sequence}")
    def proof(sequence: int = Path(ge=1, le=2**63-1), identity=Depends(reviewer)):
        try:
            return proof_bundle(api.state.store, sequence)
        except ValueError:
            raise integrity_error() from None

    @api.post("/api/audit/batches/{batch_id}/anchor")
    def anchor(batch_id: int = Path(ge=1, le=2**63-1), identity=Depends(reviewer)):
        return anchor_batch(api.state.store, api.state.blockchain, batch_id)
