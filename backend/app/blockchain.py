"""Local Ethereum adapter and retryable outbox; configured outages deny access."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException

from .store import stamp

CHAIN_ID = 31337
ZERO = "0"*64


def function(name, inputs=(), outputs=(), mutability="view"):
    return {"type": "function", "name": name, "stateMutability": mutability, "inputs": [{"name": str(i), "type": t} for i, t in enumerate(inputs)], "outputs": [{"name": str(i), "type": t} for i, t in enumerate(outputs)]}


ABI = [function("REGISTRY_VERSION", outputs=["bytes32"]), function("writer", outputs=["address"]), function("auditCount", outputs=["uint256"]), function("auditHead", outputs=["bytes32"]), function("auditHashes", ["uint256"], ["bytes32"]), function("grants", ["bytes32"], ["bytes32", "bytes32", "uint64", "bool", "bool"]), function("hasAccess", ["bytes32", "bytes32", "bytes32"], ["bool"]), function("anchorAudit", ["bytes32", "bytes32"], mutability="nonpayable"), function("recordGrant", ["bytes32", "bytes32", "bytes32", "uint64"], mutability="nonpayable"), function("revokeGrant", ["bytes32"], mutability="nonpayable")]


def identity_hash(value: str):
    return hashlib.sha256(value.encode()).digest()


def permitted_rpc(value: str):
    try:
        parsed = urlsplit(value)
        _ = parsed.port
        return (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1", "chain"}
                and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
                and parsed.path in {"", "/"})
    except ValueError:
        return False


class BlockchainMirror:
    def __init__(self, store, data_dir: Path, rpc_url=None, contract_address=None):
        self.store, self.data_dir = store, data_dir
        self.rpc_url = os.getenv("IAM_WEB3_RPC_URL", "") if rpc_url is None else rpc_url
        self.address = os.getenv("IAM_WEB3_CONTRACT_ADDRESS", "") if contract_address is None else contract_address
        self.enabled = bool(self.rpc_url)
        self.configuration_error = None if not self.enabled or permitted_rpc(self.rpc_url) else "Only loopback or internal Docker chain HTTP RPC is allowed"
        self.lock = threading.RLock()
        self.w3 = None

    def connect(self):
        if not self.enabled or self.configuration_error:
            raise RuntimeError(self.configuration_error or "Web3 is disabled")
        from web3 import Web3
        if self.w3 is None:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 1.5}, exception_retry_configuration=None))
        if self.w3.eth.chain_id != CHAIN_ID:
            raise RuntimeError("Refusing any chain except local research chain 31337")
        address = self.address
        if not address:
            metadata_path = self.data_dir / "deployment.json"
            if metadata_path.exists():
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if metadata.get("chain_id") != CHAIN_ID:
                    raise RuntimeError("Deployment metadata is not local chain 31337")
                address = metadata.get("contract_address", "")
        if not address or not Web3.is_address(address):
            raise RuntimeError("No valid local registry address is configured")
        address = Web3.to_checksum_address(address)
        if not self.w3.eth.get_code(address):
            raise RuntimeError("No deployed contract at configured registry address")
        contract = self.w3.eth.contract(address=address, abi=ABI)
        if contract.functions.REGISTRY_VERSION().call() != Web3.keccak(text="AdaptiveIAM.AccessGrantRegistry.v1"):
            raise RuntimeError("Configured contract is not the expected research registry")
        accounts = self.w3.eth.accounts
        if not accounts or contract.functions.writer().call().lower() != accounts[0].lower():
            raise RuntimeError("Registry writer must be the unlocked local test account")
        return self.w3, contract, accounts[0]

    def local_events(self):
        with self.store.connection() as db:
            return [dict(r) for r in db.execute("SELECT id,hash,previous_hash FROM audit ORDER BY id")]

    def status(self):
        events = self.local_events()
        with self.store.connection() as db:
            pending_grants = db.execute("SELECT COUNT(*) FROM blockchain_outbox WHERE kind IN ('grant','revoke') AND status!='confirmed'").fetchone()[0]
            failures = db.execute("SELECT COUNT(*) FROM blockchain_outbox WHERE status='failed'").fetchone()[0]
        result = {"enabled": self.enabled, "connected": False, "ready": False, "chain_id": None, "contract_address": self.address or None, "audit_count": 0, "head_hash": ZERO, "local_audit_count": len(events), "pending_audit_events": len(events) if self.enabled else 0, "pending_grants": pending_grants if self.enabled else 0, "failed_outbox_items": failures if self.enabled else 0, "error": self.configuration_error, "limitation": "Single local Ganache validator and public development writer. Actual EVM hash anchors and timed grants; not decentralized production consensus. Identity/resource hashes can be guessable; no text, passwords or tokens are written on-chain."}
        if not self.enabled:
            return result
        try:
            _, contract, _ = self.connect()
            count = contract.functions.auditCount().call()
            head = contract.functions.auditHead().call().hex()
            if count > len(events) or (count and events[count-1]["hash"] != head):
                raise RuntimeError("On-chain checkpoint does not match the local audit prefix")
            if not self.store.verify_audit()["valid"]:
                raise RuntimeError("Local audit chain has been modified")
            result.update({"connected": True, "ready": True, "chain_id": CHAIN_ID, "contract_address": contract.address, "audit_count": count, "head_hash": head, "pending_audit_events": len(events)-count})
        except Exception as error:
            result["error"] = str(error) if isinstance(error, RuntimeError) else "Local RPC or registry is unavailable; protected access fails closed"
        return result

    def grant_status(self, db, grant_id):
        if not self.enabled:
            return {"required": False, "status": "disabled", "transaction_hash": None}
        row = db.execute("SELECT * FROM blockchain_outbox WHERE kind='grant' AND local_id=?", (grant_id,)).fetchone()
        return {"required": True, "status": row["status"] if row else "pending", "transaction_hash": row["transaction_hash"] if row else None}

    def check_grant(self, grant):
        if not self.enabled:
            return {"required": False, "allowed": True, "status": "disabled"}
        try:
            # Always verify live chain and identity/expiry; cached UI receipts are not authority.
            _, contract, _ = self.connect()
            events = self.local_events()
            count = contract.functions.auditCount().call()
            if count > len(events) or (count and contract.functions.auditHead().call().hex() != events[count-1]["hash"]) or not self.store.verify_audit()["valid"]:
                raise RuntimeError("Audit checkpoint mismatch")
            allowed = bool(contract.functions.hasAccess(identity_hash(grant["id"]), identity_hash(grant["user_id"]), identity_hash(grant["resource_id"])).call())
            return {"required": True, "allowed": allowed, "status": "confirmed" if allowed else "pending_or_expired", "reason": "Live identity-bound contract grant" if allowed else "On-chain grant missing, revoked or expired"}
        except Exception:
            return {"required": True, "allowed": False, "status": "unavailable", "reason": "Local chain/registry unavailable or checkpoint invalid; access denied"}

    def update(self, kind, local_id, status, tx_hash=None, block=None, error=None):
        with self.store.connection(write=True) as db:
            db.execute("INSERT INTO blockchain_outbox (kind,local_id,status,transaction_hash,block_number,error,updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(kind,local_id) DO UPDATE SET status=excluded.status,transaction_hash=COALESCE(excluded.transaction_hash,blockchain_outbox.transaction_hash),block_number=COALESCE(excluded.block_number,blockchain_outbox.block_number),error=excluded.error,updated_at=excluded.updated_at", (kind, str(local_id), status, tx_hash, block, error, stamp()))

    def transact(self, w3, call, writer, kind, local_id):
        tx_hash = w3.to_hex(call.transact({"from": writer, "gas": 350000}))
        self.update(kind, local_id, "pending", tx_hash=tx_hash)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=3, poll_latency=.05)
        if receipt["status"] != 1:
            raise RuntimeError("Registry transaction reverted")
        self.update(kind, local_id, "confirmed", tx_hash, receipt["blockNumber"])
        return {"kind": kind, "local_id": str(local_id), "transaction_hash": tx_hash, "block_number": receipt["blockNumber"]}

    def sync(self, max_events=200):
        if not self.enabled:
            return {**self.status(), "synced_audit_events": 0, "synced_grants": 0, "receipts": [], "errors": []}
        receipts, errors = [], []
        with self.lock:
            try:
                w3, contract, writer = self.connect()
                if not self.store.verify_audit()["valid"]:
                    raise RuntimeError("Refusing to anchor a modified local audit chain")
                events = self.local_events()
                count = contract.functions.auditCount().call()
                if count > len(events):
                    raise RuntimeError("Local audit history is shorter than its on-chain checkpoint")
                for event in events[:count]:
                    if contract.functions.auditHashes(event["id"]).call().hex() != event["hash"]:
                        raise RuntimeError("Existing on-chain audit prefix mismatches local history")
                    self.update("audit", event["id"], "confirmed")
                for event in events[count:count+max_events]:
                    try:
                        receipts.append(self.transact(w3, contract.functions.anchorAudit(bytes.fromhex(event["hash"]), bytes.fromhex(event["previous_hash"])), writer, "audit", event["id"]))
                    except Exception:
                        self.update("audit", event["id"], "failed", error="Local registry anchor failed; retry sync")
                        errors.append({"kind": "audit", "local_id": str(event["id"]), "message": "Local registry anchor failed; no further events anchored"})
                        break
                # Only mirror grants whose creation has been checkpointed and whose
                # actual owner quorum still validates. NLP/LLM cannot populate this.
                checkpoint = contract.functions.auditCount().call()
                with self.store.connection(write=True) as db:
                    self.store.expire(db)
                    grants = [dict(g) for g in db.execute("SELECT * FROM grants")]
                    anchored_creations = {json.loads(r["payload"]).get("grant_id") for r in db.execute("SELECT payload FROM audit WHERE id<=? AND event_type='grant_created'", (checkpoint,))}
                for grant in grants:
                    try:
                        if grant["status"] == "revoked":
                            record = contract.functions.grants(identity_hash(grant["id"])).call()
                            if record[4] and not record[3]:
                                receipts.append(self.transact(w3, contract.functions.revokeGrant(identity_hash(grant["id"])), writer, "revoke", grant["id"]))
                            else:
                                self.update("revoke", grant["id"], "confirmed")
                            continue
                        if grant["status"] != "active" or grant["expires_at"] <= stamp() or grant["id"] not in anchored_creations:
                            continue
                        with self.store.connection() as db:
                            packet = self.store.request_dto(db, grant["request_id"], grant["user_id"])
                            resource = db.execute("SELECT owner_id FROM resources WHERE id=?", (grant["resource_id"],)).fetchone()
                        owner_id = resource["owner_id"]
                        owner_approved = any(v["reviewer_id"] == owner_id and v["approve"] for v in packet["votes"])
                        if packet["status"] != "approved" or packet["requester_id"] != grant["user_id"] or packet["resource_id"] != grant["resource_id"] or not packet["consensus"]["quorum_reached"] or not owner_approved or packet["consensus"]["approval_weight"] <= .5*packet["consensus"]["total_weight"]:
                            raise RuntimeError("Grant no longer has a valid owner quorum")
                        expiry = int(datetime.fromisoformat(grant["expires_at"]).timestamp())
                        record = contract.functions.grants(identity_hash(grant["id"])).call()
                        if record[4]:
                            if record[0] != identity_hash(grant["user_id"]) or record[1] != identity_hash(grant["resource_id"]) or record[2] != expiry or record[3]:
                                raise RuntimeError("Existing contract grant mismatches local policy")
                            self.update("grant", grant["id"], "confirmed")
                        else:
                            receipts.append(self.transact(w3, contract.functions.recordGrant(identity_hash(grant["id"]), identity_hash(grant["user_id"]), identity_hash(grant["resource_id"]), expiry), writer, "grant", grant["id"]))
                    except Exception:
                        self.update("grant", grant["id"], "failed", error="Grant could not be mirrored or owner quorum invalid")
                        errors.append({"kind": "grant", "local_id": grant["id"], "message": "Grant confirmation failed; protected access denied"})
            except Exception as error:
                errors.append({"kind": "configuration_or_rpc", "local_id": "", "message": str(error) if isinstance(error, RuntimeError) else "Local RPC or registry unavailable"})
        return {**self.status(), "synced_audit_events": sum(r["kind"] == "audit" for r in receipts), "synced_grants": sum(r["kind"] == "grant" for r in receipts), "receipts": receipts, "errors": errors}


def install_blockchain(api, authenticated):
    @api.get("/api/blockchain/status")
    def status(identity=Depends(authenticated)):
        return api.state.blockchain.status()

    @api.post("/api/blockchain/sync")
    def sync(identity=Depends(authenticated)):
        if identity["user"]["role"] != "security_reviewer":
            raise HTTPException(403, "Only a security reviewer can sync the local chain")
        return api.state.blockchain.sync()

    @api.post("/api/grants/{grant_id}/revoke")
    def revoke(grant_id: str, identity=Depends(authenticated)):
        store, actor = api.state.store, identity["user"]
        with store.connection(write=True) as db:
            grant = db.execute("SELECT g.*,r.owner_id FROM grants g JOIN resources r ON g.resource_id=r.id WHERE g.id=?", (grant_id,)).fetchone()
            if not grant:
                raise HTTPException(404, "Grant not found")
            if actor["role"] != "security_reviewer" and grant["owner_id"] != actor["id"]:
                raise HTTPException(403, "Only the resource owner or security reviewer may revoke a grant")
            db.execute("UPDATE grants SET status='revoked' WHERE id=?", (grant_id,))
            store.audit(db, "grant_revoked", actor["id"], {"grant_id": grant_id, "resource_id": grant["resource_id"], "user_id": grant["user_id"]})
            db.execute("INSERT OR IGNORE INTO blockchain_outbox (kind,local_id,status,updated_at) VALUES ('revoke',?,'pending',?)", (grant_id, stamp()))
        chain = api.state.blockchain.sync() if api.state.blockchain.enabled else api.state.blockchain.status()
        return {"grant_id": grant_id, "status": "revoked", "blockchain": chain}
