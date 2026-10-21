"""Merkle shape, atomic prefix sealing, privacy and live-anchor failure boundaries."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from backend.app.audit_proofs import (ALGORITHM, SCHEMA, ZERO, MAX_BUNDLE_BYTES,
    anchor_batch, decode_bundle, inclusion_path, install_audit_proofs, leaf_hash,
    merkle_root, proof_bundle, seal_batch, verify_bundle, verify_snapshot)
from backend.app.store import Store


class AuditProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = Store(Path(cls.temp.name)/"iam.sqlite3")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        with self.store.connection(write=True) as db:
            db.execute("DROP TRIGGER IF EXISTS audit_batches_no_delete")
            db.execute("DELETE FROM audit_batches")
            db.execute("DELETE FROM audit")
            db.execute("DELETE FROM blockchain_outbox")
            db.execute("CREATE TRIGGER audit_batches_no_delete BEFORE DELETE ON audit_batches BEGIN SELECT RAISE(ABORT, 'Audit batches are append-only'); END")
            for index in range(7):
                self.store.audit(db, "test_event", "kavya", {"fixture": index})

    def bundle_for(self, count, index):
        hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(count)]
        leaves = [leaf_hash(i+1, digest) for i, digest in enumerate(hashes)]
        return {"schema_version": SCHEMA, "algorithm": ALGORITHM,
            "batch": {"id": 1, "start_sequence": 1, "end_sequence": count, "event_count": count,
                "root": merkle_root(leaves).hex(), "previous_root": ZERO, "audit_end_hash": hashes[-1]},
            "leaf": {"sequence": index+1, "audit_event_hash": hashes[index]},
            "siblings": inclusion_path(leaves, index),
            "trust": {"root_origin": "local_sqlite", "external_anchor_checked": False}}

    def test_domain_separation_and_non_power_of_two_shape(self):
        a = hashlib.sha256(b"\x00" + (1).to_bytes(8, "big") + bytes.fromhex("ab"*32)).digest()
        b = leaf_hash(2, "cd"*32)
        c = leaf_hash(3, "ef"*32)
        self.assertEqual(leaf_hash(1, "ab"*32), a)
        expected = hashlib.sha256(b"\x01" + hashlib.sha256(b"\x01"+a+b).digest()+c).digest()
        self.assertEqual(merkle_root([a,b,c]), expected)
        self.assertNotEqual(merkle_root([a,b,c]), merkle_root([a,b,c,c]))

    def test_all_positions_across_balanced_and_unbalanced_tree_sizes(self):
        for count in (1,2,3,5,7,8,255,256):
            for index in range(count):
                with self.subTest(count=count, index=index):
                    bundle = self.bundle_for(count, index)
                    result = verify_bundle(bundle, bundle["batch"]["root"])
                    self.assertTrue(result["trusted_inclusion"])
                    self.assertLessEqual(len(bundle["siblings"]), 8)

    def test_self_supplied_root_is_not_trusted_and_wrong_expected_root_fails(self):
        bundle = self.bundle_for(5, 1)
        self.assertTrue(verify_bundle(bundle)["inclusion_valid"])
        self.assertIsNone(verify_bundle(bundle)["trusted_root_match"])
        self.assertFalse(verify_bundle(bundle)["trusted_inclusion"])
        self.assertFalse(verify_bundle(bundle, ZERO)["trusted_inclusion"])
        self.assertFalse(verify_bundle(bundle)["anchor_checked"])

    def test_changed_leaf_sibling_and_root_cannot_verify(self):
        original = self.bundle_for(5, 1)
        for target in ("leaf", "sibling", "root"):
            bundle = deepcopy(original)
            if target == "leaf":
                bundle["leaf"]["audit_event_hash"] = "ab"*32
            elif target == "sibling":
                bundle["siblings"][0]["hash"] = "ab"*32
            else:
                bundle["batch"]["root"] = "ab"*32
            self.assertFalse(verify_bundle(bundle)["inclusion_valid"])

    def test_invalid_fields_tree_shapes_and_forged_trust_are_rejected(self):
        changes = [lambda b: b["leaf"].update(sequence=True), lambda b: b["batch"].update(event_count=257),
            lambda b: b["batch"].update(end_sequence=99), lambda b: b["leaf"].update(sequence=0),
            lambda b: b["batch"].update(previous_root="AB"*32), lambda b: b["batch"].update(id=1.0),
            lambda b: b["siblings"][0].update(side="left"), lambda b: b["siblings"].append({"side":"right","hash":ZERO}),
            lambda b: b["leaf"].update(payload="unexpected"), lambda b: b["trust"].update(external_anchor_checked=True),
            lambda b: b.update(algorithm="sha256-no-domains"), lambda b: b["batch"].update(audit_end_hash="ab"*32)]
        for index, change in enumerate(changes):
            bundle = self.bundle_for(5, 4 if index == 11 else 0)
            change(bundle)
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify_bundle(bundle)

    def test_bounded_json_rejects_duplicate_nonfinite_and_nested_input(self):
        for data in (b"{"+b" "*MAX_BUNDLE_BYTES+b"}", b'{"a":1,"a":2}', b'{"x":NaN}',
                     b'{"x":Infinity}', b"\xff", b"["*2000+b"]"*2000):
            with self.assertRaises(ValueError):
                decode_bundle(data)

    def test_seal_records_a_non_circular_next_prefix_and_hash_only_proof(self):
        first = seal_batch(self.store, 5, "kavya")
        second = seal_batch(self.store, 256, "kavya")
        self.assertEqual((first["start_sequence"], first["end_sequence"]), (1,5))
        self.assertEqual((second["start_sequence"], second["end_sequence"]), (6,8))
        self.assertEqual(second["previous_root"], first["root"])
        with self.store.connection() as db:
            self.assertEqual(verify_snapshot(db)["checked_events"], 9)
            self.assertEqual(db.execute("SELECT event_type FROM audit WHERE id=8").fetchone()[0], "audit_batch_sealed")
        bundle = proof_bundle(self.store, 3)
        self.assertTrue(verify_bundle(bundle, first["root"])["trusted_inclusion"])
        serialized = json.dumps(bundle)
        for excluded in ("actor", "payload", "timestamp", "test_event", "kavya", "fixture"):
            self.assertNotIn(excluded, serialized)
        with self.assertRaises(HTTPException) as error:
            proof_bundle(self.store, 9)
        self.assertEqual(error.exception.status_code, 404)

    def test_concurrent_seals_serialize_without_overlap_or_duplicate_ids(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            batches = list(pool.map(lambda _: seal_batch(self.store, 3, "kavya"), range(2)))
        batches.sort(key=lambda b: b["id"])
        self.assertEqual([b["id"] for b in batches], [1,2])
        self.assertEqual([(b["start_sequence"], b["end_sequence"]) for b in batches], [(1,3),(4,6)])
        self.assertEqual(batches[1]["previous_root"], batches[0]["root"])

    def test_modified_original_audit_or_batch_prevents_seal_and_proof(self):
        seal_batch(self.store, 5, "kavya")
        with self.store.connection(write=True) as db:
            db.execute("UPDATE audit SET payload='{}' WHERE id=2")
        with self.assertRaises(ValueError):
            seal_batch(self.store, 5, "kavya")
        with self.assertRaises(ValueError):
            proof_bundle(self.store, 2)

    def test_batch_rows_are_append_only_and_rewritten_commitments_fail_verification(self):
        seal_batch(self.store, 5, "kavya")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.connection(write=True) as db:
                db.execute("UPDATE audit_batches SET root=? WHERE id=1", ("ab"*32,))
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store.connection(write=True) as db:
                db.execute("DELETE FROM audit_batches")
        with self.store.connection(write=True) as db:
            db.execute("DROP TRIGGER audit_batches_no_update")
            db.execute("UPDATE audit_batches SET root=? WHERE id=1", ("ab"*32,))
            db.execute("CREATE TRIGGER audit_batches_no_update BEFORE UPDATE ON audit_batches BEGIN SELECT RAISE(ABORT, 'Audit batches are append-only'); END")
        with self.assertRaises(ValueError):
            proof_bundle(self.store, 2)

    def client(self, chain=None):
        app = FastAPI()
        app.state.store, app.state.blockchain = self.store, chain or Mock(enabled=False)
        def authenticated(request: Request):
            token = request.headers.get("Authorization", "")
            if token not in ("Bearer reviewer", "Bearer analyst"):
                raise HTTPException(401, "A valid session is required")
            return {"user": {"id": "kavya" if token.endswith("reviewer") else "aisha", "role": "security_reviewer" if token.endswith("reviewer") else "analyst"}}
        install_audit_proofs(app, authenticated)
        return TestClient(app)

    def test_all_global_routes_require_security_reviewer(self):
        client = self.client()
        for method, path, body in (("get", "/api/audit/batches", None), ("post", "/api/audit/batches/seal", {}),
                ("get", "/api/audit/proofs/1", None), ("post", "/api/audit/batches/1/anchor", None)):
            for authorization, expected in ((None,401),("Bearer analyst",403)):
                options = {"headers": {"Authorization": authorization}} if authorization else {}
                if body is not None:
                    options["json"] = body
                self.assertEqual(getattr(client, method)(path, **options).status_code, expected)

    def test_route_bounds_disabled_anchor_and_local_status(self):
        client, headers = self.client(), {"Authorization": "Bearer reviewer"}
        for value in (0,257,True,2.5,"3"):
            self.assertEqual(client.post("/api/audit/batches/seal", headers=headers, json={"max_events":value}).status_code, 422)
        self.assertEqual(client.post("/api/audit/batches/seal", headers=headers, json={"secret":"forbidden"}).status_code, 422)
        response = client.post("/api/audit/batches/seal", headers=headers, json={"max_events":7})
        self.assertEqual(response.status_code,200)
        self.assertFalse(response.json()["anchor_checked"])
        self.assertEqual(client.get("/api/audit/batches?limit=101", headers=headers).status_code,422)
        self.assertEqual(client.get("/api/audit/proofs/0", headers=headers).status_code,422)
        self.assertEqual(client.post("/api/audit/batches/1/anchor", headers=headers).status_code,503)
        report = client.get("/api/audit/batches", headers=headers).json()
        self.assertEqual(report["unsealed_events"],1)
        self.assertFalse(report["anchor_checked"])

    def test_offline_cli_rejects_wrong_trusted_root_and_does_not_assert_network_trust(self):
        root = Path(__file__).resolve().parents[2]
        path = Path(self.temp.name)/"proof.json"
        bundle = self.bundle_for(5,2)
        path.write_text(json.dumps(bundle), encoding="utf-8")
        command = [sys.executable,str(root/"scripts/verify_audit_bundle.py"),str(path)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(json.loads(result.stdout)["trusted_inclusion"])
        result = subprocess.run(command+["--expected-root",ZERO],capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,1)

    def chain_fixture(self, anchored=0):
        batch = seal_batch(self.store,5,"kavya")
        chain, w3, legacy, contract = Mock(), Mock(), Mock(), Mock()
        chain.enabled, chain.lock = True, threading.RLock()
        chain.connect.return_value = w3,legacy,"writer"
        w3.eth.contract.return_value = contract
        w3.keccak.return_value = b"version"
        contract.functions.AUDIT_BATCH_VERSION.return_value.call.return_value = b"version"
        contract.functions.auditBatchCount.return_value.call.return_value = anchored
        contract.functions.auditBatchHead.return_value.call.return_value = bytes.fromhex(batch["root"] if anchored else ZERO)
        contract.functions.auditBatchEnd.return_value.call.return_value = batch["end_sequence"] if anchored else 0
        contract.functions.auditBatches.return_value.call.return_value = (batch["start_sequence"],batch["end_sequence"],bytes.fromhex(batch["root"]),bytes.fromhex(batch["audit_end_hash"]),bytes.fromhex(batch["previous_root"]))
        legacy.functions.auditCount.return_value.call.return_value = 5
        legacy.functions.auditHead.return_value.call.return_value = bytes.fromhex(batch["audit_end_hash"])
        legacy.functions.auditHashes.return_value.call.return_value = bytes.fromhex(batch["audit_end_hash"])
        return chain,contract,legacy,batch

    def test_matching_live_anchor_is_verified_and_idempotent(self):
        chain,_,_,batch = self.chain_fixture(1)
        result = anchor_batch(self.store,chain,1)
        self.assertTrue(result["anchor_checked"])
        self.assertEqual(result["batch"]["root"],batch["root"])
        chain.transact.assert_not_called()

    def test_forged_receipt_does_not_establish_an_anchor(self):
        chain,_,_,_ = self.chain_fixture(0)
        chain.transact.return_value = {"transaction_hash":"0xfixture"}
        with self.assertRaises(HTTPException) as error:
            anchor_batch(self.store,chain,1)
        self.assertEqual(error.exception.status_code,503)
        self.assertEqual(chain.update.call_args.args[2],"failed")

    def test_live_root_mismatch_rpc_failure_and_old_capability_fail_verification(self):
        for mode in ("root","rpc","version","head"):
            with self.subTest(mode=mode):
                self.setUp()
                chain,contract,legacy,_ = self.chain_fixture(1)
                if mode == "root":
                    contract.functions.auditBatches.return_value.call.return_value = (1,5,bytes(32),bytes(32),bytes(32))
                elif mode == "rpc":
                    chain.connect.side_effect = RuntimeError("secret-bearing arbitrary provider detail")
                elif mode == "version":
                    contract.functions.AUDIT_BATCH_VERSION.return_value.call.return_value = b"old"
                else:
                    legacy.functions.auditHead.return_value.call.return_value = bytes(32)
                with self.assertRaises(HTTPException) as error:
                    anchor_batch(self.store,chain,1)
                self.assertEqual(error.exception.status_code,503)
                self.assertNotIn("secret-bearing",error.exception.detail)
                chain.transact.assert_not_called()

    def test_missing_legacy_prefix_requires_explicit_sync(self):
        chain,_,legacy,_ = self.chain_fixture(0)
        legacy.functions.auditCount.return_value.call.return_value = 0
        legacy.functions.auditHead.return_value.call.return_value = bytes(32)
        with self.assertRaises(HTTPException) as error:
            anchor_batch(self.store,chain,1)
        self.assertEqual(error.exception.status_code,409)
        chain.transact.assert_not_called()

    def test_sealing_changes_no_grants_requests_votes_or_sessions(self):
        with self.store.connection() as db:
            before = {table: db.execute("SELECT count(*) FROM "+table).fetchone()[0] for table in ("grants","requests","votes","sessions")}
        seal_batch(self.store,5,"kavya")
        with self.store.connection() as db:
            after = {table: db.execute("SELECT count(*) FROM "+table).fetchone()[0] for table in before}
        self.assertEqual(before,after)


@unittest.skipUnless(os.getenv("IAM_TEST_WEB3_RPC_URL"), "Use the isolated live-Web3 verifier for real audit batch HTTP/EVM tests")
class RealAuditBatchTests(unittest.TestCase):
    def setUp(self):
        from web3 import Web3
        self.w3 = Web3(Web3.HTTPProvider(os.environ["IAM_TEST_WEB3_RPC_URL"]))
        self.assertEqual(self.w3.eth.chain_id,31337)
        self.snapshot = self.w3.provider.make_request("evm_snapshot",[])["result"]

    def tearDown(self):
        self.assertTrue(self.w3.provider.make_request("evm_revert",[self.snapshot])["result"])

    def exercise(self, tamper=False):
        from backend.app.blockchain import BlockchainMirror, function
        from backend.app.main import create_app
        from backend.app.store import PASSWORD
        metadata = json.loads(Path(os.environ["IAM_TEST_WEB3_DEPLOYMENT_FILE"]).read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(Path(directory),Path(directory)/"risk.joblib")
            with TestClient(app) as client:
                app.state.blockchain = BlockchainMirror(app.state.store,Path(directory),rpc_url=os.environ["IAM_TEST_WEB3_RPC_URL"],contract_address=metadata["contract_address"])
                headers = {}
                for user in ("kavya","aisha"):
                    login = client.post("/api/auth/login",json={"user_id":user,"password":PASSWORD,"context":{}})
                    self.assertEqual(login.status_code,200,login.text)
                    headers[user] = {"Authorization":"Bearer "+login.json()["token"]}
                self.assertEqual(client.post("/api/audit/batches/seal",headers=headers["aisha"],json={}).status_code,403)
                sealed = client.post("/api/audit/batches/seal",headers=headers["kavya"],json={"max_events":3})
                self.assertEqual(sealed.status_code,200,sealed.text)
                batch = sealed.json()["batch"]
                self.assertEqual((batch["start_sequence"],batch["end_sequence"]),(1,3))
                missing_prefix = client.post("/api/audit/batches/1/anchor",headers=headers["kavya"])
                self.assertEqual(missing_prefix.status_code,409,missing_prefix.text)
                synced = client.post("/api/blockchain/sync",headers=headers["kavya"])
                self.assertEqual(synced.status_code,200,synced.text)
                self.assertEqual(synced.json()["errors"],[])
                anchored = client.post("/api/audit/batches/1/anchor",headers=headers["kavya"])
                self.assertEqual(anchored.status_code,200,anchored.text)
                self.assertTrue(anchored.json()["anchor_checked"])
                registry = self.w3.eth.contract(address=metadata["contract_address"],abi=[function("verifyAuditBatchInclusion",["uint256","uint64","bytes32","bytes32[]"],["bool"])])
                for sequence in (1,2,3):
                    response = client.get(f"/api/audit/proofs/{sequence}",headers=headers["kavya"])
                    self.assertEqual(response.status_code,200,response.text)
                    bundle = response.json()
                    self.assertTrue(verify_bundle(bundle,anchored.json()["batch"]["root"])["trusted_inclusion"])
                    siblings = [bytes.fromhex(item["hash"]) for item in bundle["siblings"]]
                    self.assertTrue(registry.functions.verifyAuditBatchInclusion(1,sequence,bytes.fromhex(bundle["leaf"]["audit_event_hash"]),siblings).call())
                    self.assertFalse(registry.functions.verifyAuditBatchInclusion(1,sequence,bytes(32),siblings).call())
                if tamper:
                    with app.state.store.connection(write=True) as db:
                        db.execute("UPDATE audit SET payload='{}' WHERE id=2")
                    self.assertEqual(client.get("/api/audit/proofs/2",headers=headers["kavya"]).status_code,409)
                    self.assertEqual(client.post("/api/audit/batches/1/anchor",headers=headers["kavya"]).status_code,503)
                else:
                    again = client.post("/api/audit/batches/1/anchor",headers=headers["kavya"])
                    self.assertEqual(again.status_code,200,again.text)
                    self.assertIsNone(again.json()["receipt"])
                    with patch.object(app.state.blockchain,"connect",side_effect=RuntimeError("Isolated outage")):
                        unavailable = client.post("/api/audit/batches/1/anchor",headers=headers["kavya"])
                    self.assertEqual(unavailable.status_code,503,unavailable.text)

    def test_real_http_anchor_python_and_contract_inclusion_and_outage(self):
        self.exercise()

    def test_real_anchored_history_mutation_is_rejected(self):
        self.exercise(tamper=True)


if __name__ == "__main__":
    unittest.main()
