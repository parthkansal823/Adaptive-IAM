"""Fail-closed boundary tests; optional real EVM HTTP flow uses an isolated chain."""
from __future__ import annotations

import json
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from backend.app.blockchain import BlockchainMirror, identity_hash, permitted_rpc
from backend.app.main import create_app
from backend.app.oauth import pkce
from backend.app.store import PASSWORD, Store, canonical, now, stamp
from datetime import timedelta


class BlockchainBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name)/"iam.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_rpc_rejects_external_credentials_paths_and_protocols(self):
        for value in ("http://127.0.0.1:8545", "http://localhost:8545/", "http://[::1]:8545", "http://chain:8545"):
            self.assertTrue(permitted_rpc(value), value)
        for value in ("https://chain:8545", "http://example.org", "http://127.0.0.1.evil.test", "http://user:secret@localhost:8545", "http://localhost/private", "http://localhost:bad", "http://localhost?token=secret", "http://chain/#fragment"):
            self.assertFalse(permitted_rpc(value), value)

    def test_disabled_extension_preserves_local_grant_authority(self):
        mirror = BlockchainMirror(self.store, Path(self.temp.name), rpc_url="")
        self.assertFalse(mirror.status()["enabled"])
        self.assertFalse(mirror.check_grant({})["required"])
        self.assertTrue(mirror.check_grant({})["allowed"])
        self.assertEqual(mirror.sync()["receipts"], [])

    def test_invalid_configuration_and_rpc_failure_never_allow(self):
        mirror = BlockchainMirror(self.store, Path(self.temp.name), rpc_url="http://external.test:8545")
        self.assertIsNone(mirror.w3)
        self.assertFalse(mirror.check_grant({"id": "g", "user_id": "aisha", "resource_id": "research-vault"})["allowed"])
        self.assertFalse(mirror.status()["ready"])
        mirror = BlockchainMirror(self.store, Path(self.temp.name), rpc_url="http://localhost:8545")
        with patch.object(mirror, "connect", side_effect=RuntimeError("RPC unavailable")):
            self.assertFalse(mirror.check_grant({})["allowed"])
            self.assertTrue(mirror.sync()["errors"])

    def test_unknown_registry_grant_is_not_confirmed_by_an_outbox_row(self):
        mirror = BlockchainMirror(self.store, Path(self.temp.name), rpc_url="http://localhost:8545")
        mirror.update("grant", "unconfirmed", "confirmed", "0xpublicreceipt", 1)
        contract = Mock()
        contract.functions.auditCount.return_value.call.return_value = 0
        contract.functions.hasAccess.return_value.call.return_value = False
        with patch.object(mirror, "connect", return_value=(None, contract, "writer")):
            result = mirror.check_grant({"id": "unconfirmed", "user_id": "aisha", "resource_id": "research-vault"})
        self.assertFalse(result["allowed"])
        self.assertEqual(result["status"], "pending_or_expired")

    def test_checkpoint_mismatch_and_tampered_history_fail_closed(self):
        mirror = BlockchainMirror(self.store, Path(self.temp.name), rpc_url="http://localhost:8545")
        contract = Mock()
        contract.functions.auditCount.return_value.call.return_value = 1
        contract.functions.auditHead.return_value.call.return_value = bytes.fromhex("ab"*32)
        with patch.object(mirror, "connect", return_value=(None, contract, "writer")):
            self.assertFalse(mirror.status()["ready"])
            self.assertFalse(mirror.check_grant({"id": "g", "user_id": "aisha", "resource_id": "research-vault"})["allowed"])
        with self.store.connection(write=True) as db:
            db.execute("UPDATE audit SET payload='{}' WHERE id=1")
        with patch.object(mirror, "connect", return_value=(None, contract, "writer")):
            self.assertTrue(mirror.sync()["errors"])
        contract.functions.anchorAudit.assert_not_called()

    def test_identity_hash_matches_solidity_bytes32_and_is_deterministic(self):
        self.assertEqual(len(identity_hash("aisha")), 32)
        self.assertEqual(identity_hash("aisha"), identity_hash("aisha"))
        self.assertNotEqual(identity_hash("aisha"), identity_hash("meera"))


@unittest.skipUnless(os.getenv("IAM_TEST_WEB3_RPC_URL"), "Use isolated deployment/compose.web3-tests.yaml for real RPC tests")
class RealWeb3FlowTests(unittest.TestCase):
    """No workspace DB or active research chain is changed by this opt-in suite."""

    def setUp(self):
        from web3 import Web3
        self.w3 = Web3(Web3.HTTPProvider(os.environ["IAM_TEST_WEB3_RPC_URL"]))
        self.assertEqual(self.w3.eth.chain_id, 31337)
        self.snapshot = self.w3.provider.make_request("evm_snapshot", [])["result"]

    def tearDown(self):
        self.assertTrue(self.w3.provider.make_request("evm_revert", [self.snapshot])["result"])

    def new_application(self, directory):
        metadata = json.loads(Path(os.environ["IAM_TEST_WEB3_DEPLOYMENT_FILE"]).read_text())
        application = create_app(Path(directory), Path(directory)/"risk.joblib")
        return application, metadata

    def connect_application(self, application, directory, metadata):
        application.state.blockchain = BlockchainMirror(application.state.store, Path(directory), rpc_url=os.environ["IAM_TEST_WEB3_RPC_URL"], contract_address=metadata["contract_address"])

    def users(self, client):
        result = {}
        for uid in ("aisha", "meera", "kavya", "vihaan"):
            response = client.post("/api/auth/login", json={"user_id": uid, "password": PASSWORD, "context": {}})
            self.assertEqual(response.status_code, 200)
            result[uid] = {"Authorization": "Bearer "+response.json()["token"]}
        return result

    def request(self, client, headers):
        response = client.post("/api/requests", headers=headers["aisha"], json={"resource_id": "research-vault", "duration_hours": 1, "justification": "Read approved IAM audit evidence for the assigned research project review."})
        self.assertEqual(response.status_code, 201)
        return response.json()

    def approve(self, client, headers):
        packet = self.request(client, headers)
        for reviewer in [next(r["id"] for r in packet["reviewers"] if r["is_owner"]), next(r["id"] for r in packet["reviewers"] if not r["is_owner"])]:
            response = client.post(f"/api/requests/{packet['id']}/votes", headers=headers[reviewer], json={"approve": True, "comment": "Reviewed assigned scope"})
            self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "approved")
        self.assertEqual(response.json()["blockchain_sync"]["errors"], [])
        return client.get("/api/grants", headers=headers["aisha"]).json()["items"][0]

    def test_chain_expiry_denies_while_local_grant_is_still_active(self):
        with tempfile.TemporaryDirectory() as directory:
            application, metadata = self.new_application(directory)
            with TestClient(application) as client:
                self.connect_application(application, directory, metadata)
                headers = self.users(client)
                grant = self.approve(client, headers)
                self.assertTrue(client.get("/api/resources/research-vault/access", headers=headers["aisha"]).json()["allowed"])
                self.w3.provider.make_request("evm_increaseTime", [3601])
                self.w3.provider.make_request("evm_mine", [])
                with application.state.store.connection() as db:
                    row = db.execute("SELECT status,expires_at FROM grants WHERE id=?", (grant["id"],)).fetchone()
                    self.assertEqual(row["status"], "active")
                    self.assertGreater(row["expires_at"], stamp())
                result = client.get("/api/resources/research-vault/access", headers=headers["aisha"]).json()
                self.assertFalse(result["allowed"])
                self.assertEqual(result["blockchain"]["status"], "pending_or_expired")

    def test_consistently_rewritten_local_ledger_is_detected_by_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            application, metadata = self.new_application(directory)
            with TestClient(application) as client:
                self.connect_application(application, directory, metadata)
                headers = self.users(client)
                self.approve(client, headers)
                # Demonstrate the weakness of a database-only verifier: all later
                # hashes are recomputed consistently, without changing the EVM.
                with application.state.store.connection(write=True) as db:
                    previous = "0"*64
                    for index, row in enumerate(db.execute("SELECT * FROM audit ORDER BY id").fetchall()):
                        record = {key: row[key] for key in ("id", "timestamp", "event_type", "actor_id")}
                        record["payload"] = {"rewritten": True} if index == 0 else json.loads(row["payload"])
                        record["previous_hash"] = previous
                        digest = hashlib.sha256(canonical(record).encode()).hexdigest()
                        db.execute("UPDATE audit SET payload=?,previous_hash=?,hash=? WHERE id=?", (canonical(record["payload"]), previous, digest, row["id"]))
                        previous = digest
                self.assertTrue(application.state.store.verify_audit()["valid"])
                self.assertFalse(application.state.blockchain.status()["ready"])
                self.assertFalse(client.get("/api/resources/research-vault/access", headers=headers["aisha"]).json()["allowed"])
                self.assertTrue(application.state.blockchain.sync()["errors"])

    def test_chain_rollback_removes_authority_until_valid_state_is_resynced(self):
        with tempfile.TemporaryDirectory() as directory:
            application, metadata = self.new_application(directory)
            with TestClient(application) as client:
                self.connect_application(application, directory, metadata)
                headers = self.users(client)
                before_grant = self.w3.provider.make_request("evm_snapshot", [])["result"]
                self.approve(client, headers)
                self.assertTrue(client.get("/api/resources/research-vault/access", headers=headers["aisha"]).json()["allowed"])
                self.assertTrue(self.w3.provider.make_request("evm_revert", [before_grant])["result"])
                self.assertFalse(client.get("/api/resources/research-vault/access", headers=headers["aisha"]).json()["allowed"])
                self.assertEqual(application.state.blockchain.status()["audit_count"], 0)
                self.assertEqual(application.state.blockchain.sync()["errors"], [])
                self.assertTrue(client.get("/api/resources/research-vault/access", headers=headers["aisha"]).json()["allowed"])

    def test_mirror_rejects_fabricated_grant_without_owner_quorum(self):
        with tempfile.TemporaryDirectory() as directory:
            application, metadata = self.new_application(directory)
            with TestClient(application) as client:
                self.connect_application(application, directory, metadata)
                headers = self.users(client)
                packet = self.request(client, headers)
                with application.state.store.connection(write=True) as db:
                    expiry = stamp(now()+timedelta(hours=1))
                    db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?,?)", ("fabricated-grant", packet["id"], "aisha", "research-vault", "read", stamp(), expiry, "active"))
                    application.state.store.audit(db, "grant_created", "aisha", {"grant_id": "fabricated-grant", "request_id": packet["id"], "user_id": "aisha", "resource_id": "research-vault", "expires_at": expiry})
                result = application.state.blockchain.sync()
                self.assertEqual(result["synced_grants"], 0)
                self.assertTrue(any(error["kind"] == "grant" for error in result["errors"]))
                self.assertFalse(client.get("/api/resources/research-vault/access", headers=headers["aisha"]).json()["allowed"])

    def test_real_vote_anchor_permission_outage_revocation_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            metadata = json.loads(Path(os.environ["IAM_TEST_WEB3_DEPLOYMENT_FILE"]).read_text())
            with patch.dict(os.environ, {"IAM_WEB3_RPC_URL": os.environ["IAM_TEST_WEB3_RPC_URL"], "IAM_WEB3_CONTRACT_ADDRESS": metadata["contract_address"]}):
                application = create_app(data, data/"risk.joblib")
                with TestClient(application) as client:
                    tokens = {}
                    for uid in ("aisha", "meera", "kavya", "vihaan"):
                        response = client.post("/api/auth/login", json={"user_id": uid, "password": PASSWORD, "context": {}})
                        self.assertEqual(response.status_code, 200)
                        tokens[uid] = response.json()["token"]
                    headers = lambda uid="aisha": {"Authorization": "Bearer "+tokens[uid]}
                    access_url = "/api/resources/research-vault/access"
                    self.assertFalse(client.get(access_url, headers=headers()).json()["allowed"])
                    self.assertEqual(client.post("/api/blockchain/sync", headers=headers()).status_code, 403)
                    packet = client.post("/api/requests", headers=headers(), json={"resource_id": "research-vault", "duration_hours": 1, "justification": "Read approved IAM audit research evidence for the assigned project review."}).json()
                    for reviewer in [next(r["id"] for r in packet["reviewers"] if r["is_owner"]), next(r["id"] for r in packet["reviewers"] if not r["is_owner"])]:
                        response = client.post(f"/api/requests/{packet['id']}/votes", headers=headers(reviewer), json={"approve": True, "comment": "Reviewed assigned scope"})
                        self.assertEqual(response.status_code, 200)
                    approved = response.json()
                    self.assertEqual(approved["status"], "approved")
                    self.assertEqual(approved["blockchain_sync"]["errors"], [])
                    self.assertEqual(approved["blockchain_sync"]["synced_grants"], 1)
                    self.assertTrue(client.get(access_url, headers=headers()).json()["allowed"])
                    self.assertFalse(client.get(access_url, headers=headers("vihaan")).json()["allowed"])
                    status = client.get("/api/blockchain/status", headers=headers()).json()
                    self.assertTrue(status["ready"])
                    self.assertEqual(status["chain_id"], 31337)
                    grant = client.get("/api/grants", headers=headers()).json()["items"][0]
                    self.assertEqual(grant["blockchain"]["status"], "confirmed")
                    self.assertTrue(grant["blockchain"]["transaction_hash"].startswith("0x"))

                    # Real website token authorization must also consult the live registry.
                    callback = "http://localhost:3001/callback"
                    app = client.post("/api/apps", headers=headers("kavya"), json={"name": "Isolated EVM test site", "redirect_uris": [callback], "client_type": "public", "scopes": ["openid", "iam:permissions"], "resource_ids": ["research-vault"]}).json()
                    verifier = "B"*64
                    query = {"client_id": app["client_id"], "redirect_uri": callback, "response_type": "code", "scope": "openid iam:permissions", "state": "isolated-state-123", "nonce": "isolated-nonce-123", "code_challenge": pkce(verifier), "code_challenge_method": "S256"}
                    authorize = client.get("/oauth/authorize?"+urlencode(query), follow_redirects=False)
                    request_id = parse_qs(urlsplit(authorize.headers["location"]).query)["request_id"][0]
                    consent = client.post("/api/oauth/consent", headers=headers(), json={"request_id": request_id, "approve": True}).json()
                    code = parse_qs(urlsplit(consent["redirect_to"]).query)["code"][0]
                    token = client.post("/oauth/token", data={"grant_type": "authorization_code", "client_id": app["client_id"], "redirect_uri": callback, "code": code, "code_verifier": verifier}).json()["access_token"]
                    website_headers = {"Authorization": "Bearer "+token}
                    permission_url = "/oauth/permissions/research-vault"
                    self.assertTrue(client.get(permission_url, headers=website_headers).json()["allowed"])
                    with patch.object(application.state.blockchain, "connect", side_effect=RuntimeError("Isolated outage")):
                        self.assertFalse(client.get(access_url, headers=headers()).json()["allowed"])
                        self.assertFalse(client.get(permission_url, headers=website_headers).json()["allowed"])
                    self.assertTrue(client.get(access_url, headers=headers()).json()["allowed"])
                    self.assertEqual(client.post(f"/api/grants/{grant['id']}/revoke", headers=headers()).status_code, 403)
                    revoked = client.post(f"/api/grants/{grant['id']}/revoke", headers=headers("meera")).json()
                    self.assertEqual(revoked["status"], "revoked")
                    self.assertEqual(revoked["blockchain"]["errors"], [])
                    self.assertFalse(client.get(access_url, headers=headers()).json()["allowed"])
                    self.assertFalse(client.get(permission_url, headers=website_headers).json()["allowed"])
                    self.assertFalse(application.state.blockchain.check_grant(grant)["allowed"])
                    with application.state.store.connection(write=True) as db:
                        db.execute("UPDATE audit SET payload='{}' WHERE id=1")
                    self.assertFalse(application.state.blockchain.status()["ready"])
                    self.assertTrue(application.state.blockchain.sync()["errors"])


if __name__ == "__main__":
    unittest.main()
