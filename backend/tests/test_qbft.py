"""Narrow signer and opt-in real four-validator consensus boundary checks."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from backend.app.blockchain import BlockchainMirror, identity_hash, permitted_rpc
from backend.app.chain_signer import RegistrySigner, permitted_signer
from backend.app.store import Store, canonical, now, stamp


class QbftBoundaryTests(unittest.TestCase):
    def test_exact_private_rpc_aliases_require_qbft_mode_and_port(self):
        for index in range(1, 5):
            self.assertTrue(permitted_rpc(f"http://qbft{index}:8545", "qbft"))
            self.assertFalse(permitted_rpc(f"http://qbft{index}:8545"))
        for value in ("http://qbft1.evil:8545", "http://qbft1:9000", "http://qbft1:8545/path", "http://127.0.0.1:8545", "https://qbft1:8545", "http://user@qbft1:8545", "http://qbft1:8545?token=x"):
            self.assertFalse(permitted_rpc(value, "qbft"), value)

    def test_signer_has_one_exact_private_origin(self):
        self.assertTrue(permitted_signer("http://registry-signer:9100"))
        for value in ("http://registry-signer.evil:9100", "http://registry-signer:80", "http://localhost:9100", "https://registry-signer:9100", "http://u:p@registry-signer:9100", "http://registry-signer:9100/sign", "http://registry-signer:9100?token=x"):
            self.assertFalse(permitted_signer(value), value)

    def test_signer_cannot_request_arbitrary_transaction_paths_or_kinds(self):
        signer = RegistrySigner("http://registry-signer:9100", Path("unused"))
        with self.assertRaises(RuntimeError):
            signer.call("/eth_sendTransaction", {})
        with self.assertRaises(RuntimeError):
            signer.submit("transfer", ["wallet", 1])

    def test_missing_signer_credential_does_not_send(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory)/"token"
            token.write_text("short", encoding="utf-8")
            with patch("backend.app.chain_signer.urlopen") as network:
                with self.assertRaises(RuntimeError):
                    RegistrySigner("http://registry-signer:9100", token).submit("revoke", [])
            network.assert_not_called()

    def test_quorum_outage_denies_without_cached_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"IAM_WEB3_NETWORK": "qbft"}):
                mirror = BlockchainMirror(Store(Path(directory)/"iam.sqlite3"), Path(directory), rpc_url="http://qbft1:8545")
            with patch("urllib.request.urlopen", side_effect=OSError("private network unavailable")):
                with self.assertRaises(RuntimeError):
                    mirror.require_quorum()
            self.assertEqual(mirror.validator_health, 0)

    def test_explicit_qbft_mode_cannot_silently_disable_chain_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"IAM_WEB3_NETWORK": "qbft"}):
                mirror = BlockchainMirror(Store(Path(directory)/"iam.sqlite3"), Path(directory), rpc_url="")
            self.assertTrue(mirror.enabled)
            self.assertFalse(mirror.status()["ready"])
            self.assertFalse(mirror.check_grant({})["allowed"])


@unittest.skipUnless(os.getenv("IAM_TEST_QBFT") == "1", "Run isolated QBFT compose study for actual Besu consensus")
class RealQbftTests(unittest.TestCase):
    def rpc(self, method, params=None):
        request = Request("http://qbft1:8545", data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(), headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=3) as response:
            result = json.loads(response.read())
        self.assertNotIn("error", result)
        return result["result"]

    def test_real_consensus_registry_and_outage_phase(self):
        phase = os.getenv("IAM_QBFT_PHASE", "baseline")
        state = Path("/test-state")
        store = Store(state/"iam.sqlite3")
        mirror = BlockchainMirror(store, state)
        results_file = Path("/results/qbft-results.json")
        results = json.loads(results_file.read_text()) if phase != "baseline" else {
            "measured_at": stamp(), "environment": "Four Besu 26.9.0 validators on one Docker Desktop Linux host; chain 31337; synthetic IAM policy state", "independent_administration": False,
            "security": "No published RPC; distinct validator keys; signer-only encrypted writer keystore; authenticated fixed registry operations; API never receives writer key", "validator_count": 4, "block_period_seconds": 1, "phases": {}, "confirmation_ms": [],
            "limitations": ["Crash outages tested; no Byzantine or wide-area fault injection", "Single host and administrator; encrypted keystore password co-resides in isolated signer volume, not HSM", "Small sequential transaction sample; not a throughput benchmark", "Fresh-head guard requires three responsive validators agreeing on a recent common block"]}
        grant_id = "qbft-owner-approved-research-grant"
        if phase == "baseline":
            self.assertEqual(self.rpc("eth_accounts"), [])
            validators = self.rpc("qbft_getValidatorsByBlockNumber", ["latest"])
            self.assertEqual(len(set(validators)), 4)
            self.assertTrue(mirror.status()["ready"])
            expiry = stamp(now() + timedelta(hours=1))
            reviewers = [{"id": "meera", "weight": 1.5, "is_owner": True}, {"id": "vihaan", "weight": 1, "is_owner": False}]
            with store.connection(write=True) as db:
                db.execute("INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("qbft-request", "aisha", "research-vault", "Synthetic owner-reviewed research scope", 1, "approved", stamp(), stamp(now()+timedelta(hours=48)), "{}", "{}", canonical(reviewers), "{}"))
                # Mirror must still find recorded owner and peer approvals.
                for reviewer in reviewers:
                    db.execute("INSERT INTO votes VALUES (?,?,?,?,?,?)", ("qbft-request", reviewer["id"], 1, reviewer["weight"], "Synthetic security fixture", stamp()))
                db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?,?)", (grant_id, "qbft-request", "aisha", "research-vault", "read", stamp(), expiry, "active"))
                store.audit(db, "grant_created", "meera", {"grant_id": grant_id, "request_id": "qbft-request", "user_id": "aisha", "resource_id": "research-vault", "expires_at": expiry})
            packet = mirror.sync()
            self.assertEqual(packet["errors"], [])
            self.assertEqual(packet["synced_grants"], 1)
            results["confirmation_ms"].extend(receipt["confirmation_ms"] for receipt in packet["receipts"])
            with store.connection() as db:
                grant = dict(db.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone())
            self.assertTrue(mirror.check_grant(grant)["allowed"])
            self.assertFalse(mirror.check_grant({**grant, "user_id": "vihaan"})["allowed"])
            request = Request("http://registry-signer:9100/transaction", data=b'{"kind":"revoke","arguments":[]}', headers={"Content-Type": "application/json"})
            with self.assertRaises(HTTPError) as rejection:
                urlopen(request, timeout=3)
            self.assertEqual(rejection.exception.code, 401)
            for operation in ({"kind": "transfer", "arguments": []}, {"kind": "grant", "arguments": ["0x"+"aa"*32]*3+[int(time.time())+73*3600]}, {"kind": "revoke", "arguments": ["0x"+"aa"*32], "to": "0x"+"11"*20}):
                with self.assertRaises(HTTPError) as rejection:
                    mirror.signer.call("/transaction", operation)
                self.assertEqual(rejection.exception.code, 400)
            results["phases"][phase] = {"passed": True, "responsive_validators": mirror.validator_health, "identity_bound_grant": True, "authenticated_narrow_signer": True, "unlocked_accounts": 0, "anchored_events": packet["audit_count"]}
        elif phase == "one_down":
            mirror.require_quorum()
            self.assertEqual(mirror.validator_health, 3)
            with store.connection(write=True) as db:
                store.audit(db, "qbft_one_validator_outage", None, {"synthetic": True})
            packet = mirror.sync()
            self.assertEqual(packet["errors"], [])
            results["confirmation_ms"].extend(receipt["confirmation_ms"] for receipt in packet["receipts"])
            with store.connection() as db:
                grant = dict(db.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone())
            self.assertTrue(mirror.check_grant(grant)["allowed"])
            results["phases"][phase] = {"passed": True, "responsive_validators": 3, "grant_allowed": True, "new_anchor_confirmed": True}
        elif phase == "two_down":
            before = self.rpc("eth_blockNumber")
            with store.connection() as db:
                grant = dict(db.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone())
            self.assertFalse(mirror.check_grant(grant)["allowed"])
            self.assertTrue(mirror.sync()["errors"])
            time.sleep(4)
            after = self.rpc("eth_blockNumber")
            self.assertEqual(before, after)
            results["phases"][phase] = {"passed": True, "grant_allowed": False, "new_anchors_denied": True, "block_height_before": int(before, 16), "block_height_after": int(after, 16), "stall_observation_seconds": 4}
        elif phase == "recovered":
            recovery_started = float(os.getenv("IAM_QBFT_RECOVERY_START", str(time.time())))
            for _ in range(90):
                try:
                    mirror.require_quorum()
                    break
                except RuntimeError:
                    time.sleep(1)
            self.assertTrue(mirror.status()["ready"])
            with store.connection() as db:
                grant = dict(db.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone())
            self.assertTrue(mirror.check_grant(grant)["allowed"])
            with store.connection(write=True) as db:
                db.execute("UPDATE grants SET status='revoked' WHERE id=?", (grant_id,))
                store.audit(db, "grant_revoked", "meera", {"grant_id": grant_id})
            packet = mirror.sync()
            self.assertEqual(packet["errors"], [])
            results["confirmation_ms"].extend(receipt["confirmation_ms"] for receipt in packet["receipts"])
            self.assertFalse(mirror.check_grant(grant)["allowed"])
            results["phases"][phase] = {"passed": True, "responsive_validators": mirror.validator_health, "access_restored_after_recovery": True, "onchain_revoke_denies": True, "recovery_and_revocation_elapsed_seconds": round(time.time()-recovery_started, 3), "poll_timeout_seconds": 90}
        else:
            self.fail("Unknown isolated study phase")
        values = sorted(results["confirmation_ms"])
        if values:
            results["latency"] = {"transactions": len(values), "median_ms": values[len(values)//2] if len(values)%2 else (values[len(values)//2-1]+values[len(values)//2])/2, "min_ms": min(values), "max_ms": max(values)}
        results_file.write_text(json.dumps(results, indent=2)+"\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
