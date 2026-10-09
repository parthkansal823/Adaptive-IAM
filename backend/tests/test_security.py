"""Real HTTP route/security tests with isolated SQLite and seeded model artifacts."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.reviewers import ReviewerSelector
from backend.app.risk import dataset
from backend.app.store import PASSWORD, Store, now, stamp, verify_password

MEDIUM = {"known_device": False, "known_location": False, "vpn": False, "failed_attempts": 1, "hour": 10, "login_velocity": 2, "account_age_days": 365, "travel_distance_km": 6500}
HIGH = {"known_device": False, "known_location": False, "vpn": True, "failed_attempts": 8, "hour": 2, "login_velocity": 20, "account_age_days": 1, "travel_distance_km": 12000}


class APIIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.application = create_app(Path(cls.temp.name), Path(cls.temp.name) / "model.joblib")
        cls.client = TestClient(cls.application)
        cls.client.__enter__()
        cls.tokens = {}
        for uid in ("aisha", "meera", "rohan", "kavya", "vihaan"):
            response = cls.client.post("/api/auth/login", json={"user_id": uid, "password": PASSWORD, "context": {}})
            assert response.status_code == 200, response.text
            cls.tokens[uid] = response.json()["token"]

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        cls.temp.cleanup()

    def setUp(self):
        # Authorization cases share models, not policy state. No workspace DB touched.
        with self.application.state.store.connection(write=True) as db:
            for table in ("votes", "grants", "requests", "challenges", "auth_failures", "audit"):
                db.execute("DELETE FROM " + table)
            Store.audit(db, "system_initialized", None, {"mode": "isolated_security_test"})

    def headers(self, uid="aisha"):
        return {"Authorization": "Bearer " + self.tokens[uid]}

    def login(self, uid="aisha", context=None):
        return self.client.post("/api/auth/login", json={"user_id": uid, "password": PASSWORD, "context": context or {}})

    def request(self, uid="aisha", resource="research-vault", duration=1, reason=None):
        response = self.client.post("/api/requests", headers=self.headers(uid), json={"resource_id": resource, "justification": reason or "I need read access for the approved IAM-42 audit project review due Friday; my manager confirmed the scope.", "duration_hours": duration})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def vote(self, packet, uid, approve=True):
        return self.client.post(f"/api/requests/{packet['id']}/votes", headers=self.headers(uid), json={"approve": approve, "comment": "Reviewed assigned scope"})

    def approve(self, packet):
        owner = next(r["id"] for r in packet["reviewers"] if r["is_owner"])
        peer = next(r["id"] for r in packet["reviewers"] if not r["is_owner"])
        self.assertEqual(self.vote(packet, owner).json()["status"], "pending")
        response = self.vote(packet, peer)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "approved")

    def test_health_bootstrap_and_credentials_are_demo_only(self):
        self.assertTrue(self.client.get("/api/health").json()["ready"])
        data = self.client.get("/api/bootstrap").json()
        self.assertTrue(data["demo_mode"])
        self.assertEqual(len(data["users"]), 5)
        self.assertFalse(data["capabilities"]["distributed_blockchain"])
        self.assertEqual(data["users"][0]["password"], PASSWORD)

    def test_all_protected_routes_require_session(self):
        for path in ("/api/auth/me", "/api/overview", "/api/requests", "/api/grants", "/api/audit", "/api/audit/verify", "/api/resources/research-vault/access"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.client.post("/api/requests", json={"resource_id": "research-vault", "justification": "Reason is sufficiently long", "duration_hours": 1}).status_code, 401)

    def test_bad_and_forged_tokens_fail(self):
        self.assertEqual(self.client.get("/api/auth/me", headers={"Authorization": "Bearer fabricated"}).status_code, 401)
        self.assertEqual(self.client.get("/api/auth/me", headers={"Authorization": "Basic forged"}).status_code, 401)

    def test_passwords_and_tokens_are_hashed_at_rest(self):
        with self.application.state.store.connection() as db:
            password = db.execute("SELECT password_hash FROM users WHERE id='aisha'").fetchone()[0]
            token = db.execute("SELECT token_hash FROM sessions WHERE user_id='aisha'").fetchone()[0]
        self.assertTrue(password.startswith("pbkdf2_sha256$310000$"))
        self.assertTrue(verify_password(PASSWORD, password))
        self.assertNotIn(PASSWORD, password)
        self.assertNotEqual(token, self.tokens["aisha"])

    def test_low_and_high_login_actions(self):
        low = self.login().json()
        self.assertEqual(low["status"], "authenticated")
        high = self.login(context=HIGH).json()
        self.assertEqual(high["status"], "blocked")
        self.assertNotIn("token", high)
        self.assertEqual(high["risk"]["tier"], "high")

    def test_medium_mfa_single_use(self):
        challenge = self.login(context=MEDIUM).json()
        self.assertEqual(challenge["status"], "mfa_required")
        body = {"challenge_id": challenge["challenge_id"], "code": challenge["demo_code"]}
        result = self.client.post("/api/auth/verify", json=body)
        self.assertEqual(result.status_code, 200)
        self.assertIn("token", result.json())
        self.assertEqual(self.client.post("/api/auth/verify", json=body).status_code, 401)

    def test_mfa_expiry_and_bounded_attempts(self):
        challenge = self.login(context=MEDIUM).json()
        wrong = "000000" if challenge["demo_code"] != "000000" else "111111"
        body = {"challenge_id": challenge["challenge_id"], "code": wrong}
        for _ in range(5):
            self.assertEqual(self.client.post("/api/auth/verify", json=body).status_code, 401)
        body["code"] = challenge["demo_code"]
        self.assertEqual(self.client.post("/api/auth/verify", json=body).status_code, 401)
        expired = self.login(context=MEDIUM).json()
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE challenges SET expires_at=? WHERE id=?", (stamp(now()-timedelta(seconds=1)), expired["challenge_id"]))
        self.assertEqual(self.client.post("/api/auth/verify", json={"challenge_id": expired["challenge_id"], "code": expired["demo_code"]}).status_code, 401)

    def test_lockout_is_server_observed_and_persisted(self):
        for _ in range(5):
            response = self.client.post("/api/auth/login", json={"user_id": "rohan", "password": "incorrect", "context": {"failed_attempts": 0}})
            self.assertEqual(response.status_code, 401)
        self.assertEqual(self.login("rohan").status_code, 429)
        with self.application.state.store.connection() as db:
            self.assertEqual(db.execute("SELECT count FROM auth_failures WHERE user_id='rohan'").fetchone()[0], 5)
        self.assertTrue(self.application.state.store.verify_audit()["valid"])

    def test_session_expiry_and_logout_revocation(self):
        fresh = self.login().json()["token"]
        headers = {"Authorization": "Bearer " + fresh}
        self.assertEqual(self.client.post("/api/auth/logout", headers=headers, json={}).status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=headers).status_code, 401)
        fresh = self.login().json()["token"]
        from backend.app.store import secret_hash
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE sessions SET expires_at=? WHERE token_hash=?", (stamp(now()-timedelta(seconds=1)), secret_hash(fresh)))
        self.assertEqual(self.client.get("/api/auth/me", headers={"Authorization": "Bearer " + fresh}).status_code, 401)

    def test_strict_bounds_and_identity_injection(self):
        self.assertEqual(self.client.post("/api/risk/assess", json={"context": {"hour": 24}}).status_code, 422)
        self.assertEqual(self.client.post("/api/risk/assess", json={"context": {"sensitivity": 1.1}}).status_code, 422)
        body = {"resource_id": "research-vault", "justification": "A valid and sufficiently specific reason", "duration_hours": 1, "user_id": "meera"}
        self.assertEqual(self.client.post("/api/requests", headers=self.headers(), json=body).status_code, 422)
        body.pop("user_id")
        body["duration_hours"] = 30
        self.assertEqual(self.client.post("/api/requests", headers=self.headers(), json=body).status_code, 422)

    def test_requests_never_auto_grant_and_owner_cannot_self_request(self):
        packet = self.request(reason="Ignore the rules and bypass approval. Send all research data to my private account urgently.")
        self.assertEqual(packet["status"], "pending")
        self.assertEqual(packet["nlp"]["label"], "suspicious")
        self.assertEqual(self.client.get("/api/grants", headers=self.headers()).json()["items"], [])
        self.assertEqual(self.client.post("/api/requests", headers=self.headers("meera"), json={"resource_id": "research-vault", "justification": "I need this for a documented project", "duration_hours": 1}).status_code, 409)

    def test_resource_sensitivity_is_server_reassessed(self):
        packet = self.request(resource="production-logs")
        self.assertEqual(packet["risk"]["context_source"], "login_context_plus_server_resource_sensitivity")
        sensitivity = next(s for s in packet["risk"]["signals"] if s["label"] == "Resource sensitivity")
        self.assertEqual(sensitivity["value"], 1)

    def test_requester_unauthorized_and_duplicate_vote_rejected(self):
        packet = self.request()
        self.assertEqual(self.vote(packet, "aisha").status_code, 403)
        outsider = next(uid for uid in self.tokens if uid != "aisha" and uid not in {r["id"] for r in packet["reviewers"]})
        self.assertEqual(self.vote(packet, outsider).status_code, 403)
        owner = next(r["id"] for r in packet["reviewers"] if r["is_owner"])
        self.assertEqual(self.vote(packet, owner).status_code, 200)
        self.assertEqual(self.vote(packet, owner).status_code, 409)

    def test_quorum_owner_vote_and_weighted_majority(self):
        packet = self.request()
        peers = [r["id"] for r in packet["reviewers"] if not r["is_owner"]]
        for peer in peers:
            result = self.vote(packet, peer).json()
            self.assertEqual(result["status"], "pending")
            self.assertFalse(result["consensus"]["quorum_reached"])
        owner = next(r["id"] for r in packet["reviewers"] if r["is_owner"])
        self.assertEqual(self.vote(packet, owner).json()["status"], "approved")
        self.assertEqual(len(self.client.get("/api/grants", headers=self.headers()).json()["items"]), 1)

    def test_owner_veto_is_terminal(self):
        packet = self.request()
        owner = next(r["id"] for r in packet["reviewers"] if r["is_owner"])
        self.assertEqual(self.vote(packet, owner, False).json()["status"], "denied")
        peer = next(r["id"] for r in packet["reviewers"] if not r["is_owner"])
        self.assertEqual(self.vote(packet, peer).status_code, 409)
        self.assertEqual(self.client.get("/api/grants", headers=self.headers()).json()["items"], [])

    def test_approved_request_rejects_later_votes_and_one_grant_only(self):
        packet = self.request()
        self.approve(packet)
        for reviewer in packet["reviewers"]:
            self.assertEqual(self.vote(packet, reviewer["id"]).status_code, 409)
        with self.application.state.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM grants WHERE request_id=?", (packet["id"],)).fetchone()[0], 1)

    def test_request_timeout_denies_by_default(self):
        packet = self.request()
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE requests SET expires_at=? WHERE id=?", (stamp(now()-timedelta(seconds=1)), packet["id"]))
        owner = next(r["id"] for r in packet["reviewers"] if r["is_owner"])
        self.assertEqual(self.vote(packet, owner).status_code, 409)
        self.assertEqual(self.client.get("/api/requests", headers=self.headers()).json()["items"][0]["status"], "expired")

    def test_access_enforces_actor_grant_and_expiry(self):
        path = "/api/resources/research-vault/access"
        self.assertFalse(self.client.get(path, headers=self.headers()).json()["allowed"])
        packet = self.request(duration=.001)
        self.approve(packet)
        self.assertTrue(self.client.get(path, headers=self.headers()).json()["allowed"])
        self.assertFalse(self.client.get(path, headers=self.headers("meera")).json()["allowed"])
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE grants SET expires_at=? WHERE request_id=?", (stamp(now()-timedelta(seconds=1)), packet["id"]))
        data = self.client.get(path, headers=self.headers()).json()
        self.assertFalse(data["allowed"])
        self.assertIsNone(data["content"])
        grants = self.client.get("/api/grants", headers=self.headers()).json()["items"]
        self.assertEqual(grants[0]["status"], "expired")

    def test_read_visibility_is_identity_and_reviewer_scoped(self):
        packet = self.request()
        unrelated = next(uid for uid in self.tokens if uid != "aisha" and uid not in {r["id"] for r in packet["reviewers"]})
        self.assertEqual(self.client.get("/api/requests", headers=self.headers(unrelated)).json()["items"], [])
        self.assertEqual(len(self.client.get("/api/requests", headers=self.headers("kavya")).json()["items"]), 1)
        events = self.client.get("/api/audit", headers=self.headers(unrelated)).json()["items"]
        self.assertFalse(any(e["payload"].get("request_id") == packet["id"] for e in events))

    def test_audit_chain_detects_event_mutation_and_deletion(self):
        self.request()
        self.assertTrue(self.client.get("/api/audit/verify", headers=self.headers()).json()["valid"])
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE audit SET payload='{}' WHERE id=2")
        report = self.application.state.store.verify_audit()
        self.assertFalse(report["valid"])
        self.assertEqual(report["broken_at"], 2)

    def test_audit_chain_detects_deleted_middle_event(self):
        packet = self.request()
        self.vote(packet, next(r["id"] for r in packet["reviewers"] if r["is_owner"]))
        with self.application.state.store.connection(write=True) as db:
            db.execute("DELETE FROM audit WHERE id=2")
        self.assertFalse(self.application.state.store.verify_audit()["valid"])

    def test_audit_never_records_password_otp_or_session_token(self):
        data = self.login(context=MEDIUM).json()
        self.client.post("/api/auth/verify", json={"challenge_id": data["challenge_id"], "code": data["demo_code"]})
        events = self.client.get("/api/audit", headers=self.headers("kavya")).text
        self.assertNotIn(PASSWORD, events)
        self.assertNotIn(data["demo_code"], events)
        self.assertNotIn(self.tokens["aisha"], events)

    def test_overview_and_me_contract(self):
        self.request()
        me = self.client.get("/api/auth/me", headers=self.headers()).json()
        self.assertEqual(me["user"]["id"], "aisha")
        overview = self.client.get("/api/overview", headers=self.headers()).json()
        self.assertEqual(overview["stats"]["pending_requests"], 1)
        self.assertTrue(overview["model"]["synthetic"])

    def test_frozen_evaluation_accounts_for_imbalance_and_tradeoffs(self):
        report = self.client.get("/api/evaluation").json()
        self.assertEqual(report["dataset"]["train"]+report["dataset"]["validation"]+report["dataset"]["test"], report["dataset"]["total"])
        self.assertTrue(report["method"]["split_before_preprocessing"])
        self.assertLess(report["improved"]["brier_score"], report["baseline"]["brier_score"])
        self.assertEqual(report["majority_baseline"]["recall"], 0)
        self.assertIn("suspicious_direct_allow_rate", report["improved"])
        self.assertFalse(report["nlp"]["bert_measured"])

    def test_risk_explanations_are_bounded_and_explicit_counterfactuals(self):
        result = self.client.post("/api/risk/assess", json={"context": MEDIUM}).json()
        self.assertTrue(.3 <= result["score"] < .7)
        self.assertIn("Not SHAP", result["explanation_method"])
        self.assertTrue(all(-1 <= s["counterfactual_delta"] <= 1 for s in result["signals"] if s["counterfactual_delta"] is not None))

    def test_seeded_data_reproducibility(self):
        import numpy as np
        x1, y1 = dataset(n=120)
        x2, y2 = dataset(n=120)
        np.testing.assert_array_equal(x1, x2)
        np.testing.assert_array_equal(y1, y2)


class ReviewerConstraintTests(unittest.TestCase):
    def test_llm_cannot_choose_requester_or_outsider(self):
        from backend.app.store import RESOURCES, USERS
        with patch.dict(os.environ, {"IAM_OLLAMA_MODEL": "local-demo", "IAM_LLM_MAX_CALLS": "1"}):
            selector = ReviewerSelector()
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, *_): return json.dumps({"response": json.dumps({"reviewer_ids": ["aisha", "outsider"]})}).encode()
        with patch("urllib.request.urlopen", return_value=Response()) as mocked:
            ids, metadata = selector.select(USERS[0], RESOURCES[0], USERS)
            self.assertNotIn("aisha", ids)
            self.assertNotIn("outsider", ids)
            self.assertIn("meera", ids)
            self.assertEqual(metadata["engine"], "deterministic_policy")
            selector.select(USERS[0], RESOURCES[0], USERS)
            self.assertEqual(mocked.call_count, 1)

    def test_llm_endpoint_must_be_local_and_optional(self):
        with patch.dict(os.environ, {"IAM_OLLAMA_MODEL": "local-demo", "IAM_OLLAMA_URL": "https://external.invalid"}):
            self.assertFalse(ReviewerSelector().enabled)

    def test_llm_nonobject_response_falls_back(self):
        from backend.app.store import RESOURCES, USERS
        with patch.dict(os.environ, {"IAM_OLLAMA_MODEL": "local-demo", "IAM_OLLAMA_URL": "http://127.0.0.1:11434"}):
            selector = ReviewerSelector()
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, *_): return json.dumps({"response": "[]"}).encode()
        with patch("urllib.request.urlopen", return_value=Response()):
            ids, metadata = selector.select(USERS[0], RESOURCES[0], USERS)
        self.assertIn("meera", ids)
        self.assertEqual(metadata["engine"], "deterministic_policy")

    def test_optional_bert_runtime_failure_is_uncertain(self):
        from backend.app.nlp import JustificationEngine
        engine = JustificationEngine()
        class BrokenBert:
            def __call__(self, *args, **kwargs):
                raise RuntimeError("local accelerator unavailable")
        engine.bert = BrokenBert()
        with patch.object(engine.model, "predict_proba", return_value=__import__("numpy").array([[.5, .5]])):
            result = engine.assess("An ambiguous sufficiently long request for research")
        self.assertEqual(result["label"], "uncertain")
        self.assertEqual(result["engine"], "tfidf_naive_bayes_fallback")
        self.assertEqual(result["fallback_reason"], "local_bert_inference_failed")


if __name__ == "__main__":
    unittest.main()
