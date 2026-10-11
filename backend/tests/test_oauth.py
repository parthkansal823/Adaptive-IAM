"""Protocol, signed identity and authority-isolation tests for the research IdP."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.oauth import OAuthProvider, pkce
from backend.app.store import PASSWORD, Store, now, secret_hash, stamp

VERIFIER = "B"*64
STATE = "state-"+"x"*32
NONCE = "nonce-"+"y"*32
CALLBACK = "http://localhost:3001/callback"


class OAuthIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.application = create_app(Path(cls.temp.name), Path(cls.temp.name)/"risk.joblib")
        cls.client = TestClient(cls.application)
        cls.client.__enter__()
        cls.tokens = {}
        for uid in ("aisha", "meera", "kavya", "vihaan"):
            result = cls.client.post("/api/auth/login", json={"user_id": uid, "password": PASSWORD, "context": {}})
            assert result.status_code == 200, result.text
            cls.tokens[uid] = result.json()["token"]

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        cls.temp.cleanup()

    def setUp(self):
        with self.application.state.store.connection(write=True) as db:
            for table in ("oauth_tokens", "oauth_codes", "oauth_authorizations", "oauth_apps", "votes", "grants", "requests", "audit"):
                db.execute("DELETE FROM "+table)
            Store.audit(db, "system_initialized", None, {"mode": "isolated_oauth_test"})

    def headers(self, uid="aisha"):
        return {"Authorization": "Bearer "+self.tokens[uid]}

    def register(self, confidential=False, resources=None, scopes=None):
        body = {"name": "Test relying party", "redirect_uris": [CALLBACK], "client_type": "confidential" if confidential else "public", "scopes": scopes or ["openid", "profile", "iam:permissions"], "resource_ids": resources if resources is not None else ["research-vault"]}
        result = self.client.post("/api/apps", headers=self.headers("kavya"), json=body)
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()

    def authorize(self, app, **changes):
        query = {"client_id": app["client_id"], "redirect_uri": CALLBACK, "response_type": "code", "scope": " ".join(app["scopes"]), "state": STATE, "nonce": NONCE, "code_challenge": pkce(VERIFIER), "code_challenge_method": "S256"}
        query.update(changes)
        return self.client.get("/oauth/authorize?"+urlencode(query), follow_redirects=False)

    def consent(self, app, approve=True, uid="aisha"):
        response = self.authorize(app)
        self.assertEqual(response.status_code, 302, response.text)
        request_id = parse_qs(urlsplit(response.headers["location"]).query)["request_id"][0]
        packet = self.client.get("/api/oauth/authorization/"+request_id)
        self.assertEqual(packet.status_code, 200)
        result = self.client.post("/api/oauth/consent", headers=self.headers(uid), json={"request_id": request_id, "approve": approve})
        self.assertEqual(result.status_code, 200, result.text)
        redirect = urlsplit(result.json()["redirect_to"])
        self.assertEqual(redirect.scheme+"://"+redirect.netloc+redirect.path, CALLBACK)
        return parse_qs(redirect.query), request_id

    def token(self, app, code, **changes):
        values = {"grant_type": "authorization_code", "client_id": app["client_id"], "code": code, "redirect_uri": CALLBACK, "code_verifier": VERIFIER}
        if app["client_type"] == "confidential":
            values["client_secret"] = app["client_secret"]
        values.update(changes)
        return self.client.post("/oauth/token", data=values)

    def roundtrip(self, confidential=False, scopes=None):
        app = self.register(confidential=confidential, scopes=scopes)
        callback, _ = self.consent(app)
        response = self.token(app, callback["code"][0])
        self.assertEqual(response.status_code, 200, response.text)
        return app, response.json()

    def test_discovery_and_jwks_are_public_rs256_only(self):
        discovery = self.client.get("/.well-known/openid-configuration").json()
        self.assertEqual(discovery["code_challenge_methods_supported"], ["S256"])
        self.assertEqual(discovery["id_token_signing_alg_values_supported"], ["RS256"])
        self.assertEqual(discovery["response_types_supported"], ["code"])
        self.assertNotIn("implicit", discovery["grant_types_supported"])
        jwk = self.client.get("/oauth/jwks").json()["keys"][0]
        self.assertEqual(jwk["alg"], "RS256")
        self.assertNotIn("d", jwk)
        old_kid = self.application.state.oauth.kid
        rebuilt = OAuthProvider(self.application.state.store, Path(self.temp.name))
        self.assertEqual(old_kid, rebuilt.kid)

    def test_registration_security_role_and_secret_once(self):
        body = {"name": "Client", "redirect_uris": [CALLBACK], "resource_ids": []}
        self.assertEqual(self.client.post("/api/apps", json=body).status_code, 401)
        self.assertEqual(self.client.post("/api/apps", headers=self.headers(), json=body).status_code, 403)
        listing = self.client.get("/api/apps", headers=self.headers())
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["items"], [])
        app = self.register(confidential=True)
        self.assertIn("client_secret", app)
        listing = self.client.get("/api/apps", headers=self.headers("kavya")).json()
        self.assertNotIn("client_secret", listing["items"][0])
        with self.application.state.store.connection() as db:
            stored = db.execute("SELECT secret_hash FROM oauth_apps WHERE client_id=?", (app["client_id"],)).fetchone()[0]
        self.assertNotEqual(stored, app["client_secret"])

    def test_registration_rejects_unsafe_redirects_scopes_and_resources(self):
        for uri in ("http://external.example/callback", "https://user:pass@example.com/callback", "https://example.com/callback#fragment", "https://example.com/callback?code=confuse", "https://example.com/callback?code=", "https://example.com/callback?state", "https://example.com\\@evil.test/cb"):
            with self.subTest(uri=uri):
                response = self.client.post("/api/apps", headers=self.headers("kavya"), json={"name": "Bad URL", "redirect_uris": [uri]})
                self.assertEqual(response.status_code, 422)
        self.assertEqual(self.client.post("/api/apps", headers=self.headers("kavya"), json={"name": "Bad scope", "redirect_uris": [CALLBACK], "scopes": ["admin"]}).status_code, 422)
        self.assertEqual(self.client.post("/api/apps", headers=self.headers("kavya"), json={"name": "Bad map", "redirect_uris": [CALLBACK], "resource_ids": ["unregistered"]}).status_code, 422)

    def test_authorize_requires_exact_redirect_pkce_state_nonce_scope(self):
        app = self.register()
        for changes in ({"redirect_uri": "http://localhost:3001/callback/extra"}, {"redirect_uri": "https://evil.example/cb"}, {"response_type": "token"}, {"code_challenge_method": "plain"}, {"code_challenge": "short"}, {"state": ""}, {"nonce": ""}, {"scope": "openid admin"}):
            with self.subTest(changes=changes):
                response = self.authorize(app, **changes)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn("location", response.headers)

    def test_public_consent_packet_omits_protocol_secrets(self):
        app = self.register()
        response = self.authorize(app)
        request_id = parse_qs(urlsplit(response.headers["location"]).query)["request_id"][0]
        packet = self.client.get("/api/oauth/authorization/"+request_id).json()
        self.assertEqual(packet["app"]["client_id"], app["client_id"])
        self.assertNotIn("nonce", packet)
        self.assertNotIn("state", packet)
        self.assertNotIn("code_challenge", packet)
        self.assertEqual(self.client.post("/api/oauth/consent", json={"request_id": request_id, "approve": True}).status_code, 401)

    def test_consent_denial_echoes_state_and_consumes_request(self):
        app = self.register()
        callback, request_id = self.consent(app, approve=False)
        self.assertEqual(callback["error"], ["access_denied"])
        self.assertEqual(callback["state"], [STATE])
        self.assertNotIn("code", callback)
        self.assertEqual(self.client.post("/api/oauth/consent", headers=self.headers(), json={"request_id": request_id, "approve": True}).status_code, 409)
        self.assertEqual(self.client.get("/api/oauth/authorization/"+request_id).status_code, 404)

    def test_signed_identity_roundtrip_and_profile(self):
        app, tokens = self.roundtrip()
        jwk = self.client.get("/oauth/jwks").json()["keys"][0]
        claims = jwt.decode(tokens["id_token"], jwt.PyJWK.from_dict(jwk).key, algorithms=["RS256"], audience=app["client_id"], issuer=self.application.state.oauth.issuer, options={"require": ["iss", "sub", "aud", "iat", "exp", "nonce", "auth_time"]})
        self.assertEqual(claims["nonce"], NONCE)
        self.assertEqual(claims["sub"], "aisha")
        self.assertEqual(tokens["expires_in"], 600)
        self.assertEqual(tokens["token_type"], "Bearer")
        userinfo = self.client.get("/oauth/userinfo", headers={"Authorization": "Bearer "+tokens["access_token"]}).json()
        self.assertEqual(userinfo["sub"], claims["sub"])
        self.assertEqual(userinfo["name"], "Aisha Verma")
        with self.assertRaises(jwt.InvalidAudienceError):
            jwt.decode(tokens["id_token"], jwt.PyJWK.from_dict(jwk).key, algorithms=["RS256"], audience="wrong-app", issuer=claims["iss"])

    def test_code_wrong_client_redirect_verifier_and_replay(self):
        app = self.register()
        callback, _ = self.consent(app)
        code = callback["code"][0]
        other = self.register()
        self.assertEqual(self.token(other, code).status_code, 400)
        self.assertEqual(self.token(app, code, redirect_uri=CALLBACK+"/wrong").status_code, 400)
        self.assertEqual(self.token(app, code, code_verifier="Z"*64).status_code, 400)
        self.assertEqual(self.token(app, code).status_code, 200)
        self.assertEqual(self.token(app, code).status_code, 400)

    def test_code_redemption_is_atomic_under_concurrency(self):
        app = self.register()
        callback, _ = self.consent(app)
        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(lambda _: self.token(app, callback["code"][0]).status_code, range(2)))
        self.assertEqual(sorted(statuses), [200, 400])

    def test_confidential_client_secret_is_required_and_basic_supported(self):
        app = self.register(confidential=True)
        callback, _ = self.consent(app)
        code = callback["code"][0]
        self.assertEqual(self.token(app, code, client_secret="wrong").status_code, 401)
        values = {"grant_type": "authorization_code", "client_id": app["client_id"], "code": code, "redirect_uri": CALLBACK, "code_verifier": VERIFIER}
        self.assertEqual(self.client.post("/oauth/token", data=values).status_code, 401)
        credentials = base64.b64encode((app["client_id"]+":"+app["client_secret"]).encode()).decode()
        self.assertEqual(self.client.post("/oauth/token", data=values, headers={"Authorization": "Basic "+credentials}).status_code, 200)

    def test_expired_authorization_code_and_access_token(self):
        app = self.register()
        response = self.authorize(app)
        request_id = parse_qs(urlsplit(response.headers["location"]).query)["request_id"][0]
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE oauth_authorizations SET expires_at=? WHERE id=?", (stamp(now()-timedelta(seconds=1)), request_id))
        self.assertEqual(self.client.get("/api/oauth/authorization/"+request_id).status_code, 404)
        callback, _ = self.consent(app)
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE oauth_codes SET expires_at=? WHERE code_hash=?", (stamp(now()-timedelta(seconds=1)), secret_hash(callback["code"][0])))
        self.assertEqual(self.token(app, callback["code"][0]).status_code, 400)
        callback, _ = self.consent(app)
        tokens = self.token(app, callback["code"][0]).json()
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE oauth_tokens SET expires_at=? WHERE token_hash=?", (stamp(now()-timedelta(seconds=1)), secret_hash(tokens["access_token"])))
        self.assertEqual(self.client.get("/oauth/userinfo", headers={"Authorization": "Bearer "+tokens["access_token"]}).status_code, 401)

    def test_app_tokens_and_console_tokens_have_separate_authority(self):
        app, tokens = self.roundtrip()
        headers = {"Authorization": "Bearer "+tokens["access_token"]}
        for path in ("/api/auth/me", "/api/apps", "/api/audit", "/api/requests", "/api/grants"):
            self.assertEqual(self.client.get(path, headers=headers).status_code, 401)
        self.assertEqual(self.client.get("/oauth/userinfo", headers=self.headers()).status_code, 401)
        self.assertEqual(self.client.get("/oauth/userinfo", headers={"Authorization": "Bearer "+tokens["id_token"]}).status_code, 401)

    def test_oauth_consent_never_grants_resource_access(self):
        app, tokens = self.roundtrip()
        headers = {"Authorization": "Bearer "+tokens["access_token"]}
        permission = self.client.get("/oauth/permissions/research-vault", headers=headers).json()
        self.assertFalse(permission["allowed"])
        self.assertEqual(permission["sub"], "aisha")
        self.assertEqual(permission["client_id"], app["client_id"])
        self.assertEqual(self.client.get("/oauth/permissions/finance-reports", headers=headers).status_code, 403)

    def test_permission_requires_scope_and_userinfo_respects_profile_scope(self):
        app, tokens = self.roundtrip(scopes=["openid"])
        headers = {"Authorization": "Bearer "+tokens["access_token"]}
        self.assertEqual(self.client.get("/oauth/userinfo", headers=headers).json(), {"sub": "aisha"})
        self.assertEqual(self.client.get("/oauth/permissions/research-vault", headers=headers).status_code, 403)

    def test_permission_uses_actual_subject_timed_human_grant(self):
        app, tokens = self.roundtrip()
        request = self.client.post("/api/requests", headers=self.headers(), json={"resource_id": "research-vault", "justification": "I need scoped access for approved IAM-42 audit evidence due Friday with manager confirmation.", "duration_hours": 1}).json()
        owner = next(r["id"] for r in request["reviewers"] if r["is_owner"])
        peer = next(r["id"] for r in request["reviewers"] if not r["is_owner"])
        for uid in (owner, peer):
            response = self.client.post(f"/api/requests/{request['id']}/votes", headers=self.headers(uid), json={"approve": True, "comment": "Approved scoped read"})
            self.assertEqual(response.status_code, 200, response.text)
        headers = {"Authorization": "Bearer "+tokens["access_token"]}
        self.assertTrue(self.client.get("/oauth/permissions/research-vault", headers=headers).json()["allowed"])
        with self.application.state.store.connection(write=True) as db:
            db.execute("UPDATE grants SET expires_at=? WHERE request_id=?", (stamp(now()-timedelta(seconds=1)), request["id"]))
        self.assertFalse(self.client.get("/oauth/permissions/research-vault", headers=headers).json()["allowed"])

    def test_registered_origin_cors_does_not_expand_console_authority(self):
        self.register()
        allowed = self.client.options("/oauth/token", headers={"Origin": "http://localhost:3001", "Access-Control-Request-Method": "POST"})
        self.assertEqual(allowed.status_code, 204)
        self.assertEqual(allowed.headers["Access-Control-Allow-Origin"], "http://localhost:3001")
        self.assertEqual(self.client.options("/oauth/token", headers={"Origin": "https://evil.example"}).status_code, 403)
        self.assertNotIn("Access-Control-Allow-Origin", self.client.get("/api/health", headers={"Origin": "http://localhost:3001"}).headers)

    def test_token_exchange_rejects_duplicate_form_keys_and_wrong_content_type(self):
        error = self.client.post("/oauth/token", json={"grant_type": "authorization_code"})
        self.assertEqual(error.status_code, 400)
        self.assertEqual(error.headers["Cache-Control"], "no-store")
        body = "grant_type=authorization_code&code=one&code=two&client_id=app&redirect_uri=uri&code_verifier="+VERIFIER
        self.assertEqual(self.client.post("/oauth/token", content=body, headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code, 400)

    def test_replayed_code_revokes_previously_issued_access_token(self):
        app = self.register()
        callback, _ = self.consent(app)
        code = callback["code"][0]
        tokens = self.token(app, code).json()
        headers = {"Authorization": "Bearer "+tokens["access_token"]}
        self.assertEqual(self.client.get("/oauth/userinfo", headers=headers).status_code, 200)
        self.assertEqual(self.token(app, code).status_code, 400)
        self.assertEqual(self.client.get("/oauth/userinfo", headers=headers).status_code, 401)

    def test_client_revocation_is_bound_idempotent_and_authenticated(self):
        app, tokens = self.roundtrip(confidential=True)
        other = self.register()
        body = {"client_id": other["client_id"], "token": tokens["access_token"]}
        self.assertEqual(self.client.post("/oauth/revoke", data=body).status_code, 200)
        headers = {"Authorization": "Bearer "+tokens["access_token"]}
        self.assertEqual(self.client.get("/oauth/userinfo", headers=headers).status_code, 200)
        body = {"client_id": app["client_id"], "token": tokens["access_token"]}
        self.assertEqual(self.client.post("/oauth/revoke", data=body).status_code, 401)
        body["client_secret"] = app["client_secret"]
        self.assertEqual(self.client.post("/oauth/revoke", data=body).status_code, 200)
        self.assertEqual(self.client.post("/oauth/revoke", data=body).status_code, 200)
        self.assertEqual(self.client.get("/oauth/userinfo", headers=headers).status_code, 401)

    def test_disabling_application_revokes_authority_and_pending_consent(self):
        app, tokens = self.roundtrip()
        response = self.authorize(app)
        request_id = parse_qs(urlsplit(response.headers["location"]).query)["request_id"][0]
        self.assertEqual(self.client.delete("/api/apps/"+app["client_id"], headers=self.headers()).status_code, 403)
        self.assertEqual(self.client.delete("/api/apps/"+app["client_id"], headers=self.headers("kavya")).status_code, 200)
        self.assertEqual(self.client.get("/oauth/userinfo", headers={"Authorization": "Bearer "+tokens["access_token"]}).status_code, 401)
        self.assertEqual(self.authorize(app).status_code, 400)
        self.assertEqual(self.client.get("/api/oauth/authorization/"+request_id).status_code, 404)
        self.assertEqual(self.client.post("/api/oauth/consent", headers=self.headers(), json={"request_id": request_id, "approve": True}).status_code, 409)

    def test_audit_chain_records_protocol_events_without_secrets(self):
        app, tokens = self.roundtrip(confidential=True)
        data = self.client.get("/api/audit", headers=self.headers("kavya")).text
        for value in (app["client_secret"], tokens["access_token"], tokens["id_token"], VERIFIER, NONCE):
            self.assertNotIn(value, data)
        self.assertTrue(self.client.get("/api/audit/verify", headers=self.headers()).json()["valid"])


if __name__ == "__main__":
    unittest.main()
