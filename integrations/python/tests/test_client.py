from __future__ import annotations

import io
import json
import time
import unittest
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from integrations.python.adaptive_iam import AdaptiveIamClient, IamError, SiteSession, transaction

ISSUER = "https://iam.example"
CLIENT_ID = "website-client"
METADATA = {"issuer": ISSUER, "authorization_endpoint": ISSUER+"/oauth/authorize", "token_endpoint": ISSUER+"/oauth/token", "userinfo_endpoint": ISSUER+"/oauth/userinfo", "jwks_uri": ISSUER+"/oauth/jwks", "revocation_endpoint": ISSUER+"/oauth/revoke"}


class Response(io.BytesIO):
    def __init__(self, value, status=200, raw=False):
        super().__init__(value if raw else json.dumps(value).encode())
        self.status = status


class Opener:
    def __init__(self, handler):
        self.handler = handler

    def open(self, request, timeout):
        return self.handler(request, timeout)


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.private_key.public_key())), "kid": "test-key", "alg": "RS256", "use": "sig"}

    def client(self, handler, **overrides):
        config = {"issuer": ISSUER, "client_id": CLIENT_ID, "client_secret": "fixture-secret", "redirect_uri": "https://website.example/callback", "opener": Opener(handler)}
        config.update(overrides)
        return AdaptiveIamClient(**config)

    def session(self):
        return SiteSession("fixture-token", {"sub": "aisha"}, time.time()+60)

    def permit(self, **changes):
        return {"allowed": True, "sub": "aisha", "client_id": CLIENT_ID, "resource_id": "research-vault", "scope": "read", "expires_at": datetime.fromtimestamp(time.time()+60, timezone.utc).isoformat(), **changes}

    def signed(self, **changes):
        claims = {"sub": "aisha", "iss": ISSUER, "aud": CLIENT_ID, "nonce": "nonce-fixture", "iat": int(time.time()), "exp": int(time.time())+600, **changes}
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "test-key"})

    def provider(self, token=None, identity=None, token_changes=None, observe=None):
        token = token or self.signed()
        def handler(request, _timeout):
            path = urlparse(request.full_url).path
            if path.endswith("openid-configuration"):
                return Response(METADATA)
            if path == "/oauth/token":
                if observe:
                    observe(request)
                return Response({"access_token": "fixture-token", "token_type": "Bearer", "expires_in": 600, "scope": "openid profile iam:permissions", "id_token": token, **(token_changes or {})})
            if path == "/oauth/jwks":
                return Response({"keys": [self.jwk]})
            if path == "/oauth/userinfo":
                return Response(identity or {"sub": "aisha"})
            self.fail("Unexpected endpoint")
        return handler

    def test_https_and_explicit_loopback_http(self):
        for value in ("http://evil.example", "http://127.0.0.1:8000"):
            with self.assertRaises(IamError):
                self.client(lambda *_: None, issuer=value)
        self.client(lambda *_: None, issuer="http://127.0.0.1:8000", redirect_uri="http://127.0.0.1:3001/callback", allow_local_http=True)

    def test_pkce_state_nonce_and_secret_not_in_login_url(self):
        flow = transaction()
        url = self.client(lambda *_: Response(METADATA)).authorization_url(flow)
        query = parse_qs(urlparse(url).query)
        self.assertEqual(query["state"], [flow["state"]])
        self.assertEqual(query["nonce"], [flow["nonce"]])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(len(query["code_challenge"][0]), 43)
        self.assertNotIn("client_secret", query)

    def test_signed_code_exchange_binds_identity_and_sends_server_secret(self):
        forms = []
        client = self.client(self.provider(observe=lambda request: forms.append(parse_qs(request.data.decode()))))
        session = client.exchange_code(code="fixture-code", verifier="v"*43, nonce="nonce-fixture")
        self.assertEqual(session.identity["sub"], "aisha")
        self.assertGreater(session.expires_at, time.time())
        self.assertEqual(forms[0]["client_secret"], ["fixture-secret"])
        self.assertEqual(forms[0]["code_verifier"], ["v"*43])

    def test_token_verification_latency_never_extends_access_token_lifetime(self):
        started = time.time()
        for delay in (5, 60):
            now = [started]
            upstream = self.provider(self.signed(iat=int(started), exp=int(started)+600), token_changes={"expires_in": 60})

            def delayed(request, timeout):
                response = upstream(request, timeout)
                if urlparse(request.full_url).path == "/oauth/userinfo":
                    now[0] += delay
                return response

            client = self.client(delayed, clock=lambda: now[0])
            if delay == 60:
                with self.assertRaises(IamError) as error:
                    client.exchange_code(code="fixture-code", verifier="v"*43, nonce="nonce-fixture")
                self.assertEqual(error.exception.code, "invalid_session")
            else:
                session = client.exchange_code(code="fixture-code", verifier="v"*43, nonce="nonce-fixture")
                self.assertEqual(session.expires_at, started+60)

    def test_invalid_nonce_audience_issuer_expiry_and_signature(self):
        for change in ({"nonce": "wrong-nonce"}, {"aud": "other-client"}, {"iss": "https://wrong.example"}, {"exp": int(time.time())-1}):
            with self.subTest(change=change), self.assertRaises(IamError) as result:
                self.client(self.provider(self.signed(**change))).exchange_code(code="x", verifier="v"*43, nonce="nonce-fixture")
            self.assertEqual(result.exception.status, 401)
        parts = self.signed().split(".")
        parts[2] = ("a" if parts[2][0] != "a" else "b")+parts[2][1:]
        with self.assertRaises(IamError):
            self.client(self.provider(".".join(parts))).exchange_code(code="x", verifier="v"*43, nonce="nonce-fixture")

    def test_userinfo_subject_mismatch_is_rejected(self):
        with self.assertRaises(IamError) as result:
            self.client(self.provider(identity={"sub": "other"})).exchange_code(code="x", verifier="v"*43, nonce="nonce-fixture")
        self.assertEqual(result.exception.code, "subject_mismatch")

    def test_authorized_party_and_recent_integer_issuance_are_required(self):
        for change in ({"azp": "other-client"}, {"aud": [CLIENT_ID, "other-client"]}, {"aud": [CLIENT_ID, "other-client"], "azp": "other-client"}, {"iat": int(time.time())-901}, {"iat": str(int(time.time()))}, {"exp": str(int(time.time())+600)}):
            with self.subTest(change=change), self.assertRaises(IamError) as result:
                self.client(self.provider(self.signed(**change))).exchange_code(code="x", verifier="v"*43, nonce="nonce-fixture")
            self.assertEqual(result.exception.code, "invalid_id_token")
        session = self.client(self.provider(self.signed(aud=[CLIENT_ID, "other-client"], azp=CLIENT_ID))).exchange_code(code="x", verifier="v"*43, nonce="nonce-fixture")
        self.assertEqual(session.identity["sub"], "aisha")

    def test_valid_permission_is_rechecked_every_call(self):
        calls = []
        client = self.client(lambda request, _: calls.append(request) or Response(self.permit()))
        self.assertEqual(client.permission(self.session(), "research-vault")["scope"], "read")
        client.permission(self.session(), "research-vault")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].headers["Authorization"], "Bearer fixture-token")

    def test_denied_malformed_inconsistent_expired_permissions_fail_closed(self):
        for changes in ({"allowed": False}, {"allowed": "true"}, {"resource_id": "other"}, {"sub": "other"}, {"client_id": "other-client"}, {"scope": "admin"}, {"expires_at": "2000-01-01T00:00:00+00:00"}, {"expires_at": "2040-01-01T00:00:00"}):
            with self.subTest(changes=changes), self.assertRaises(IamError):
                self.client(lambda *_: Response(self.permit(**changes))).permission(self.session(), "research-vault")

    def test_session_expiry_nan_or_missing_token_rejected_before_request(self):
        for session in (SiteSession("x", {"sub": "aisha"}, time.time()-1), SiteSession("x", {"sub": "aisha"}, float("nan")), SiteSession("", {"sub": "aisha"}, time.time()+60)):
            with self.assertRaises(IamError) as result:
                self.client(lambda *_: self.fail("No network call expected")).permission(session, "research-vault")
            self.assertEqual(result.exception.status, 401)

    def test_401_arrays_bad_json_oversized_body_and_timeout_never_allow(self):
        for handler in (lambda *_: Response({}, 401), lambda *_: Response([]), lambda *_: Response(b"{", raw=True), lambda *_: Response({"padding": "x"*70000})):
            with self.assertRaises(IamError):
                self.client(handler).permission(self.session(), "research-vault")
        def timeout(*_):
            raise TimeoutError()
        with self.assertRaises(IamError):
            self.client(timeout).permission(self.session(), "research-vault")

    def test_discovery_endpoints_must_stay_at_configured_issuer(self):
        with self.assertRaises(IamError) as result:
            self.client(lambda *_: Response({**METADATA, "token_endpoint": "https://attacker.example/token"})).discover()
        self.assertEqual(result.exception.code, "issuer_endpoint_mismatch")

    def test_logout_revocation_sends_site_bound_token_and_secret_server_side(self):
        forms = []
        def handler(request, _timeout):
            if urlparse(request.full_url).path.endswith("openid-configuration"):
                return Response(METADATA)
            self.assertEqual(urlparse(request.full_url).path, "/oauth/revoke")
            forms.append(parse_qs(request.data.decode()))
            return Response({})
        self.client(handler).revoke(self.session())
        self.assertEqual(forms[0]["token"], ["fixture-token"])
        self.assertEqual(forms[0]["client_id"], [CLIENT_ID])
        self.assertEqual(forms[0]["client_secret"], ["fixture-secret"])


if __name__ == "__main__":
    unittest.main()
