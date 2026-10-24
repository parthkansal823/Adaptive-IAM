"""Server-side OAuth/OIDC client; standard-library transport and PyJWT verification."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import secrets
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt


class IamError(Exception):
    def __init__(self, code: str, status: int = 503):
        super().__init__(code)
        self.code, self.status = code, status


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def validate_url(value: str, allow_local_http: bool = False) -> str:
    parsed = urlparse(value)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query
            or (parsed.scheme != "https" and not (allow_local_http and loopback and parsed.scheme == "http"))):
        raise IamError("https_required", 500)
    return value


def transaction() -> dict[str, str]:
    return {"state": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32), "verifier": secrets.token_urlsafe(32)}


@dataclass(frozen=True)
class SiteSession:
    access_token: str
    identity: dict[str, Any]
    expires_at: float


class AdaptiveIamClient:
    def __init__(self, *, issuer: str, client_id: str, redirect_uri: str, client_secret: str = "",
                 scopes: tuple[str, ...] = ("openid", "profile", "iam:permissions"), allow_local_http: bool = False,
                 timeout: float = 2.5, opener=None, clock=time.time):
        self.issuer = validate_url(issuer.rstrip("/"), allow_local_http)
        if urlparse(self.issuer).path not in {"", "/"} or not client_id or "openid" not in scopes or not 0 < timeout <= 30:
            raise IamError("invalid_configuration", 500)
        self.client_id, self.client_secret = client_id, client_secret
        self.redirect_uri = validate_url(redirect_uri, allow_local_http)
        self.scopes, self.allow_local_http = scopes, allow_local_http
        self.timeout, self.opener, self.clock = timeout, opener or build_opener(NoRedirects()), clock
        self.metadata = None

    def endpoint(self, value: str) -> str:
        parsed = urlparse(validate_url(value, self.allow_local_http))
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin != self.issuer:
            raise IamError("issuer_endpoint_mismatch")
        return value

    def request(self, url: str, *, token: str | None = None, form: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if token is not None:
            if not isinstance(token, str) or not token or len(token) > 8192 or any(character.isspace() or ord(character) < 32 for character in token):
                raise IamError("invalid_session", 401)
            headers["Authorization"] = "Bearer " + token
        data = None
        if form is not None:
            data = urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = Request(self.endpoint(url), data=data, headers=headers, method="POST" if form is not None else "GET")
        deadline = time.monotonic() + self.timeout
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise IamError("invalid_session" if response.status == 401 else "access_denied" if response.status == 403 else "iam_unavailable", response.status if response.status in {401, 403} else 503)
                chunks, size = [], 0
                while True:
                    if time.monotonic() >= deadline:
                        raise IamError("iam_timeout")
                    chunk = response.read1(min(4096, 65537-size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 65536:
                        raise IamError("iam_response_too_large")
                    chunks.append(chunk)
                value = json.loads(b"".join(chunks).decode("utf-8"))
                if not isinstance(value, dict):
                    raise IamError("invalid_iam_response")
                return value
        except HTTPError as error:
            raise IamError("invalid_session" if error.code == 401 else "access_denied" if error.code == 403 else "iam_unavailable", error.code if error.code in {401, 403} else 503) from None
        except (TimeoutError, URLError, OSError):
            raise IamError("iam_timeout_or_unavailable") from None
        except (ValueError, TypeError, AttributeError):
            raise IamError("invalid_iam_response") from None

    def discover(self) -> dict[str, Any]:
        if self.metadata:
            return self.metadata
        body = self.request(self.issuer + "/.well-known/openid-configuration")
        if body.get("issuer") != self.issuer:
            raise IamError("issuer_mismatch")
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"):
            if not isinstance(body.get(name), str):
                raise IamError("invalid_discovery_response")
            self.endpoint(body[name])
        if body.get("revocation_endpoint"):
            self.endpoint(body["revocation_endpoint"])
        self.metadata = body
        return body

    @staticmethod
    def _verifier(value: str) -> bool:
        return isinstance(value, str) and 43 <= len(value) <= 128 and all(c.isascii() and (c.isalnum() or c in "._~-") for c in value)

    def authorization_url(self, flow: dict[str, str]) -> str:
        if not self._verifier(flow.get("verifier")) or not all(isinstance(flow.get(name), str) and len(flow[name]) >= 8 for name in ("state", "nonce")):
            raise IamError("invalid_login_transaction", 500)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(flow["verifier"].encode()).digest()).rstrip(b"=").decode()
        query = {"client_id": self.client_id, "response_type": "code", "redirect_uri": self.redirect_uri, "scope": " ".join(self.scopes), "state": flow["state"], "nonce": flow["nonce"], "code_challenge": challenge, "code_challenge_method": "S256"}
        return self.discover()["authorization_endpoint"] + "?" + urlencode(query)

    def exchange_code(self, *, code: str, verifier: str, nonce: str) -> SiteSession:
        if not isinstance(code, str) or not code or len(code) > 2048 or not self._verifier(verifier) or not isinstance(nonce, str) or len(nonce) < 8:
            raise IamError("invalid_callback", 401)
        metadata = self.discover()
        form = {"grant_type": "authorization_code", "code": code, "client_id": self.client_id, "redirect_uri": self.redirect_uri, "code_verifier": verifier}
        if self.client_secret:
            form["client_secret"] = self.client_secret
        # Verification and UserInfo requests must not restart the access-token TTL.
        token_requested_at = self.clock()
        token = self.request(metadata["token_endpoint"], form=form)
        if (not isinstance(token.get("access_token"), str) or not token["access_token"] or not isinstance(token.get("id_token"), str)
                or len(token["id_token"]) > 16384 or not isinstance(token.get("token_type"), str) or token["token_type"].lower() != "bearer"
                or type(token.get("expires_in")) is not int or not 0 < token["expires_in"] <= 86400 or not isinstance(token.get("scope"), str)
                or not set(self.scopes) <= set(token["scope"].split())):
            raise IamError("invalid_token_response")
        try:
            header = jwt.get_unverified_header(token["id_token"])
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise ValueError("algorithm")
            jwks = self.request(metadata["jwks_uri"])
            matches = [key for key in jwks.get("keys", []) if isinstance(key, dict) and key.get("kid") == header["kid"] and key.get("kty") == "RSA" and key.get("use", "sig") == "sig" and key.get("alg", "RS256") == "RS256"]
            if len(matches) != 1:
                raise ValueError("key")
            key = jwt.PyJWK.from_dict(matches[0], algorithm="RS256").key
            claims = jwt.decode(token["id_token"], key, algorithms=["RS256"], issuer=self.issuer, audience=self.client_id, options={"require": ["sub", "exp", "iat", "nonce"]}, leeway=0)
            if (not isinstance(claims["sub"], str) or not claims["sub"] or not isinstance(claims["nonce"], str) or not hmac.compare_digest(claims["nonce"], nonce)
                    or type(claims["iat"]) is not int or type(claims["exp"]) is not int
                    or not 0 <= self.clock()-claims["iat"] <= 900
                    or ("azp" in claims and claims["azp"] != self.client_id)
                    or (isinstance(claims.get("aud"), list) and len(claims["aud"]) > 1 and claims.get("azp") != self.client_id)):
                raise ValueError("claims")
        except (jwt.PyJWTError, ValueError, KeyError, TypeError):
            raise IamError("invalid_id_token", 401) from None
        identity = self.request(metadata["userinfo_endpoint"], token=token["access_token"])
        if identity.get("sub") != claims["sub"]:
            raise IamError("subject_mismatch")
        expiry = min(token_requested_at+token["expires_in"], claims["exp"])
        if expiry <= self.clock():
            raise IamError("invalid_session", 401)
        return SiteSession(token["access_token"], identity, expiry)

    def permission(self, session: SiteSession, resource_id: str) -> dict[str, Any]:
        if (not isinstance(session, SiteSession) or not isinstance(session.identity, dict) or not isinstance(session.identity.get("sub"), str)
                or not session.identity["sub"] or not isinstance(session.access_token, str) or not session.access_token
                or not isinstance(session.expires_at, (int, float)) or not math.isfinite(session.expires_at) or session.expires_at <= self.clock()):
            raise IamError("invalid_session", 401)
        if not isinstance(resource_id, str) or not 1 <= len(resource_id) <= 80 or not resource_id[0].isascii() or not resource_id[0].isalnum() or not all(c.isascii() and (c.isalnum() or c in "_.:-") for c in resource_id):
            raise IamError("invalid_resource", 500)
        body = self.request(self.issuer + "/oauth/permissions/" + resource_id, token=session.access_token)
        if body.get("resource_id") != resource_id or body.get("sub") != session.identity.get("sub") or body.get("client_id") != self.client_id or type(body.get("allowed")) is not bool:
            raise IamError("permission_response_mismatch")
        if not body["allowed"]:
            raise IamError("access_denied", 403)
        try:
            expiry = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
            if expiry.tzinfo is None or expiry.timestamp() <= self.clock() or body.get("scope") != "read" or session.expires_at <= self.clock():
                raise ValueError("expiry")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise IamError("grant_expired_or_invalid", 403) from None
        return {"identity": session.identity, "resource_id": resource_id, "scope": "read", "expires_at": body["expires_at"]}

    def revoke(self, session: SiteSession) -> None:
        metadata = self.discover()
        if not metadata.get("revocation_endpoint"):
            raise IamError("revocation_unavailable")
        form = {"token": session.access_token, "client_id": self.client_id, "token_type_hint": "access_token"}
        if self.client_secret:
            form["client_secret"] = self.client_secret
        self.request(metadata["revocation_endpoint"], form=form)
