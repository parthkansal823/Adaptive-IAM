"""Research OAuth/OIDC code+PKCE provider, separated from console authority.

Protocol references: RFC 7636, RFC 9700, OpenID Connect Core 1.0.
This module is a working research provider, not a certified production IdP.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus, urlencode, urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import Field

from .models import StrictInput
from .store import canonical, now, secret_hash, stamp

SCOPES = {"openid", "profile", "iam:permissions"}
VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class AppInput(StrictInput):
    name: str = Field(min_length=2, max_length=80)
    redirect_uris: list[str] = Field(min_length=1, max_length=8)
    client_type: str = Field("public", pattern="^(public|confidential)$")
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "iam:permissions"], min_length=1, max_length=3)
    resource_ids: list[str] = Field(default_factory=list, max_length=12)
    organization_id: str | None = Field(None, min_length=3, max_length=64, pattern=r"^[a-z0-9_-]+$")


class EmptyInput(StrictInput):
    pass


class ConsentInput(StrictInput):
    request_id: str = Field(min_length=20, max_length=128)
    approve: bool


def valid_url(value: str, callback=False):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 32 or c.isspace() for c in value) or "\\" in value:
        return False
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    if not parsed.hostname or "*" in parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        return False
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in LOOPBACK):
        return False
    # Existing OAuth protocol keys in a callback could cause parameter confusion.
    if callback and set(parse_qs(parsed.query, keep_blank_values=True)) & {"code", "state", "error", "iss", "error_description"}:
        return False
    return True


def pkce(verifier: str):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


def callback_url(uri: str, parameters: dict):
    parsed = urlsplit(uri)
    query = parsed.query + ("&" if parsed.query else "") + urlencode(parameters)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def protocol_json(value, status_code=200, headers=None):
    return JSONResponse(value, status_code=status_code, headers={"Cache-Control": "no-store", "Pragma": "no-cache", **(headers or {})})


def client_credentials(values, authorization):
    """Resolve one client identity from form parameters or OAuth HTTP Basic."""
    if not authorization:
        return values
    scheme, separator, encoded = authorization.partition(" ")
    if scheme.lower() != "basic" or not separator or "client_secret" in values:
        raise ValueError("Use one client authentication method")
    identifier, secret = base64.b64decode(encoded, validate=True).decode("utf-8").split(":", 1)
    identifier = unquote_plus(identifier, encoding="utf-8", errors="strict")
    secret = unquote_plus(secret, encoding="utf-8", errors="strict")
    if not identifier or values.get("client_id", identifier) != identifier:
        raise ValueError("Conflicting client identity")
    return {**values, "client_id": identifier, "client_secret": secret}


class OAuthProvider:
    def __init__(self, store, data_dir: Path):
        self.store = store
        self.issuer = os.getenv("IAM_OAUTH_ISSUER", "http://127.0.0.1:8000").rstrip("/")
        self.frontend = os.getenv("IAM_FRONTEND_URL", "http://127.0.0.1:5173").rstrip("/")
        if not valid_url(self.issuer) or urlsplit(self.issuer).query or not valid_url(self.frontend) or urlsplit(self.frontend).query:
            raise ValueError("OAuth issuer/frontend URL must be HTTPS or loopback HTTP without query/fragment")
        key_path = data_dir / "oidc-signing-key.pem"
        data_dir.mkdir(parents=True, exist_ok=True)
        if not key_path.exists():
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            try:
                # Exclusive creation avoids replacing an existing signing identity.
                descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(pem)
            except FileExistsError:
                pass
        self.key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        public = self.key.public_key()
        if not isinstance(self.key, rsa.RSAPrivateKey) or self.key.key_size < 2048:
            raise ValueError("OIDC signing key must be an RSA private key of at least 2048 bits")
        public_der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.kid = hashlib.sha256(public_der).hexdigest()[:24]
        self.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public))
        self.jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        with store.connection(write=True) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS oauth_apps (client_id TEXT PRIMARY KEY, name TEXT NOT NULL, client_type TEXT NOT NULL, redirect_uris TEXT NOT NULL, scopes TEXT NOT NULL, resource_ids TEXT NOT NULL, secret_hash TEXT, created_at TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), active INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS oauth_authorizations (id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oauth_apps(client_id), redirect_uri TEXT NOT NULL, scopes TEXT NOT NULL, state TEXT NOT NULL, nonce TEXT NOT NULL, code_challenge TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS oauth_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oauth_apps(client_id), user_id TEXT NOT NULL REFERENCES users(id), redirect_uri TEXT NOT NULL, scopes TEXT NOT NULL, nonce TEXT NOT NULL, code_challenge TEXT NOT NULL, auth_time INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS oauth_tokens (token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oauth_apps(client_id), user_id TEXT NOT NULL REFERENCES users(id), scopes TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, code_hash TEXT);
                CREATE TABLE IF NOT EXISTS oauth_session_bindings (code_hash TEXT PRIMARY KEY REFERENCES oauth_codes(code_hash) ON DELETE CASCADE, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE);
            """)
            if "active" not in {r["name"] for r in db.execute("PRAGMA table_info(oauth_apps)")}:
                db.execute("ALTER TABLE oauth_apps ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
            if "code_hash" not in {r["name"] for r in db.execute("PRAGMA table_info(oauth_tokens)")}:
                db.execute("ALTER TABLE oauth_tokens ADD COLUMN code_hash TEXT")
            if "organization_id" not in {r["name"] for r in db.execute("PRAGMA table_info(oauth_apps)")}:
                db.execute("ALTER TABLE oauth_apps ADD COLUMN organization_id TEXT")

    @staticmethod
    def app_dto(row):
        return {"client_id": row["client_id"], "name": row["name"], "client_type": row["client_type"], "redirect_uris": json.loads(row["redirect_uris"]), "scopes": json.loads(row["scopes"]), "resource_ids": json.loads(row["resource_ids"]), "created_at": row["created_at"], "active": bool(row["active"]), "organization_id": row["organization_id"]}

    def endpoints(self):
        return {"issuer": self.issuer, "authorization_endpoint": self.issuer+"/oauth/authorize", "token_endpoint": self.issuer+"/oauth/token", "userinfo_endpoint": self.issuer+"/oauth/userinfo", "jwks_uri": self.issuer+"/oauth/jwks", "revocation_endpoint": self.issuer+"/oauth/revoke"}

    def access_token(self, value, db=None):
        if not value or len(value) > 256:
            raise HTTPException(401, "Invalid OAuth access token")
        if db is None:
            with self.store.connection() as connection:
                return self.access_token(value, db=connection)
        row = db.execute("SELECT t.*,a.resource_ids,a.redirect_uris,a.organization_id,u.name,u.role,u.department,b.session_id source_session_id FROM oauth_tokens t JOIN oauth_apps a ON t.client_id=a.client_id JOIN users u ON t.user_id=u.id LEFT JOIN oauth_session_bindings b ON t.code_hash=b.code_hash WHERE t.token_hash=? AND a.active=1", (secret_hash(value),)).fetchone()
        if not row or row["expires_at"] <= stamp():
            raise HTTPException(401, "OAuth access token expired or invalid")
        return dict(row)

    @staticmethod
    def cors(origin, redirect_uris):
        if not origin:
            return {}
        origins = {urlunsplit((p.scheme, p.netloc, "", "", "")) for p in map(urlsplit, redirect_uris)}
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"} if origin in origins else {}


def install_oauth(api, authenticated, data_dir: Path):
    # Provider is constructed by application lifespan after SQLite users exist.
    def provider():
        return api.state.oauth

    def security(identity=Depends(authenticated)):
        if identity["user"]["role"] != "security_reviewer":
            raise HTTPException(403, "Application registration requires a security reviewer")
        return identity

    def checked_app_token(request, db):
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "OAuth Bearer token required")
        token = provider().access_token(authorization[7:], db=db)
        if not token['source_session_id'] or not api.state.identity.check_session(token['source_session_id'], db=db):
            raise HTTPException(401, 'Source identity session expired, revoked or requires re-verification')
        api.state.developer.allow_subject(db, token, token['user_id'])
        return token

    def app_token(request: Request):
        # Token, application, source session and membership form one policy snapshot.
        rejection, token = None, None
        with provider().store.connection(write=True) as db:
            try:
                token = checked_app_token(request, db)
            except HTTPException as error:
                # Keep any server-observed source-session risk transition durable.
                rejection = error
        if rejection:
            raise rejection
        return token

    @api.get("/.well-known/openid-configuration")
    def discovery():
        return {**provider().endpoints(), "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"], "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"], "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"], "code_challenge_methods_supported": ["S256"], "scopes_supported": sorted(SCOPES), "claims_supported": ["iss", "sub", "aud", "exp", "iat", "nonce", "auth_time", "name", "role", "department"], "research_demo": True}

    @api.get("/oauth/jwks")
    def jwks():
        return JSONResponse({"keys": [provider().jwk]}, headers={"Cache-Control": "public, max-age=300"})

    @api.get("/api/apps")
    def apps(identity=Depends(authenticated)):
        with provider().store.connection() as db:
            rows = db.execute("SELECT * FROM oauth_apps ORDER BY created_at DESC").fetchall()
            rows = [row for row in rows if identity['user']['role'] == 'security_reviewer' or api.state.developer.role(db, row['organization_id'], identity['user']['id'])]
            packets = [api.state.developer.app_dto(db, row, identity, provider()) for row in rows]
        return {"items": packets, **provider().endpoints()}

    @api.post("/api/apps", status_code=201)
    def register(body: AppInput, identity=Depends(authenticated)):
        if body.organization_id or not api.state.identity.context.demo_mode:
            api.state.identity.require_recent(identity)
        elif identity['user']['role'] != 'security_reviewer':
            raise HTTPException(403, 'Legacy app registration requires a security reviewer; use an organization')
        if len(set(body.redirect_uris)) != len(body.redirect_uris) or not all(valid_url(uri, callback=True) for uri in body.redirect_uris):
            raise HTTPException(422, "Redirect URIs must be unique exact HTTPS URLs or loopback HTTP URLs, without credentials, fragments or reserved OAuth query fields")
        if "openid" not in body.scopes or not set(body.scopes) <= SCOPES or len(set(body.scopes)) != len(body.scopes):
            raise HTTPException(422, "Allowed scopes are openid, profile, iam:permissions; openid is required")
        if len(set(body.resource_ids)) != len(body.resource_ids):
            raise HTTPException(422, "Resource mappings must be unique")
        client_id = "app_"+secrets.token_urlsafe(18)
        secret = secrets.token_urlsafe(32) if body.client_type == "confidential" else None
        store = provider().store
        with store.connection(write=True) as db:
            if body.organization_id:
                api.state.developer.require_member(db, body.organization_id, identity['user']['id'], {'admin','developer'})
                if not set(body.resource_ids) <= set(api.state.developer.resource_ids(db, body.organization_id)):
                    raise HTTPException(422, 'Resource owner must belong to this organization before its resource can be mapped')
            elif identity['user']['role'] != 'security_reviewer':
                raise HTTPException(403, 'Select an organization that you administer')
            resources = {r["id"] for r in db.execute("SELECT id FROM resources")}
            if not set(body.resource_ids) <= resources:
                raise HTTPException(422, "Unknown resource mapping")
            if db.execute("SELECT COUNT(*) FROM oauth_apps").fetchone()[0] >= 100:
                raise HTTPException(429, "Research provider supports at most 100 registered applications")
            db.execute("INSERT INTO oauth_apps (client_id,name,client_type,redirect_uris,scopes,resource_ids,secret_hash,created_at,created_by,organization_id) VALUES (?,?,?,?,?,?,?,?,?,?)", (client_id, body.name, body.client_type, canonical(body.redirect_uris), canonical(body.scopes), canonical(body.resource_ids), secret_hash(secret) if secret else None, stamp(), identity["user"]["id"], body.organization_id))
            store.audit(db, "oauth_app_registered", identity["user"]["id"], {"client_id": client_id, "name": body.name, "client_type": body.client_type, "resource_ids": body.resource_ids})
            result = provider().app_dto(db.execute("SELECT * FROM oauth_apps WHERE client_id=?", (client_id,)).fetchone())
        if secret:
            result["client_secret"] = secret
        return JSONResponse(result, status_code=201, headers={"Cache-Control": "no-store"})

    @api.delete("/api/apps/{client_id}")
    def disable(client_id: str, identity=Depends(authenticated)):
        store = provider().store
        with store.connection(write=True) as db:
            app = db.execute("SELECT * FROM oauth_apps WHERE client_id=?", (client_id,)).fetchone()
            if not app:
                raise HTTPException(404, "Application not found")
            api.state.developer.require_app_manager(db, app, identity)
            if app['organization_id'] or not api.state.identity.context.demo_mode:
                api.state.identity.require_recent(identity)
            db.execute("UPDATE oauth_apps SET active=0 WHERE client_id=?", (client_id,))
            db.execute("DELETE FROM oauth_tokens WHERE client_id=?", (client_id,))
            db.execute("UPDATE oauth_authorizations SET consumed=1 WHERE client_id=?", (client_id,))
            store.audit(db, "oauth_app_disabled", identity["user"]["id"], {"client_id": client_id, "tokens_revoked": True})
        return {"client_id": client_id, "active": False, "tokens_revoked": True}

    @api.post('/api/apps/{client_id}/rotate-secret')
    def rotate_secret(client_id: str, body: EmptyInput, identity=Depends(authenticated)):
        api.state.identity.require_recent(identity)
        store = provider().store
        secret = secrets.token_urlsafe(32)
        with store.connection(write=True) as db:
            application = db.execute('SELECT * FROM oauth_apps WHERE client_id=?', (client_id,)).fetchone()
            if not application:
                raise HTTPException(404, 'Application not found')
            api.state.developer.require_app_manager(db, application, identity)
            if not application['active'] or application['client_type'] != 'confidential':
                raise HTTPException(409, 'Only an active confidential application has a secret to rotate')
            db.execute('UPDATE oauth_apps SET secret_hash=? WHERE client_id=?', (secret_hash(secret), client_id))
            db.execute('DELETE FROM oauth_tokens WHERE client_id=?', (client_id,))
            db.execute('UPDATE oauth_codes SET consumed=1 WHERE client_id=?', (client_id,))
            db.execute('UPDATE oauth_authorizations SET consumed=1 WHERE client_id=?', (client_id,))
            store.audit(db, 'oauth_secret_rotated', identity['user']['id'], {'client_id': client_id, 'tokens_revoked': True})
        return JSONResponse({'client_id': client_id, 'client_secret': secret, 'rotated': True, 'tokens_revoked': True}, headers={'Cache-Control':'no-store','Pragma':'no-cache'})

    @api.get("/oauth/authorize")
    def authorize(request: Request):
        query = dict(request.query_params)
        required = {"client_id", "response_type", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"}
        if set(query) != required or any(len(request.query_params.getlist(key)) != 1 for key in query):
            raise HTTPException(400, "Authorization requires one value for each supported parameter")
        if query["response_type"] != "code" or query["code_challenge_method"] != "S256" or not CHALLENGE.fullmatch(query["code_challenge"]):
            raise HTTPException(400, "Only authorization code with PKCE S256 is supported")
        if any(not 8 <= len(query[field]) <= 256 or any(ord(c) < 32 for c in query[field]) for field in ("state", "nonce")):
            raise HTTPException(400, "State and nonce must be 8–256 characters")
        if len(query["scope"]) > 100 or len(query["client_id"]) > 128 or len(query["redirect_uri"]) > 2048:
            raise HTTPException(400, "Authorization parameters too long")
        store = provider().store
        with store.connection(write=True) as db:
            app = db.execute("SELECT * FROM oauth_apps WHERE client_id=?", (query["client_id"],)).fetchone()
            if not app or not app["active"] or query["redirect_uri"] not in json.loads(app["redirect_uris"]):
                # Never redirect an error to an unvalidated callback.
                raise HTTPException(400, "Unknown client or unregistered exact redirect URI")
            scopes = query["scope"].split()
            if "openid" not in scopes or len(set(scopes)) != len(scopes) or not set(scopes) <= set(json.loads(app["scopes"])):
                raise HTTPException(400, "Invalid or unregistered scope")
            if db.execute("SELECT COUNT(*) FROM oauth_authorizations WHERE consumed=0 AND expires_at>?", (stamp(),)).fetchone()[0] >= 500:
                raise HTTPException(429, "Too many pending authorization requests")
            request_id = secrets.token_urlsafe(32)
            db.execute("INSERT INTO oauth_authorizations VALUES (?,?,?,?,?,?,?,?,?,0)", (request_id, query["client_id"], query["redirect_uri"], canonical(scopes), query["state"], query["nonce"], query["code_challenge"], stamp(), stamp(now()+timedelta(minutes=5))))
        return RedirectResponse(provider().frontend+"/connect?"+urlencode({"request_id": request_id}), status_code=302, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    @api.get("/api/oauth/authorization/{request_id}")
    def authorization_packet(request_id: str):
        with provider().store.connection() as db:
            record = db.execute("SELECT q.*,a.name,a.resource_ids FROM oauth_authorizations q JOIN oauth_apps a ON q.client_id=a.client_id WHERE q.id=? AND a.active=1", (request_id,)).fetchone()
            if not record or record["consumed"] or record["expires_at"] <= stamp():
                raise HTTPException(404, "Authorization request invalid, expired or used")
            resource_ids = set(json.loads(record["resource_ids"]))
            resources = [dict(r) for r in db.execute("SELECT * FROM resources") if r["id"] in resource_ids]
        return JSONResponse({"request_id": request_id, "app": {"name": record["name"], "client_id": record["client_id"]}, "scopes": json.loads(record["scopes"]), "resources": resources, "expires_at": record["expires_at"]}, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    @api.post("/api/oauth/consent")
    def consent(body: ConsentInput, identity=Depends(authenticated)):
        store = provider().store
        with store.connection(write=True) as db:
            record = db.execute("SELECT q.* FROM oauth_authorizations q JOIN oauth_apps a ON q.client_id=a.client_id WHERE q.id=? AND a.active=1", (body.request_id,)).fetchone()
            if not record or record["consumed"] or record["expires_at"] <= stamp():
                raise HTTPException(409, "Authorization request expired or already consumed")
            db.execute("UPDATE oauth_authorizations SET consumed=1 WHERE id=?", (body.request_id,))
            parameters = {"state": record["state"], "iss": provider().issuer}
            if body.approve:
                application = db.execute('SELECT * FROM oauth_apps WHERE client_id=?', (record['client_id'],)).fetchone()
                api.state.developer.allow_subject(db, application, identity['user']['id'])
                code = secrets.token_urlsafe(32)
                session = db.execute("SELECT created_at FROM sessions WHERE id=?", (identity["session"]["id"],)).fetchone()
                if not session:
                    raise HTTPException(401, "Console session was revoked")
                from datetime import datetime
                auth_time = int(datetime.fromisoformat(session["created_at"]).timestamp())
                db.execute("INSERT INTO oauth_codes VALUES (?,?,?,?,?,?,?,?,?,?,0)", (secret_hash(code), record["client_id"], identity["user"]["id"], record["redirect_uri"], record["scopes"], record["nonce"], record["code_challenge"], auth_time, stamp(), stamp(now()+timedelta(seconds=90))))
                db.execute('INSERT INTO oauth_session_bindings VALUES (?,?)', (secret_hash(code), identity['session']['id']))
                parameters["code"] = code
            else:
                parameters["error"] = "access_denied"
            store.audit(db, "oauth_consent", identity["user"]["id"], {"client_id": record["client_id"], "approved": body.approve, "scopes": json.loads(record["scopes"])})
            redirect_to = callback_url(record["redirect_uri"], parameters)
        return JSONResponse({"redirect_to": redirect_to}, headers={"Cache-Control": "no-store"})

    @api.post("/oauth/token")
    async def token(request: Request):
        if request.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
            return protocol_json({"error": "invalid_request", "error_description": "Use form-urlencoded token parameters"}, status_code=400)
        raw = await request.body()
        if len(raw) > 8192:
            return protocol_json({"error": "invalid_request"}, status_code=400)
        try:
            parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True, strict_parsing=True, max_num_fields=8)
        except (UnicodeError, ValueError):
            return protocol_json({"error": "invalid_request"}, status_code=400)
        required = {"grant_type", "code", "redirect_uri", "code_verifier"}
        if not required <= set(parsed) or set(parsed) - required - {"client_id", "client_secret"} or any(len(v) != 1 for v in parsed.values()):
            return protocol_json({"error": "invalid_request"}, status_code=400)
        values = {k: v[0] for k, v in parsed.items()}
        if values["grant_type"] != "authorization_code" or not VERIFIER.fullmatch(values["code_verifier"]):
            return protocol_json({"error": "invalid_grant"}, status_code=400)
        try:
            values = client_credentials(values, request.headers.get("Authorization"))
        except (ValueError, UnicodeError):
            return protocol_json({"error": "invalid_client"}, status_code=401)
        if not values.get("client_id"):
            return protocol_json({"error": "invalid_request"}, status_code=400)
        store = provider().store
        with store.connection(write=True) as db:
            app = db.execute("SELECT * FROM oauth_apps WHERE client_id=?", (values["client_id"],)).fetchone()
            if not app or not app["active"]:
                return protocol_json({"error": "invalid_client"}, status_code=401)
            if app["client_type"] == "confidential" and not hmac.compare_digest(secret_hash(values.get("client_secret", "")), app["secret_hash"]):
                return protocol_json({"error": "invalid_client"}, status_code=401)
            code = db.execute("SELECT * FROM oauth_codes WHERE code_hash=?", (secret_hash(values["code"]),)).fetchone()
            if (not code or code["expires_at"] <= stamp() or code["client_id"] != values["client_id"] or code["redirect_uri"] != values["redirect_uri"] or not hmac.compare_digest(code["code_challenge"], pkce(values["code_verifier"]))):
                return protocol_json({"error": "invalid_grant"}, status_code=400)
            if code["consumed"]:
                db.execute("DELETE FROM oauth_tokens WHERE code_hash=?", (code["code_hash"],))
                store.audit(db, "oauth_code_replay_denied", code["user_id"], {"client_id": code["client_id"], "issued_access_tokens_revoked": True})
                return protocol_json({"error": "invalid_grant"}, status_code=400)
            binding = db.execute('SELECT session_id FROM oauth_session_bindings WHERE code_hash=?', (code['code_hash'],)).fetchone()
            if not binding or not api.state.identity.check_session(binding['session_id'], db=db):
                return protocol_json({'error': 'invalid_grant'}, status_code=400)
            try:
                api.state.developer.allow_subject(db, app, code['user_id'])
            except HTTPException:
                return protocol_json({'error':'access_denied'}, status_code=403)
            db.execute("UPDATE oauth_codes SET consumed=1 WHERE code_hash=?", (code["code_hash"],))
            access_token = secrets.token_urlsafe(32)
            db.execute("INSERT INTO oauth_tokens VALUES (?,?,?,?,?,?,?)", (secret_hash(access_token), code["client_id"], code["user_id"], code["scopes"], stamp(), stamp(now()+timedelta(seconds=600)), code["code_hash"]))
            timestamp = int(time.time())
            claims = {"iss": provider().issuer, "sub": code["user_id"], "aud": code["client_id"], "iat": timestamp, "exp": timestamp+600, "nonce": code["nonce"], "auth_time": code["auth_time"]}
            id_token = jwt.encode(claims, provider().key, algorithm="RS256", headers={"kid": provider().kid, "typ": "JWT"})
            store.audit(db, "oauth_token_issued", code["user_id"], {"client_id": code["client_id"], "scopes": json.loads(code["scopes"]), "expires_in": 600})
            headers = {"Cache-Control": "no-store", "Pragma": "no-cache", **provider().cors(request.headers.get("Origin"), json.loads(app["redirect_uris"]))}
            return JSONResponse({"access_token": access_token, "token_type": "Bearer", "expires_in": 600, "scope": " ".join(json.loads(code["scopes"])), "id_token": id_token}, headers=headers)

    @api.post("/oauth/revoke")
    async def revoke(request: Request):
        if request.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
            return protocol_json({"error": "invalid_request"}, status_code=400)
        raw = await request.body()
        if len(raw) > 8192:
            return protocol_json({"error": "invalid_request"}, status_code=400)
        try:
            parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True, strict_parsing=True, max_num_fields=5)
            if "token" not in parsed or set(parsed)-{"token", "client_id", "client_secret", "token_type_hint"} or any(len(v) != 1 for v in parsed.values()):
                raise ValueError()
            values = {k: v[0] for k, v in parsed.items()}
        except (UnicodeError, ValueError):
            return protocol_json({"error": "invalid_request"}, status_code=400)
        try:
            values = client_credentials(values, request.headers.get("Authorization"))
        except (ValueError, UnicodeError):
            return protocol_json({"error": "invalid_client"}, status_code=401)
        if not values.get("client_id"):
            return protocol_json({"error": "invalid_request"}, status_code=400)
        store = provider().store
        with store.connection(write=True) as db:
            app = db.execute("SELECT * FROM oauth_apps WHERE client_id=?", (values["client_id"],)).fetchone()
            if not app or not app["active"] or (app["client_type"] == "confidential" and not hmac.compare_digest(secret_hash(values.get("client_secret", "")), app["secret_hash"])):
                return protocol_json({"error": "invalid_client"}, status_code=401)
            token = db.execute("SELECT * FROM oauth_tokens WHERE token_hash=? AND client_id=?", (secret_hash(values["token"]), values["client_id"])).fetchone()
            if token:
                db.execute("DELETE FROM oauth_tokens WHERE token_hash=?", (token["token_hash"],))
                store.audit(db, "oauth_token_revoked", token["user_id"], {"client_id": token["client_id"]})
            # RFC 7009 deliberately returns success for unknown/already-revoked tokens.
            return protocol_json({}, headers=provider().cors(request.headers.get("Origin"), json.loads(app["redirect_uris"])))

    @api.get("/oauth/userinfo")
    def userinfo(request: Request, token=Depends(app_token)):
        scopes = set(json.loads(token["scopes"]))
        if "openid" not in scopes:
            raise HTTPException(403, "openid scope is required")
        result = {"sub": token["user_id"]}
        if "profile" in scopes:
            result.update({"name": token["name"], "role": token["role"], "department": token["department"]})
        return JSONResponse(result, headers={"Cache-Control": "no-store", **provider().cors(request.headers.get("Origin"), json.loads(token["redirect_uris"]))})

    @api.get("/oauth/permissions/{resource_id}")
    def permissions(resource_id: str, request: Request, token=Depends(app_token)):
        store = provider().store
        rejection = None
        with store.connection(write=True) as db:
            try:
                # The dependency may have completed before a disable, rotation,
                # revocation or mapping change. Reload authority with the grant check.
                token = checked_app_token(request, db)
                if "iam:permissions" not in set(json.loads(token["scopes"])):
                    raise HTTPException(403, "iam:permissions scope is required")
                if resource_id not in json.loads(token["resource_ids"]):
                    raise HTTPException(403, "Resource is not mapped to this OAuth application")
                if token['organization_id'] and resource_id not in api.state.developer.resource_ids(db, token['organization_id']):
                    raise HTTPException(403, 'Resource owner is no longer a member of this application organization')
                store.expire(db)
                grant, chain = store.active_grant(db, token["user_id"], resource_id, api.state.blockchain)
                # Live chain calls can outlast either credential's remaining lifetime.
                token = checked_app_token(request, db)
                allowed = bool(grant) and chain["allowed"]
                store.audit(db, "oauth_permission_checked", token["user_id"], {"client_id": token["client_id"], "resource_id": resource_id, "allowed": allowed, "chain_required": chain["required"], "chain_status": chain["status"]})
            except HTTPException as error:
                # A denied request still commits detected session-risk transitions.
                rejection = error
        if rejection:
            raise rejection
        return JSONResponse({"allowed": allowed, "sub": token["user_id"], "client_id": token["client_id"], "resource_id": resource_id, "scope": "read" if allowed else None, "expires_at": grant["expires_at"] if allowed else None, "blockchain": chain, "reason": "Active human-approved subject grant confirmed by configured policy" if allowed else chain.get("reason", "Authentication and consent do not grant resource access")}, headers={"Cache-Control": "no-store", **provider().cors(request.headers.get("Origin"), json.loads(token["redirect_uris"]))})

    @api.options("/oauth/{path:path}")
    def preflight(path: str, request: Request):
        if path not in {"token", "userinfo", "revoke"} and not path.startswith("permissions/"):
            raise HTTPException(404, "Unknown OAuth endpoint")
        origin = request.headers.get("Origin")
        with provider().store.connection() as db:
            callbacks = [uri for row in db.execute("SELECT redirect_uris FROM oauth_apps WHERE active=1") for uri in json.loads(row[0])]
        headers = provider().cors(origin, callbacks)
        if not headers:
            raise HTTPException(403, "Origin must match a registered redirect URI origin")
        headers.update({"Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Authorization,Content-Type", "Access-Control-Max-Age": "300"})
        return Response(status_code=204, headers=headers)
