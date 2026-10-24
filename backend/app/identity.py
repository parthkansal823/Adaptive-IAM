"""Verified passkeys, TOTP, recovery codes and continuously gated sessions."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import timedelta
from urllib.parse import quote, urlsplit

from fastapi import Depends, HTTPException, Request
from pydantic import Field, model_validator

from .models import StrictInput
from .security import ContextSecurity, matching_counter
from .store import canonical, now, secret_hash, stamp, verify_password


class FactorInput(StrictInput):
    code: str | None = Field(None, min_length=6, max_length=6, pattern=r"^[0-9]{6}$")
    recovery_code: str | None = Field(None, min_length=8, max_length=80)

    @model_validator(mode="after")
    def one_factor(self):
        if bool(self.code) == bool(self.recovery_code):
            raise ValueError("Supply exactly one verification code or recovery code")
        return self


class ReauthInput(StrictInput):
    password: str = Field(min_length=1, max_length=256)
    code: str | None = Field(None, min_length=6, max_length=6, pattern=r"^[0-9]{6}$")
    recovery_code: str | None = Field(None, min_length=8, max_length=80)


class EnrollmentConfirm(StrictInput):
    enrollment_id: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class PasskeyLabel(StrictInput):
    label: str = Field("My passkey", min_length=1, max_length=80)


class PasskeyLogin(StrictInput):
    user_id: str = Field(min_length=1, max_length=80)


class CeremonyInput(StrictInput):
    challenge_id: str = Field(min_length=1, max_length=128)
    credential: dict

    @model_validator(mode="after")
    def bounded(self):
        if len(canonical(self.credential)) > 24000:
            raise ValueError("Credential response too large")
        return self


def b64(value: bytes):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def unb64(value: str):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class IdentitySecurity:
    def __init__(self, store, data_dir):
        import os
        self.store = store
        self.context = ContextSecurity(data_dir)
        self.origin = os.getenv("IAM_WEBAUTHN_ORIGIN", os.getenv("IAM_FRONTEND_ORIGIN", "http://127.0.0.1:5173")).rstrip("/")
        parts = urlsplit(self.origin)
        self.rp_id = os.getenv("IAM_WEBAUTHN_RP_ID", parts.hostname or "")
        if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost")):
            raise ValueError("WebAuthn requires HTTPS or exact loopback origin")
        if parts.username or parts.password or parts.query or parts.fragment or parts.path or not self.rp_id or not (parts.hostname == self.rp_id or parts.hostname.endswith("." + self.rp_id)):
            raise ValueError("Invalid WebAuthn origin/RP ID configuration")
        with store.connection(write=True) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS totp_factors (user_id TEXT PRIMARY KEY REFERENCES users(id), encrypted_secret TEXT NOT NULL, last_counter INTEGER NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS recovery_codes (user_id TEXT NOT NULL REFERENCES users(id), code_hash TEXT NOT NULL, used_at TEXT, PRIMARY KEY(user_id,code_hash));
                CREATE TABLE IF NOT EXISTS factor_enrollments (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, encrypted_secret TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), public_key TEXT NOT NULL, sign_count INTEGER NOT NULL, user_handle TEXT NOT NULL, label TEXT NOT NULL, created_at TEXT NOT NULL, last_used_at TEXT, backed_up INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS passkey_challenges (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), session_id TEXT, kind TEXT NOT NULL, challenge TEXT NOT NULL, fingerprint TEXT NOT NULL, label TEXT, expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS identity_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, window_started TEXT NOT NULL);
            """)
            if "enrollment_only" not in {r["name"] for r in db.execute("PRAGMA table_info(session_security)")}:
                db.execute("ALTER TABLE session_security ADD COLUMN enrollment_only INTEGER NOT NULL DEFAULT 0")

    @staticmethod
    def webauthn():
        try:
            import webauthn
            return webauthn
        except (ImportError, OSError) as exc:
            raise HTTPException(503, "Passkey runtime unavailable; use the Docker environment") from exc

    def factor_enrolled(self, user_id, db=None):
        if db is None:
            with self.store.connection() as connection:
                return self.factor_enrolled(user_id, connection)
        return bool(db.execute("SELECT 1 FROM totp_factors WHERE user_id=? UNION SELECT 1 FROM passkeys WHERE user_id=? LIMIT 1", (user_id, user_id)).fetchone())

    def totp_enabled(self, user_id, db):
        return bool(db.execute("SELECT 1 FROM totp_factors WHERE user_id=?", (user_id,)).fetchone())

    def bind_session(self, db, result, request, method):
        verified = stamp() if method in ("totp", "passkey", "recovery") else None
        enrolled = self.factor_enrolled(result["user"]["id"], db)
        enrollment_only = not self.context.demo_mode and not enrolled and method == "password"
        db.execute("INSERT INTO session_security (session_id,fingerprint,verified_at,verification_method,last_seen_at,authentication_mode,enrollment_only) VALUES (?,?,?,?,?,?,?)", (result["session_id"], self.context.fingerprint(request), verified, method, stamp(), "demo" if self.context.demo_mode else "secure", int(enrollment_only)))
        if enrollment_only:
            expiry = stamp(now()+timedelta(minutes=5))
            db.execute("UPDATE sessions SET expires_at=? WHERE id=?", (expiry, result["session_id"]))
            result.update({"expires_at": expiry, "enrollment_required": True, "session_scope": "factor_enrollment"})
        result["verification_method"] = method
        result["factor_enrolled"] = enrolled

    def metadata(self, session_id, db):
        return db.execute("SELECT * FROM session_security WHERE session_id=?", (session_id,)).fetchone()

    def require_recent(self, identity, maximum_age=300, require_factor=True):
        with self.store.connection() as db:
            row = db.execute("SELECT ss.*,s.expires_at FROM session_security ss JOIN sessions s ON ss.session_id=s.id WHERE s.id=? AND s.user_id=?", (identity["session"]["id"], identity["user"]["id"])).fetchone()
            if not row or row["expires_at"] <= stamp():
                raise HTTPException(401, "Session is invalid or expired")
            permitted = row and not row["step_up_required"] and row["verified_at"] and row["verified_at"] > stamp(now()-timedelta(seconds=maximum_age))
            if require_factor:
                permitted = permitted and row["verification_method"] in ("totp", "passkey", "recovery")
            if not permitted:
                raise HTTPException(403, {"code": "recent_verification_required", "message": "Verify an enrolled factor before this security change"})

    def check_session(self, session_id, db=None):
        """OAuth backchannels check source browser session; RP headers are unrelated."""
        if db is None:
            with self.store.connection(write=True) as connection:
                return self.check_session(session_id, db=connection)
        row = db.execute("SELECT s.user_id,s.created_at,s.expires_at,ss.verified_at,ss.step_up_required,ss.authentication_mode,ss.enrollment_only FROM sessions s JOIN session_security ss ON s.id=ss.session_id WHERE s.id=?", (session_id,)).fetchone()
        if not row or row["expires_at"] <= stamp() or row["step_up_required"] or row["enrollment_only"] or (not self.context.demo_mode and row["authentication_mode"] != "secure"):
            return False
        # The exchange can pass its transaction; never start a nested SQLite writer.
        since = max(row["verified_at"] or row["created_at"], stamp(now()-timedelta(minutes=15)))
        failures = db.execute("SELECT COUNT(*) FROM audit WHERE actor_id=? AND event_type='login_failed' AND timestamp>?", (row["user_id"], since)).fetchone()[0]
        if failures >= 3:
            db.execute("UPDATE session_security SET step_up_required=1 WHERE session_id=?", (session_id,))
            self.store.audit(db, "session_risk_changed", row["user_id"], {"session_id": session_id, "action": "step_up", "signal": "server_password_failures"})
            return False
        return True

    def guard(self, identity, request):
        sid, uid = identity["session"]["id"], identity["user"]["id"]
        # Allow recovery of a gated session; no resource/vote/consent endpoint is exempt.
        recovery_paths = {"/api/auth/me", "/api/auth/security", "/api/auth/reauth", "/api/auth/step-up", "/api/auth/logout", "/api/auth/sessions", "/api/auth/passkeys/step-up/options", "/api/auth/passkeys/step-up/verify"}
        with self.store.connection(write=True) as db:
            # The token lookup and this writer are separate transactions. Expiry,
            # revocation and operator-owned identity changes can occur between them.
            session = db.execute("SELECT s.created_at,s.expires_at,u.id,u.name,u.role,u.department FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.id=? AND s.user_id=?", (sid, uid)).fetchone()
            if not session or session["expires_at"] <= stamp():
                raise HTTPException(401, "Session is invalid or expired")
            identity["user"] = {key: session[key] for key in ("id", "name", "role", "department")}
            identity["session"]["expires_at"] = session["expires_at"]
            row = self.metadata(sid, db)
            if not row:
                # Sessions from an older build must freshly authenticate; never bind a bearer on first use.
                raise HTTPException(401, "Sign in again to bind this session to trusted request context")
            if not self.context.demo_mode and row["authentication_mode"] != "secure":
                raise HTTPException(401, "Demo sessions cannot authenticate in secure mode; sign in again")
            created = session["created_at"]
            since = max(row["verified_at"] or created, stamp(now()-timedelta(minutes=15)))
            failures = db.execute("SELECT COUNT(*) FROM audit WHERE actor_id=? AND event_type='login_failed' AND timestamp>?", (uid, since)).fetchone()[0]
            context_changed = not hmac.compare_digest(row["fingerprint"], self.context.fingerprint(request))
            if (context_changed or failures >= 3) and not row["step_up_required"]:
                db.execute("UPDATE session_security SET step_up_required=1 WHERE session_id=?", (sid,))
                self.store.audit(db, "session_context_changed" if context_changed else "session_risk_changed", uid, {"session_id": sid, "action": "step_up", "signal": "request_context" if context_changed else "server_password_failures"})
            row = self.metadata(sid, db)
            # At most one durable heartbeat per minute; raw network/device values are not retained.
            if row["last_seen_at"] < stamp(now()-timedelta(minutes=1)):
                db.execute("UPDATE session_security SET last_seen_at=? WHERE session_id=?", (stamp(), sid))
            stepped = bool(row["step_up_required"])
            identity["session"].update({"verified_at": row["verified_at"], "verification_method": row["verification_method"], "step_up_required": stepped, "factor_enrolled": self.factor_enrolled(uid, db), "fresh_verification": bool(row["verified_at"] and row["verified_at"] > stamp(now()-timedelta(minutes=5)) and row["verification_method"] in ("totp", "passkey", "recovery") and not stepped)})
            enrollment_only = bool(row["enrollment_only"])
            identity["session"]["enrollment_required"] = enrollment_only
        current_revoke = "/api/auth/sessions/" + sid + "/revoke"
        if stepped and request.url.path not in recovery_paths and request.url.path != current_revoke:
            raise HTTPException(403, {"code": "step_up_required", "message": "Session risk or context changed. Verify an enrolled factor or sign in again."})
        enrollment_paths = {"/api/auth/me", "/api/auth/security", "/api/auth/reauth", "/api/auth/logout", "/api/auth/sessions", "/api/auth/totp/enroll", "/api/auth/totp/confirm", "/api/auth/passkeys/register/options", "/api/auth/passkeys/register/verify"}
        if enrollment_only and request.url.path not in enrollment_paths and request.url.path != current_revoke:
            raise HTTPException(403, {"code": "factor_enrollment_required", "message": "Complete first-factor enrollment before using protected services."})
        return identity

    def throttle(self, key, limit=10):
        failure = False
        with self.store.connection(write=True) as db:
            row = db.execute("SELECT * FROM identity_limits WHERE key=?", (key,)).fetchone()
            current = stamp()
            if row and row["window_started"] > stamp(now()-timedelta(minutes=5)):
                if row["count"] >= limit:
                    failure = True
                else:
                    db.execute("UPDATE identity_limits SET count=count+1 WHERE key=?", (key,))
            else:
                db.execute("INSERT INTO identity_limits VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=1,window_started=excluded.window_started", (key, current))
            db.execute("DELETE FROM identity_limits WHERE window_started<?", (stamp(now()-timedelta(hours=1)),))
        if failure:
            raise HTTPException(429, "Verification rate limit reached; wait five minutes")

    def factor_verify(self, db, user_id, code=None, recovery_code=None):
        if bool(code) == bool(recovery_code):
            return None
        if recovery_code:
            digest = secret_hash(user_id + ":" + recovery_code)
            updated = db.execute("UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL", (stamp(), user_id, digest)).rowcount
            return "recovery" if updated else None
        row = db.execute("SELECT * FROM totp_factors WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return None
        secret = self.context.cipher.decrypt(row["encrypted_secret"].encode()).decode()
        counter = matching_counter(secret, code, row["last_counter"])
        if counter is None:
            return None
        db.execute("UPDATE totp_factors SET last_counter=? WHERE user_id=?", (counter, user_id))
        return "totp"

    def fresh(self, db, sid, request, method):
        current = stamp()
        verified_factor = method in ("totp", "passkey", "recovery")
        row = self.metadata(sid, db)
        was_enrollment = row and row["enrollment_only"]
        db.execute("UPDATE session_security SET fingerprint=?,verified_at=?,verification_method=?,step_up_required=0,failures=0,last_seen_at=?,enrollment_only=CASE WHEN ? THEN 0 ELSE enrollment_only END WHERE session_id=?", (self.context.fingerprint(request), current, method, current, int(verified_factor), sid))
        if was_enrollment and verified_factor:
            db.execute("UPDATE sessions SET expires_at=? WHERE id=?", (stamp(now()+timedelta(minutes=30)), sid))
        return {"status": "verified", "fresh_until": stamp(now()+timedelta(minutes=5)), "verification_method": method}

    def restrict_after_factor_removal(self, db, user_id, session_id):
        if not self.context.demo_mode and not self.factor_enrolled(user_id, db):
            db.execute("UPDATE session_security SET enrollment_only=1 WHERE session_id=?", (session_id,))
            db.execute("UPDATE sessions SET expires_at=? WHERE id=?", (stamp(now()+timedelta(minutes=5)), session_id))

    def failed(self, db, identity):
        sid, uid = identity["session"]["id"], identity["user"]["id"]
        db.execute("UPDATE session_security SET failures=failures+1 WHERE session_id=?", (sid,))
        row = self.metadata(sid, db)
        revoked = row and row["failures"] >= 5
        if revoked:
            db.execute("DELETE FROM sessions WHERE id=?", (sid,))
        self.store.audit(db, "factor_verification_failed", uid, {"session_id": sid, "action": "revoke" if revoked else "deny"})

    def recovery(self, db, user_id):
        codes = [secrets.token_hex(10) for _ in range(8)]
        db.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        db.executemany("INSERT INTO recovery_codes (user_id,code_hash) VALUES (?,?)", [(user_id, secret_hash(user_id + ":" + code)) for code in codes])
        return codes

    def challenge(self, db, uid, request, kind, sid=None, label=None):
        challenge_id, nonce = secrets.token_urlsafe(24), secrets.token_bytes(32)
        db.execute("DELETE FROM passkey_challenges WHERE expires_at<?", (stamp(),))
        # Context binding keeps unrelated clients from invalidating a user's ceremony.
        db.execute("DELETE FROM passkey_challenges WHERE user_id=? AND kind=? AND COALESCE(session_id,'')=COALESCE(?,'') AND fingerprint=?", (uid, kind, sid, self.context.fingerprint(request)))
        if db.execute("SELECT COUNT(*) FROM passkey_challenges WHERE user_id=? AND kind=? AND consumed=0", (uid, kind)).fetchone()[0] >= 30:
            raise HTTPException(429, "Too many outstanding verification challenges")
        db.execute("INSERT INTO passkey_challenges VALUES (?,?,?,?,?,?,?,?,0)", (challenge_id, uid, sid, kind, b64(nonce), self.context.fingerprint(request), label, stamp(now()+timedelta(minutes=2))))
        return challenge_id, nonce

    def consume(self, db, challenge_id, request, kind, identity=None):
        row = db.execute("SELECT * FROM passkey_challenges WHERE id=?", (challenge_id,)).fetchone()
        if not row or row["consumed"] or row["expires_at"] <= stamp() or row["kind"] != kind:
            return None
        if identity and (row["user_id"] != identity["user"]["id"] or row["session_id"] != identity["session"]["id"]):
            return None
        db.execute("UPDATE passkey_challenges SET consumed=1 WHERE id=?", (challenge_id,))
        if not hmac.compare_digest(row["fingerprint"], self.context.fingerprint(request)):
            return None
        return row

    def descriptors(self, db, uid):
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor
        return [PublicKeyCredentialDescriptor(id=unb64(row["id"])) for row in db.execute("SELECT id FROM passkeys WHERE user_id=?", (uid,))]

    def assert_passkey(self, db, row, credential):
        key = db.execute("SELECT * FROM passkeys WHERE id=? AND user_id=?", (str(credential.get("id", "")), row["user_id"])).fetchone()
        if not key or credential.get("rawId") != key["id"]:
            return False
        handle = credential.get("response", {}).get("userHandle")
        if handle is not None and not hmac.compare_digest(handle, key["user_handle"]):
            return False
        verified = self.webauthn().verify_authentication_response(credential=credential, expected_challenge=unb64(row["challenge"]), expected_rp_id=self.rp_id, expected_origin=self.origin, credential_public_key=unb64(key["public_key"]), credential_current_sign_count=key["sign_count"], require_user_verification=True)
        db.execute("UPDATE passkeys SET sign_count=?,last_used_at=?,backed_up=? WHERE id=?", (verified.new_sign_count, stamp(), int(verified.credential_backed_up), key["id"]))
        return True


def install_identity(api, authenticated):
    def manager():
        return api.state.identity

    @api.get("/api/auth/security")
    def security(identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        try:
            m.webauthn()
            passkeys_available = True
        except HTTPException:
            passkeys_available = False
        with m.store.connection() as db:
            remaining = db.execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL", (uid,)).fetchone()[0]
            row = m.metadata(identity["session"]["id"], db)
            fresh = bool(row["verified_at"] and row["verified_at"] > stamp(now()-timedelta(minutes=5)) and not row["step_up_required"])
            return {"totp_enabled": m.totp_enabled(uid, db), "passkeys": [dict(row) for row in db.execute("SELECT id,label,created_at,last_used_at FROM passkeys WHERE user_id=?", (uid,))], "recovery_codes_remaining": remaining, "fresh_verification": identity["session"]["fresh_verification"], "enrollment_ready": fresh and (row["verification_method"] in ("totp", "passkey", "recovery") or not m.factor_enrolled(uid, db)), "step_up_required": bool(row["step_up_required"]), "session": identity["session"], "rp_id": m.rp_id, "origin": m.origin, "demo_mode": m.context.demo_mode, "passkeys_available": passkeys_available}

    @api.post("/api/auth/reauth")
    def reauth(body: ReauthInput, request: Request, identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        m.throttle("reauth:" + uid)
        result = None
        with m.store.connection(write=True) as db:
            user = db.execute("SELECT password_hash FROM users WHERE id=?", (uid,)).fetchone()
            if verify_password(body.password, user["password_hash"]):
                factor = m.factor_verify(db, uid, body.code, body.recovery_code) if m.factor_enrolled(uid, db) else "password"
                # A stolen password cannot clear a changed bound context without a factor.
                row = m.metadata(identity["session"]["id"], db)
                if factor and (factor != "password" or not row["step_up_required"]):
                    result = m.fresh(db, identity["session"]["id"], request, factor)
                    m.store.audit(db, "session_reverified", uid, {"method": factor})
            if not result:
                m.failed(db, identity)
        if not result:
            raise HTTPException(401, "Fresh password and enrolled factor verification required")
        return result

    @api.post("/api/auth/step-up")
    def step_up(body: FactorInput, request: Request, identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        m.throttle("factor:" + uid)
        result = None
        with m.store.connection(write=True) as db:
            method = m.factor_verify(db, uid, body.code, body.recovery_code)
            if method:
                result = m.fresh(db, identity["session"]["id"], request, method)
                m.store.audit(db, "session_reverified", uid, {"method": method})
            else:
                m.failed(db, identity)
        if not result:
            raise HTTPException(401, "Verification code invalid or already used")
        return result

    @api.post("/api/auth/totp/enroll")
    def enroll_totp(identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        m.require_recent(identity, require_factor=m.factor_enrolled(uid))
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        enrollment_id, expiry = secrets.token_urlsafe(24), stamp(now()+timedelta(minutes=5))
        with m.store.connection(write=True) as db:
            if m.totp_enabled(uid, db):
                raise HTTPException(409, "An authenticator is already enrolled")
            db.execute("DELETE FROM factor_enrollments WHERE user_id=?", (uid,))
            db.execute("INSERT INTO factor_enrollments VALUES (?,?,?,?,?,0)", (enrollment_id, uid, identity["session"]["id"], m.context.cipher.encrypt(secret.encode()).decode(), expiry))
        uri = "otpauth://totp/" + quote("Adaptive IAM:" + uid, safe="") + "?secret=" + secret + "&issuer=Adaptive%20IAM&algorithm=SHA1&digits=6&period=30"
        return {"enrollment_id": enrollment_id, "secret": secret, "otpauth_uri": uri, "expires_at": expiry}

    @api.post("/api/auth/totp/confirm")
    def confirm_totp(body: EnrollmentConfirm, request: Request, identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        m.throttle("enrollment:" + uid)
        result = None
        with m.store.connection(write=True) as db:
            row = db.execute("SELECT * FROM factor_enrollments WHERE id=? AND user_id=? AND session_id=?", (body.enrollment_id, uid, identity["session"]["id"])).fetchone()
            if row and row["expires_at"] > stamp() and row["attempts"] < 5:
                counter = matching_counter(m.context.cipher.decrypt(row["encrypted_secret"].encode()).decode(), body.code)
                if counter is not None:
                    db.execute("INSERT INTO totp_factors VALUES (?,?,?,?)", (uid, row["encrypted_secret"], counter, stamp()))
                    db.execute("DELETE FROM factor_enrollments WHERE id=?", (row["id"],))
                    m.fresh(db, identity["session"]["id"], request, "totp")
                    m.store.audit(db, "factor_enrolled", uid, {"method": "totp"})
                    result = {"status": "enabled", "recovery_codes": m.recovery(db, uid)}
                else:
                    db.execute("UPDATE factor_enrollments SET attempts=attempts+1 WHERE id=?", (row["id"],))
        if not result:
            raise HTTPException(401, "Enrollment invalid, expired or incorrect code")
        return result

    @api.delete("/api/auth/totp")
    def delete_totp(identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        m.require_recent(identity)
        with m.store.connection(write=True) as db:
            db.execute("DELETE FROM totp_factors WHERE user_id=?", (uid,))
            db.execute("DELETE FROM recovery_codes WHERE user_id=?", (uid,))
            db.execute("DELETE FROM sessions WHERE user_id=? AND id<>?", (uid, identity["session"]["id"]))
            db.execute("UPDATE session_security SET verified_at=NULL,verification_method='password' WHERE session_id=?", (identity["session"]["id"],))
            m.restrict_after_factor_removal(db, uid, identity["session"]["id"])
            m.store.audit(db, "factor_removed", uid, {"method": "totp", "other_sessions_revoked": True})
        return {"status": "disabled"}

    @api.post("/api/auth/recovery/regenerate")
    def recovery_codes(identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        m.require_recent(identity)
        with m.store.connection(write=True) as db:
            if not m.factor_enrolled(uid, db):
                raise HTTPException(409, "Enroll a factor before generating recovery codes")
            codes = m.recovery(db, uid)
            m.store.audit(db, "recovery_codes_regenerated", uid, {"count": len(codes)})
        return {"recovery_codes": codes}

    @api.get("/api/auth/sessions")
    def sessions(identity=Depends(authenticated)):
        with manager().store.connection() as db:
            items = [dict(row) for row in db.execute("SELECT s.id,s.created_at,s.expires_at,ss.last_seen_at,ss.verification_method,ss.step_up_required FROM sessions s LEFT JOIN session_security ss ON s.id=ss.session_id WHERE s.user_id=? AND s.expires_at>? ORDER BY s.created_at DESC LIMIT 50", (identity["user"]["id"], stamp()))]
            for item in items:
                item["current"] = item["id"] == identity["session"]["id"]
                item["step_up_required"] = bool(item["step_up_required"])
            return {"items": items}

    @api.post("/api/auth/sessions/{session_id}/revoke")
    def revoke_session(session_id: str, identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        with m.store.connection(write=True) as db:
            removed = db.execute("DELETE FROM sessions WHERE id=? AND user_id=?", (session_id, uid)).rowcount
            if not removed:
                raise HTTPException(404, "Session not found")
            m.store.audit(db, "session_revoked", uid, {"session_id": session_id})
        return {"status": "revoked"}

    @api.post("/api/auth/passkeys/register/options")
    def register_options(body: PasskeyLabel, request: Request, identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        m.require_recent(identity, require_factor=m.factor_enrolled(uid))
        w = m.webauthn()
        from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement, ResidentKeyRequirement
        with m.store.connection(write=True) as db:
            if db.execute("SELECT COUNT(*) FROM passkeys WHERE user_id=?", (uid,)).fetchone()[0] >= 8:
                raise HTTPException(409, "At most eight passkeys per identity")
            challenge_id, nonce = m.challenge(db, uid, request, "register", identity["session"]["id"], body.label)
            # Pseudonymous stable user handle; no email/raw user ID in authenticator storage.
            handle = hmac.new(m.context.key, uid.encode(), hashlib.sha256).digest()
            options = w.generate_registration_options(rp_id=m.rp_id, rp_name="Adaptive IAM", user_name=uid, user_id=handle, user_display_name=identity["user"]["name"], challenge=nonce, timeout=120000, authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED, resident_key=ResidentKeyRequirement.PREFERRED), exclude_credentials=m.descriptors(db, uid))
        return {"challenge_id": challenge_id, "options": json.loads(w.options_to_json(options))}

    @api.post("/api/auth/passkeys/register/verify")
    def register_verify(body: CeremonyInput, request: Request, identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        m.require_recent(identity, require_factor=m.factor_enrolled(uid))
        w, result = m.webauthn(), None
        with m.store.connection(write=True) as db:
            row = m.consume(db, body.challenge_id, request, "register", identity)
            if row:
                try:
                    verified = w.verify_registration_response(credential=body.credential, expected_challenge=unb64(row["challenge"]), expected_rp_id=m.rp_id, expected_origin=m.origin, require_user_verification=True)
                    key_id, created = b64(verified.credential_id), stamp()
                    handle = b64(hmac.new(m.context.key, uid.encode(), hashlib.sha256).digest())
                    db.execute("INSERT INTO passkeys VALUES (?,?,?,?,?,?,?,?,?)", (key_id, uid, b64(verified.credential_public_key), verified.sign_count, handle, row["label"], created, None, int(verified.credential_backed_up)))
                    m.fresh(db, identity["session"]["id"], request, "passkey")
                    m.store.audit(db, "factor_enrolled", uid, {"method": "passkey"})
                    result = {"id": key_id, "label": row["label"], "created_at": created, "last_used_at": None}
                except Exception:
                    m.store.audit(db, "passkey_verification_failed", uid, {"operation": "register", "action": "deny"})
        if not result:
            raise HTTPException(401, "Passkey registration invalid or challenge already consumed")
        return result

    @api.delete("/api/auth/passkeys/{key_id}")
    def delete_passkey(key_id: str, identity=Depends(authenticated)):
        m, uid = manager(), identity["user"]["id"]
        m.require_recent(identity)
        with m.store.connection(write=True) as db:
            if not db.execute("DELETE FROM passkeys WHERE id=? AND user_id=?", (key_id, uid)).rowcount:
                raise HTTPException(404, "Passkey not found")
            if not m.factor_enrolled(uid, db):
                db.execute("DELETE FROM recovery_codes WHERE user_id=?", (uid,))
            db.execute("DELETE FROM sessions WHERE user_id=? AND id<>?", (uid, identity["session"]["id"]))
            db.execute("UPDATE session_security SET verified_at=NULL,verification_method='password' WHERE session_id=?", (identity["session"]["id"],))
            m.restrict_after_factor_removal(db, uid, identity["session"]["id"])
            m.store.audit(db, "factor_removed", uid, {"method": "passkey", "other_sessions_revoked": True})
        return {"status": "removed"}

    def authentication_options(uid, request, kind, sid=None):
        m, w = manager(), manager().webauthn()
        m.throttle("passkey-options:" + m.context.fingerprint(request), 30)
        from webauthn.helpers.structs import UserVerificationRequirement
        with m.store.connection(write=True) as db:
            if not db.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone():
                raise HTTPException(401, "No passkey available for this identity")
            descriptors = m.descriptors(db, uid)
            if not descriptors:
                raise HTTPException(401, "No passkey available for this identity")
            challenge_id, nonce = m.challenge(db, uid, request, kind, sid)
            options = w.generate_authentication_options(rp_id=m.rp_id, challenge=nonce, allow_credentials=descriptors, timeout=120000, user_verification=UserVerificationRequirement.REQUIRED)
        return {"challenge_id": challenge_id, "options": json.loads(w.options_to_json(options))}

    @api.post("/api/auth/passkeys/login/options")
    def login_options(body: PasskeyLogin, request: Request):
        return authentication_options(body.user_id, request, "login")

    @api.post("/api/auth/passkeys/step-up/options")
    def step_options(request: Request, identity=Depends(authenticated)):
        return authentication_options(identity["user"]["id"], request, "step_up", identity["session"]["id"])

    def authentication_verify(body, request, kind, identity=None):
        m, result = manager(), None
        m.webauthn()
        m.throttle("passkey-verify:" + m.context.fingerprint(request), 30)
        with m.store.connection(write=True) as db:
            row = m.consume(db, body.challenge_id, request, kind, identity)
            verified = False
            if row:
                try:
                    verified = m.assert_passkey(db, row, body.credential)
                except Exception:
                    verified = False
            if verified:
                if kind == "step_up":
                    result = m.fresh(db, identity["session"]["id"], request, "passkey")
                else:
                    context = api.state.identity_context(request, row["user_id"], db)
                    risk = api.state.risk.assess(context)
                    risk.update({"context": context, "context_source": "server_request_observed"})
                    if risk["tier"] == "high":
                        result = {"status": "blocked", "risk": risk, "message": "Authentication policy denied high risk"}
                    else:
                        result = m.store.make_session(db, row["user_id"], risk)
                        m.bind_session(db, result, request, "passkey")
                m.store.audit(db, "passkey_authenticated", row["user_id"], {"operation": kind})
            else:
                if identity:
                    m.failed(db, identity)
                elif row:
                    m.store.audit(db, "passkey_verification_failed", row["user_id"], {"operation": kind, "action": "deny"})
        if not result:
            raise HTTPException(401, "Passkey assertion invalid or challenge already consumed")
        return result

    @api.post("/api/auth/passkeys/login/verify")
    def login_verify(body: CeremonyInput, request: Request):
        return authentication_verify(body, request, "login")

    @api.post("/api/auth/passkeys/step-up/verify")
    def step_verify(body: CeremonyInput, request: Request, identity=Depends(authenticated)):
        return authentication_verify(body, request, "step_up", identity)
