"""Offline Adaptive IAM research API. Run from root: uvicorn backend.app.main:app."""
from __future__ import annotations

import copy
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .models import AssessmentInput, LoginInput, RequestInput, VerifyInput, VoteInput
from .blockchain import BlockchainMirror, install_blockchain
from .audit_proofs import install_audit_proofs
from .identity import IdentitySecurity, install_identity
from .developer import DeveloperPortal, install_developer
from .lab import install_lab
from .nlp import JustificationEngine
from .oauth import OAuthProvider, install_oauth
from .reviewers import ReviewerSelector
from .research import install_research
from .risk import RiskEngine
from .store import PASSWORD, Store, canonical, hash_password, now, secret_hash, stamp, verify_password

BACKEND_ROOT = Path(__file__).resolve().parents[1]
bearer = HTTPBearer(auto_error=False)


def create_app(data_dir: Path | None = None, model_cache: Path | None = None):
    data_dir = Path(data_dir or os.getenv("IAM_DATA_DIR", str(BACKEND_ROOT / "data")))
    model_cache = model_cache or BACKEND_ROOT / "artifacts" / "risk-v1.joblib"

    @asynccontextmanager
    async def lifespan(application):
        application.state.store = Store(data_dir / "iam.sqlite3")
        application.state.risk = RiskEngine(model_cache)
        application.state.nlp = JustificationEngine()
        application.state.reviewers = ReviewerSelector()
        application.state.oauth = OAuthProvider(application.state.store, data_dir)
        application.state.identity = IdentitySecurity(application.state.store, data_dir)
        application.state.developer = DeveloperPortal(application.state.store)
        application.state.blockchain = BlockchainMirror(application.state.store, data_dir)
        yield

    api = FastAPI(title="Adaptive IAM research API", version="1.0.0", lifespan=lifespan)
    install_research(api)
    rate_state, rate_lock = defaultdict(deque), threading.Lock()
    # In-process isolated test fixtures can reset this limiter; no HTTP access exposes it.
    api.state.login_rate_state = rate_state

    def authenticated(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if not credentials or credentials.scheme.lower() != "bearer":
            raise HTTPException(401, "A valid session is required")
        identity = request.app.state.store.session(credentials.credentials)
        return request.app.state.identity.guard(identity, request)

    @api.middleware("http")
    async def private_auth_responses(request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/auth/") or request.url.path == "/api/bootstrap":
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    def identity_context(request, user_id, db):
        # Secure mode uses observed request and stored event features, not browser claims.
        fingerprint = api.state.identity.context.fingerprint(request)
        known = bool(db.execute("SELECT 1 FROM session_security ss JOIN sessions s ON ss.session_id=s.id WHERE s.user_id=? AND ss.fingerprint=? LIMIT 1", (user_id, fingerprint)).fetchone())
        velocity = db.execute("SELECT COUNT(*) FROM sessions WHERE user_id=? AND created_at>?", (user_id, stamp(now()-timedelta(minutes=10)))).fetchone()[0]
        failure = db.execute("SELECT count,window_started FROM auth_failures WHERE user_id=?", (user_id,)).fetchone()
        failures = failure["count"] if failure and failure["window_started"] > stamp(now()-timedelta(minutes=15)) else 0
        return {"known_device": known, "known_location": True, "vpn": False, "failed_attempts": min(20, failures), "hour": now().hour, "login_velocity": min(30, max(1, velocity)), "account_age_days": 365, "travel_distance_km": 0, "sensitivity": 0.5, "prior_risk": 0.1}

    api.state.identity_context = identity_context

    def capabilities():
        selector = api.state.reviewers
        chain = api.state.blockchain.status()
        return {"demo_mode": api.state.identity.context.demo_mode, "passkeys": True, "totp": True, "continuous_session_checks": True, "risk_model": "calibrated_lr_random_forest", "nlp": "tfidf_naive_bayes", "bert_available": bool(api.state.nlp.bert), "llm_available": selector.enabled, "llm_engine": "ollama_optional" if selector.enabled else "deterministic_policy", "llm_calls_used": selector.calls, "llm_call_budget": selector.max_calls, "ledger": "local_sha256_hash_chain", "blockchain": chain["ready"], "web3": {key: chain[key] for key in ("enabled", "connected", "ready", "chain_id", "contract_address", "error")}, "distributed_blockchain": False, "human_approval_required": True, "context_source": "client_simulated_research_only" if api.state.identity.context.demo_mode else "server_request_observed_partial_features"}

    def visible_requests(db, identity):
        actor, role = identity["user"]["id"], identity["user"]["role"]
        packets = [api.state.store.request_dto(db, row["id"], actor) for row in db.execute("SELECT id FROM requests ORDER BY created_at DESC").fetchall()]
        return [p for p in packets if role == "security_reviewer" or p["requester_id"] == actor or actor in {r["id"] for r in p["reviewers"]}]

    def visible_grants(db, identity):
        actor, role = identity["user"]["id"], identity["user"]["role"]
        rows = db.execute("SELECT g.*,u.name user_name,r.name resource_name,r.owner_id FROM grants g JOIN users u ON g.user_id=u.id JOIN resources r ON g.resource_id=r.id ORDER BY g.created_at DESC").fetchall()
        return [{**{k: v for k, v in dict(r).items() if k != "owner_id"}, "blockchain": api.state.blockchain.grant_status(db, r["id"])} for r in rows if role == "security_reviewer" or r["user_id"] == actor or r["owner_id"] == actor]

    def visible_audit(db, identity, limit=200):
        events = api.state.store.audit_dtos(db, 1000)
        if identity["user"]["role"] != "security_reviewer":
            related = {p["id"] for p in visible_requests(db, identity)}
            actor = identity["user"]["id"]
            events = [e for e in events if e["actor_id"] == actor or e["payload"].get("user_id") == actor or e["payload"].get("request_id") in related or e["event_type"] == "system_initialized"]
        return events[:limit]

    @api.get("/api/health")
    def health():
        return {"status": "ok", "ready": True, "version": "1.0.0", "demo_mode": api.state.identity.context.demo_mode, "model_version": api.state.risk.version}

    @api.get("/api/bootstrap")
    def bootstrap():
        with api.state.store.connection() as db:
            return {"demo_mode": api.state.identity.context.demo_mode, "notice": "Research prototype with public synthetic demo credentials" if api.state.identity.context.demo_mode else "Server-observed context; operator-provisioned identities and verified factors", "users": [{**user, "password": PASSWORD} for user in api.state.store.users(db)] if api.state.identity.context.demo_mode else [], "resources": api.state.store.resources(db), "reviewer_weights": {"owner": 1.5, "peer": 1}, "risk_thresholds": {"low": round(api.state.risk.low_threshold, 6), "high": api.state.risk.high_threshold}, "capabilities": capabilities()}

    @api.post("/api/risk/assess")
    def assess(body: AssessmentInput):
        return api.state.risk.assess(body.context.model_dump())

    @api.post("/api/auth/login")
    def login(body: LoginInput, request: Request):
        client = request.client.host if request.client else "unknown"
        current_time = time.monotonic()
        with rate_lock:
            if client not in rate_state and len(rate_state) >= 1024:
                rate_state.pop(next(iter(rate_state)))
            calls = rate_state[client]
            while calls and calls[0] < current_time-60:
                calls.popleft()
            if len(calls) >= 30:
                raise HTTPException(429, "Too many login attempts; try again in a minute")
            calls.append(current_time)
        store = api.state.store
        rejection = None
        result = None
        with store.connection(write=True) as db:
            row = db.execute("SELECT * FROM users WHERE id=?", (body.user_id,)).fetchone()
            failure = db.execute("SELECT * FROM auth_failures WHERE user_id=?", (body.user_id,)).fetchone()
            current = stamp()
            if failure and failure["locked_until"] and failure["locked_until"] > current:
                rejection = (429, "Account temporarily locked after failed authentication; wait 15 minutes")
                store.audit(db, "login_locked", body.user_id, {"action": "deny"})
            else:
                correct = verify_password(body.password, row["password_hash"] if row else store.dummy_password)
                demo_mode = api.state.identity.context.demo_mode
                if not correct or not row or (not demo_mode and secrets.compare_digest(body.password.encode(), PASSWORD.encode())):
                    if row:
                        count = failure["count"]+1 if failure and failure["window_started"] > stamp(now()-timedelta(minutes=15)) else 1
                        start = failure["window_started"] if failure and count > 1 else current
                        locked = stamp(now()+timedelta(minutes=15)) if count >= 5 else None
                        db.execute("INSERT INTO auth_failures VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET count=excluded.count,window_started=excluded.window_started,locked_until=excluded.locked_until", (body.user_id, count, start, locked))
                    store.audit(db, "login_failed", body.user_id if row else None, {"action": "deny", "reason": "invalid_credentials"})
                    rejection = (401, "Invalid credentials")
                else:
                    context = body.context.model_dump() if demo_mode else identity_context(request, body.user_id, db)
                    # Simulation can increase risk, but cannot hide server-observed failures.
                    server_failures = failure["count"] if failure and failure["window_started"] > stamp(now()-timedelta(minutes=15)) else 0
                    context["failed_attempts"] = min(20, max(context["failed_attempts"], server_failures))
                    risk = api.state.risk.assess(context)
                    risk["context"] = context
                    risk["context_source"] = "client_simulated_with_server_failure_floor" if demo_mode else "server_request_observed_partial_features"
                    if not demo_mode:
                        risk["unavailable_features"] = ["geolocation", "vpn_detection", "travel_distance", "verified_device_identity", "account_age", "behavioral_prior"]
                    db.execute("DELETE FROM auth_failures WHERE user_id=?", (body.user_id,))
                    store.audit(db, "login_assessed", body.user_id, {"tier": risk["tier"], "risk_score": risk["score"], "action": risk["action"], "server_failures": server_failures})
                    if risk["tier"] == "high":
                        result = {"status": "blocked", "risk": risk, "message": "High-risk authentication denied. Choose a trusted context to try again."}
                    elif not demo_mode and not api.state.identity.factor_enrolled(body.user_id, db):
                        # A private operator-provisioned password starts only a short,
                        # restricted enrollment ceremony. It grants no app/resource authority.
                        result = store.make_session(db, body.user_id, risk)
                        api.state.identity.bind_session(db, result, request, "password")
                        store.audit(db, "factor_enrollment_session_started", body.user_id, {"scope": "factor_enrollment", "session_expires_at": result["expires_at"]})
                    elif risk["tier"] == "medium" or api.state.identity.factor_enrolled(body.user_id, db):
                        enrolled = api.state.identity.factor_enrolled(body.user_id, db)
                        if not enrolled and not demo_mode:
                            rejection = (403, {"code": "factor_enrollment_required", "message": "Enroll a passkey or authenticator from an existing trusted session before this login"})
                            continue_login = False
                        else:
                            continue_login = True
                        challenge_id, code = secrets.token_urlsafe(24), f"{secrets.randbelow(1000000):06d}"
                        expiry = stamp(now()+timedelta(seconds=120))
                        if continue_login:
                            method = "factor" if enrolled else "demo"
                            db.execute("DELETE FROM challenges WHERE expires_at<=? OR (user_id=? AND consumed=0)", (current, body.user_id))
                            db.execute("INSERT INTO challenges (id,user_id,code_hash,created_at,expires_at,risk_json,fingerprint,method) VALUES (?,?,?,?,?,?,?,?)", (challenge_id, body.user_id, secret_hash(challenge_id+":"+code), current, expiry, canonical(risk), api.state.identity.context.fingerprint(request), method))
                            store.audit(db, "mfa_issued", body.user_id, {"expires_at": expiry, "delivery": "enrolled_factor" if enrolled else "demo_ui_only"})
                            methods = []
                            if enrolled:
                                if api.state.identity.totp_enabled(body.user_id, db):
                                    methods.append("totp")
                                if db.execute("SELECT 1 FROM passkeys WHERE user_id=? LIMIT 1", (body.user_id,)).fetchone():
                                    methods.append("passkey")
                                if db.execute("SELECT 1 FROM recovery_codes WHERE user_id=? AND used_at IS NULL LIMIT 1", (body.user_id,)).fetchone():
                                    methods.append("recovery")
                            else:
                                methods = ["demo"]
                            result = {"status": "mfa_required", "risk": risk, "challenge_id": challenge_id, "expires_at": expiry, "methods": methods, "message": "Verify your enrolled authenticator or use passkey sign-in" if enrolled else "Research demo code only"}
                            if not enrolled:
                                result["demo_code"] = code
                    else:
                        result = store.make_session(db, body.user_id, risk)
                        api.state.identity.bind_session(db, result, request, "password")
                        store.audit(db, "login_authenticated", body.user_id, {"tier": risk["tier"], "method": "password", "session_expires_at": result["expires_at"]})
        if rejection:
            raise HTTPException(*rejection)
        return result

    @api.post("/api/auth/verify")
    def verify(body: VerifyInput, request: Request):
        store = api.state.store
        api.state.identity.throttle("login-factor:" + api.state.identity.context.fingerprint(request), 30)
        rejection, result = None, None
        with store.connection(write=True) as db:
            row = db.execute("SELECT * FROM challenges WHERE id=?", (body.challenge_id,)).fetchone()
            if not row or row["consumed"] or row["expires_at"] <= stamp() or row["attempts"] >= 5 or row["method"] == "legacy":
                rejection = (401, "MFA challenge invalid, expired or already used")
            else:
                import hmac
                same_context = hmac.compare_digest(row["fingerprint"], api.state.identity.context.fingerprint(request))
                method = None
                if same_context and row["method"] == "factor":
                    method = api.state.identity.factor_verify(db, row["user_id"], body.code, body.recovery_code)
                elif same_context and row["method"] == "demo" and api.state.identity.context.demo_mode and body.code and not body.recovery_code:
                    if hmac.compare_digest(secret_hash(body.challenge_id+":"+body.code), row["code_hash"]):
                        method = "demo_mfa"
                if not method:
                    db.execute("UPDATE challenges SET attempts=attempts+1,consumed=CASE WHEN attempts+1>=5 THEN 1 ELSE 0 END WHERE id=?", (body.challenge_id,))
                    store.audit(db, "mfa_failed", row["user_id"], {"action": "deny"})
                    rejection = (401, "Incorrect MFA code")
                else:
                    db.execute("UPDATE challenges SET consumed=1 WHERE id=?", (body.challenge_id,))
                    risk = json.loads(row["risk_json"])
                    result = store.make_session(db, row["user_id"], risk)
                    api.state.identity.bind_session(db, result, request, method)
                    store.audit(db, "login_authenticated", row["user_id"], {"tier": risk["tier"], "method": method, "session_expires_at": result["expires_at"]})
        if rejection:
            raise HTTPException(*rejection)
        return result

    @api.get("/api/auth/me")
    def me(identity=Depends(authenticated)):
        return identity

    @api.post("/api/auth/logout")
    def logout(identity=Depends(authenticated)):
        store = api.state.store
        with store.connection(write=True) as db:
            db.execute("DELETE FROM sessions WHERE id=?", (identity["session"]["id"],))
            store.audit(db, "session_ended", identity["user"]["id"], {"action": "logout"})
        return {"status": "logged_out"}

    @api.get("/api/overview")
    def overview(identity=Depends(authenticated)):
        store, actor = api.state.store, identity["user"]["id"]
        with store.connection(write=True) as db:
            store.expire(db)
            requests = visible_requests(db, identity)
            events = visible_audit(db, identity, 1000)
            distribution = {"low": 0, "medium": 0, "high": 0}
            for event in events:
                if event["event_type"] != "login_assessed":
                    continue
                tier = event["payload"].get("tier")
                if tier in distribution:
                    distribution[tier] += 1
            review_queue = sum(p["can_vote"] for p in requests)
            stats = {"pending_requests": sum(p["status"] == "pending" for p in requests), "active_grants": sum(g["status"] == "active" for g in visible_grants(db, identity)), "audit_events": len(events), "review_queue": review_queue, "authentication_events": sum(distribution.values())}
            return {"stats": stats, "risk_distribution": distribution, "recent_events": events[:6], "recent_requests": requests[:5], "model": {"name": "Calibrated LR / Random Forest", "version": api.state.risk.version, "synthetic": True}, "capabilities": capabilities()}

    @api.get("/api/requests")
    def list_requests(identity=Depends(authenticated)):
        store = api.state.store
        with store.connection(write=True) as db:
            store.expire(db)
            return {"items": visible_requests(db, identity)}

    @api.post("/api/requests", status_code=201)
    def create_request(body: RequestInput, identity=Depends(authenticated)):
        store, actor = api.state.store, identity["user"]
        # Justification is excluded from LLM prompts; it is untrusted classifier data.
        with store.connection() as db:
            resource_row = db.execute("SELECT * FROM resources WHERE id=?", (body.resource_id,)).fetchone()
            if not resource_row:
                raise HTTPException(404, "Resource not found")
            resource = dict(resource_row)
            users = store.users(db)
        if body.duration_hours > resource["max_duration_hours"]:
            raise HTTPException(422, f"This resource permits at most {resource['max_duration_hours']:g} hours")
        if resource["owner_id"] == actor["id"]:
            raise HTTPException(409, "Owner cannot review their own request; use a separate requester identity in this demo")
        reviewers, selection = api.state.reviewers.select(actor, resource, users)
        eligible = {u["id"]: u for u in users}
        reviewer_packet = [{"id": rid, "name": eligible[rid]["name"], "weight": 1.5 if rid == resource["owner_id"] else 1, "is_owner": rid == resource["owner_id"]} for rid in reviewers]
        nlp = api.state.nlp.assess(body.justification)
        risk_context = dict(identity["risk"].get("context", {}))
        risk_context["sensitivity"] = {"internal": .3, "confidential": .7, "restricted": 1}[resource["sensitivity"]]
        request_risk = api.state.risk.assess(risk_context)
        request_risk["context_source"] = "login_context_plus_server_resource_sensitivity"
        request_id = secrets.token_hex(10)
        with store.connection(write=True) as db:
            store.expire(db)
            duplicates = db.execute("SELECT COUNT(*) FROM requests WHERE requester_id=? AND status='pending'", (actor["id"],)).fetchone()[0]
            if duplicates >= 10:
                raise HTTPException(429, "At most 10 pending requests per requester")
            created, expiry = stamp(), stamp(now()+timedelta(hours=48))
            db.execute("INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (request_id, actor["id"], body.resource_id, body.justification, body.duration_hours, "pending", created, expiry, canonical(request_risk), canonical(nlp), canonical(reviewer_packet), canonical(selection)))
            store.audit(db, "request_created", actor["id"], {"request_id": request_id, "resource_id": body.resource_id, "duration_hours": body.duration_hours, "nlp_label": nlp["label"], "reviewer_engine": selection["engine"], "reviewer_ids": reviewers})
            return store.request_dto(db, request_id, actor["id"])

    @api.post("/api/requests/{request_id}/votes")
    def vote(request_id: str, body: VoteInput, identity=Depends(authenticated)):
        store, actor = api.state.store, identity["user"]["id"]
        rejection, result = None, None
        with store.connection(write=True) as db:
            store.expire(db)
            packet = store.request_dto(db, request_id, actor)
            reviewer = next((r for r in packet["reviewers"] if r["id"] == actor), None)
            if actor == packet["requester_id"] or not reviewer:
                rejection = (403, "Only selected reviewers may vote; requester cannot vote")
            elif packet["status"] != "pending":
                rejection = (409, "Request is already terminal or expired")
            elif any(v["reviewer_id"] == actor for v in packet["votes"]):
                rejection = (409, "Each reviewer can vote once")
            else:
                db.execute("INSERT INTO votes VALUES (?,?,?,?,?,?)", (request_id, actor, int(body.approve), reviewer["weight"], body.comment, stamp()))
                store.audit(db, "reviewer_voted", actor, {"request_id": request_id, "approve": body.approve, "weight": reviewer["weight"]})
                packet = store.request_dto(db, request_id, actor)
                owners = {r["id"] for r in packet["reviewers"] if r["is_owner"]}
                owner_denied = any(v["reviewer_id"] in owners and not v["approve"] for v in packet["votes"])
                owner_approved = any(v["reviewer_id"] in owners and v["approve"] for v in packet["votes"])
                consensus = packet["consensus"]
                all_voted = len(packet["votes"]) == len(packet["reviewers"])
                if owner_denied:
                    db.execute("UPDATE requests SET status='denied' WHERE id=?", (request_id,))
                    store.audit(db, "request_denied", actor, {"request_id": request_id, "reason": "resource_owner_veto"})
                elif consensus["quorum_reached"] and owner_approved and consensus["approval_weight"] > .5*consensus["total_weight"]:
                    db.execute("UPDATE requests SET status='approved' WHERE id=?", (request_id,))
                    grant_id, expiry = secrets.token_hex(10), stamp(now()+timedelta(hours=packet["duration_hours"]))
                    db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?,?)", (grant_id, request_id, packet["requester_id"], packet["resource_id"], "read", stamp(), expiry, "active"))
                    db.execute("INSERT OR IGNORE INTO blockchain_outbox (kind,local_id,status,updated_at) VALUES ('grant',?,'pending',?)", (grant_id, stamp()))
                    store.audit(db, "grant_created", actor, {"request_id": request_id, "grant_id": grant_id, "user_id": packet["requester_id"], "resource_id": packet["resource_id"], "scope": "read", "expires_at": expiry})
                elif all_voted:
                    db.execute("UPDATE requests SET status='denied' WHERE id=?", (request_id,))
                    store.audit(db, "request_denied", actor, {"request_id": request_id, "reason": "weighted_majority_not_reached"})
                result = store.request_dto(db, request_id, actor)
        if rejection:
            raise HTTPException(*rejection)
        if result and result["status"] == "approved" and api.state.blockchain.enabled:
            result["blockchain_sync"] = api.state.blockchain.sync()
        return result

    @api.get("/api/grants")
    def grants(identity=Depends(authenticated)):
        store = api.state.store
        with store.connection(write=True) as db:
            store.expire(db)
            return {"items": visible_grants(db, identity)}

    @api.get("/api/resources/{resource_id}/access")
    def access(resource_id: str, identity=Depends(authenticated)):
        store, actor = api.state.store, identity["user"]["id"]
        with store.connection(write=True) as db:
            store.expire(db)
            resource = db.execute("SELECT * FROM resources WHERE id=?", (resource_id,)).fetchone()
            if not resource:
                raise HTTPException(404, "Resource not found")
            grant, chain = store.active_grant(db, actor, resource_id, api.state.blockchain)
            allowed = bool(grant) and chain["allowed"]
            store.audit(db, "resource_access_checked", actor, {"resource_id": resource_id, "allowed": allowed, "grant_id": grant["id"] if grant else None, "chain_required": chain["required"], "chain_status": chain["status"]})
            return {"allowed": allowed, "resource_id": resource_id, "resource_name": resource["name"], "scope": "read" if allowed else None, "expires_at": grant["expires_at"] if allowed else None, "reason": "Active identity-bound read grant confirmed by configured policy" if allowed else chain.get("reason", "No active read grant for this authenticated identity"), "blockchain": chain, "content": {"title": resource["name"], "records": ["Synthetic research record: access is checked on the server.", "This demo resource contains no production or personal data."]} if allowed else None}

    @api.get("/api/audit")
    def audit(identity=Depends(authenticated)):
        store = api.state.store
        with store.connection(write=True) as db:
            store.expire(db)
            return {"items": visible_audit(db, identity), "ledger_type": "local_sha256_hash_chain", "visibility": "security_role_full_ledger_others_own_and_related_requests"}

    @api.get("/api/audit/verify")
    def verify_ledger(identity=Depends(authenticated)):
        return {**api.state.store.verify_audit(), "blockchain": api.state.blockchain.status()}

    @api.get("/api/evaluation")
    def evaluation():
        report = copy.deepcopy(api.state.risk.report)
        report["nlp"] = api.state.nlp.report
        report["generated_at"] = stamp()
        report["model_version"] = api.state.risk.version
        return report

    install_oauth(api, authenticated, data_dir)
    install_identity(api, authenticated)
    install_developer(api, authenticated)
    install_lab(api, authenticated)
    install_blockchain(api, authenticated)
    install_audit_proofs(api, authenticated)
    return api


app = create_app()
