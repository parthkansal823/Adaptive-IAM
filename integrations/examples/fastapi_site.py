"""Own-site OAuth/OIDC integration example. Tokens stay in server process memory."""
from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from integrations.python.adaptive_iam import AdaptiveIamClient, IamError, transaction, validate_url

LOCAL = os.getenv("IAM_ALLOW_LOCAL_HTTP") == "1"
SITE = validate_url(os.getenv("SITE_ORIGIN", "http://127.0.0.1:3001"), LOCAL).rstrip("/")
SECURE = urlparse(SITE).scheme == "https"
client = AdaptiveIamClient(issuer=os.getenv("IAM_ISSUER", "http://127.0.0.1:8000"), client_id=os.environ["IAM_CLIENT_ID"], client_secret=os.getenv("IAM_CLIENT_SECRET", ""), redirect_uri=SITE+"/callback", allow_local_http=LOCAL)
app = FastAPI(title="Adaptive IAM connected website")
flows, sessions = {}, {}
lock = threading.Lock()


@app.exception_handler(IamError)
async def iam_failure(_request, error):
    return JSONResponse({"error": error.code}, status_code=error.status, headers={"Cache-Control": "no-store"})


def set_cookie(response, name, value, age):
    response.set_cookie(name, value, max_age=age, httponly=True, secure=SECURE, samesite="lax", path="/")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"


def cleanup():
    for key, value in list(flows.items()):
        if value["expires_at"] <= time.time():
            del flows[key]
    for key, value in list(sessions.items()):
        if value.expires_at <= time.time():
            del sessions[key]


@app.get("/login")
def login():
    flow = {**transaction(), "expires_at": time.time()+300}
    key = secrets.token_urlsafe(32)
    with lock:
        cleanup()
        if len(flows) >= 256:
            raise IamError("login_capacity_reached", 429)
        flows[key] = flow
    response = RedirectResponse(client.authorization_url(flow), status_code=303)
    set_cookie(response, "iam_login", key, 300)
    return response


@app.get("/callback")
def callback(request: Request):
    with lock:
        flow = flows.pop(request.cookies.get("iam_login"), None)
    state = request.query_params.get("state", "")
    if any(len(request.query_params.getlist(name)) > 1 for name in ("state", "iss", "code", "error")):
        raise IamError("invalid_callback_parameters", 401)
    if not flow or flow["expires_at"] <= time.time() or not hmac.compare_digest(flow["state"].encode(), state.encode()):
        raise IamError("invalid_login_state", 401)
    if request.query_params.get("iss") != client.issuer:
        raise IamError("callback_issuer_mismatch", 401)
    if "error" in request.query_params:
        raise IamError("login_not_approved", 401)
    session = client.exchange_code(code=request.query_params.get("code", ""), verifier=flow["verifier"], nonce=flow["nonce"])
    key = secrets.token_urlsafe(32)
    with lock:
        cleanup()
        if len(sessions) >= 1024:
            raise IamError("session_capacity_reached")
        sessions[key] = session
    response = RedirectResponse("/", status_code=303)
    set_cookie(response, "iam_site_session", key, max(1, int(session.expires_at-time.time())))
    set_cookie(response, "iam_login", "", 0)
    return response


@app.get("/protected")
def protected(request: Request):
    key = request.cookies.get("iam_site_session")
    with lock:
        cleanup()
        session = sessions.get(key)
    if not session:
        raise IamError("login_required", 401)
    access = client.permission(session, "research-vault")
    # A logout or expiry during the provider call removes local authority too.
    with lock:
        cleanup()
        if sessions.get(key) is not session:
            raise IamError("login_required", 401)
        try:
            expiry = datetime.fromisoformat(access["expires_at"].replace("Z", "+00:00"))
            if expiry.tzinfo is None or expiry.timestamp() <= time.time():
                raise ValueError("expiry")
        except (KeyError, AttributeError, TypeError, ValueError, OverflowError):
            raise IamError("grant_expired_or_invalid", 403) from None
    return JSONResponse({"message": "Your site returned this record after an IAM permission check.", "user": access["identity"]["sub"], "resource": access["resource_id"]}, headers={"Cache-Control": "no-store"})


@app.post("/logout")
def logout(request: Request):
    if request.headers.get("origin") != SITE:
        raise IamError("invalid_origin", 403)
    with lock:
        session = sessions.pop(request.cookies.get("iam_site_session"), None)
    if session:
        try:
            client.revoke(session)
        except IamError:
            pass  # Local session was removed even if the provider is unavailable.
    response = RedirectResponse("/", status_code=303)
    set_cookie(response, "iam_site_session", "", 0)
    return response


@app.get("/")
def index():
    return HTMLResponse('<!doctype html><html lang="en"><meta charset="utf-8"><title>Connected website</title><h1>Your website, connected.</h1><p><a href="/login">Sign in with Adaptive IAM</a></p><p><a href="/protected">Open protected research page</a></p><p>Identity sign-in and resource access are separate decisions.</p><form method="post" action="/logout"><button>Sign out</button></form></html>', headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
