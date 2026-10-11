"""Exercise a running loopback demo through the real Python relying-party SDK.

Run from the project root: python -m integrations.tests.smoke_oidc
Creates a disabled-after-test app and synthetic human-approved read grant. Never
prints tokens, authorization codes, client secrets or OTPs. No production target.
"""
from __future__ import annotations

import hmac
import secrets
from urllib.parse import parse_qs, urlsplit

import httpx

from integrations.python.adaptive_iam import AdaptiveIamClient, IamError, transaction

ISSUER = "http://127.0.0.1:8000"
CALLBACK = "http://127.0.0.1:3001/callback"
RESOURCE = "research-vault"


def checked(response, expected=200):
    if response.status_code != expected:
        raise RuntimeError(f"Unexpected HTTP status {response.status_code}; expected {expected}")
    return response.json()


def main():
    app_id = None
    tokens = {}
    checks = []
    with httpx.Client(base_url=ISSUER, timeout=30, follow_redirects=False) as api:
        bootstrap = checked(api.get("/api/bootstrap"))
        if bootstrap.get("demo_mode") is not True:
            raise RuntimeError("Smoke test requires the public synthetic loopback demo")
        for user in ("aisha", "meera", "kavya", "vihaan", "rohan"):
            login = checked(api.post("/api/auth/login", json={"user_id": user, "password": "Demo@123!", "context": {}}))
            if login.get("status") == "mfa_required":
                login = checked(api.post("/api/auth/verify", json={"challenge_id": login["challenge_id"], "code": login["demo_code"]}))
            if not isinstance(login.get("token"), str):
                raise RuntimeError("Synthetic demo login was denied")
            tokens[user] = login["token"]

        def headers(user="aisha"):
            return {"Authorization": "Bearer "+tokens[user]}

        try:
            registered = checked(api.post("/api/apps", headers=headers("kavya"), json={"name": "SDK smoke "+secrets.token_hex(4), "redirect_uris": [CALLBACK], "client_type": "confidential", "resource_ids": [RESOURCE]}), 201)
            app_id = registered["client_id"]
            sdk = AdaptiveIamClient(issuer=ISSUER, client_id=app_id, client_secret=registered["client_secret"], redirect_uri=CALLBACK, allow_local_http=True, timeout=15)

            def authenticate():
                flow = transaction()
                authorization = api.get(sdk.authorization_url(flow))
                if authorization.status_code != 302:
                    raise RuntimeError("Authorization did not redirect to hosted consent")
                request_id = parse_qs(urlsplit(authorization.headers["location"]).query)["request_id"][0]
                packet = checked(api.get("/api/oauth/authorization/"+request_id))
                if packet["app"]["client_id"] != app_id:
                    raise RuntimeError("Consent app mismatch")
                consent = checked(api.post("/api/oauth/consent", headers=headers(), json={"request_id": request_id, "approve": True}))
                callback = urlsplit(consent["redirect_to"])
                query = parse_qs(callback.query)
                if callback.scheme+"://"+callback.netloc+callback.path != CALLBACK or query.get("iss") != [ISSUER] or not hmac.compare_digest(query.get("state", [""])[0], flow["state"]):
                    raise RuntimeError("Callback issuer/state/URL mismatch")
                session = sdk.exchange_code(code=query["code"][0], verifier=flow["verifier"], nonce=flow["nonce"])
                if session.identity.get("sub") != "aisha":
                    raise RuntimeError("Verified identity mismatch")
                return session

            before = checked(api.get("/api/grants", headers=headers()))["items"]
            session = authenticate()
            after = checked(api.get("/api/grants", headers=headers()))["items"]
            if {g["id"] for g in before} != {g["id"] for g in after}:
                raise RuntimeError("Identity consent unexpectedly created a grant")
            checks.extend(["confidential code+PKCE", "RS256 issuer/audience/nonce verification", "consent creates no grant"])

            request = checked(api.post("/api/requests", headers=headers(), json={"resource_id": RESOURCE, "justification": "Scoped read access for synthetic SDK smoke audit evidence IAM-42, approved by the resource owner.", "duration_hours": 1}), 201)
            reviewers = sorted(request["reviewers"], key=lambda reviewer: not reviewer["is_owner"])
            for reviewer in reviewers:
                result = checked(api.post("/api/requests/"+request["id"]+"/votes", headers=headers(reviewer["id"]), json={"approve": True, "comment": "Synthetic SDK smoke scoped read approval"}))
                if result["status"] == "approved":
                    break
            if result["status"] != "approved":
                raise RuntimeError("Owner and peer votes did not establish approval")
            if bootstrap.get("capabilities", {}).get("web3", {}).get("enabled"):
                checked(api.post("/api/blockchain/sync", headers=headers("kavya")))
            sdk.permission(session, RESOURCE)
            checks.append("human quorum and live subject grant")

            sdk.revoke(session)
            try:
                sdk.permission(session, RESOURCE)
            except IamError as error:
                if error.status != 401:
                    raise RuntimeError("Revoked token returned unexpected error") from None
            else:
                raise RuntimeError("Revoked token retained authority")
            checks.append("client-bound revocation")

            session = authenticate()
            checked(api.delete("/api/apps/"+app_id, headers=headers("kavya")))
            try:
                sdk.permission(session, RESOURCE)
            except IamError as error:
                if error.status != 401:
                    raise RuntimeError("Disabled app returned unexpected error") from None
            else:
                raise RuntimeError("Disabled app retained authority")
            checks.append("app disable revokes authority")
            print("OIDC smoke passed: "+"; ".join(checks)+".")
        finally:
            if app_id:
                api.delete("/api/apps/"+app_id, headers=headers("kavya"))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Provider responses and exception tracebacks may contain secret values.
        print("OIDC smoke failed ("+type(error).__name__+"); inspect assertions locally without logging credentials.")
        raise SystemExit(1) from None
