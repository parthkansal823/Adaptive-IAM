# API contract

Base URL: `http://127.0.0.1:8000`. Interactive OpenAPI documentation: `/docs`. Source inputs: `backend/app/models.py`; routes: `backend/app/main.py`.

Protected routes require `Authorization: Bearer <token>`. Tokens expire after 30 minutes and are stored as hashes server-side. Login credentials, demo OTPs and token values must never appear in audit events.

The table below uses console session tokens. Website application tokens are a separate, client-bound credential with ten-minute lifetime and cannot vote or manage the console.

## Routes

| Method / path | Authentication | Behavior |
| --- | --- | --- |
| `GET /api/health` | Public | Readiness, version and demo marker |
| `GET /api/bootstrap` | Public | Demo identities/credentials only in demo mode; resources, policy and capabilities |
| `POST /api/risk/assess` | Public | Context simulation only; does not create an authenticated session |
| `POST /api/auth/login` | Credentials | Returns `authenticated`, `mfa_required` or `blocked` |
| `POST /api/auth/verify` | Challenge | Consume a context-bound real-factor or unenrolled demo challenge once |
| `GET /api/auth/me` | Bearer | Current server identity, session and login risk |
| `POST /api/auth/logout` | Bearer | Invalidate current session |
| `GET /api/overview` | Bearer | Research dashboard stats and recent activity |
| `GET /api/requests` | Bearer | Actor-visible requests with reviewer policy and `can_vote` |
| `POST /api/requests` | Bearer | Create a pending identity-bound access request |
| `POST /api/requests/{request_id}/votes` | Eligible bearer | One binary vote with optional comment |
| `GET /api/grants` | Bearer | Actor-visible current and expired demo grants |
| `POST /api/grants/{grant_id}/revoke` | Owner/security bearer | Revoke local authority immediately and attempt optional chain synchronization |
| `GET /api/resources/{resource_id}/access` | Bearer | Server checks current actor's unexpired read grant before returning synthetic content |
| `GET /api/audit` | Bearer | Actor-visible recent canonical chained events |
| `GET /api/audit/verify` | Bearer | Recompute local chain integrity and include optional live blockchain status |
| `GET /api/evaluation` | Public | Synthetic baseline/improved model and NLP evaluation |
| `GET /api/blockchain/status` | Bearer | Optional local chain readiness, registry/checkpoint and pending event count |
| `POST /api/blockchain/sync` | Security bearer | Retry audit/grant/revocation outbox and return confirmed receipts/errors |

`bootstrap` deliberately exposes public demo passwords. All routes are intended for loopback-only research. Requesters and selected reviewers see their related requests/audit events; grantees and owners see related grants. The security reviewer sees organization-wide activity.

## Login and context

```json
{
  "user_id": "aisha",
  "password": "Demo@123!",
  "context": {
    "known_device": true,
    "known_location": true,
    "vpn": false,
    "failed_attempts": 0,
    "hour": 10,
    "login_velocity": 1,
    "account_age_days": 365,
    "travel_distance_km": 0,
    "sensitivity": 0.5,
    "prior_risk": 0.1
  }
}
```

These context values are simulated by the client. Login merges server-observed recent credential failures so a client cannot reduce that signal. Input fields are bounded, and unknown properties are rejected. Public risk simulation accepts `{ "context": { ... } }` with the same shape.

Medium risk returns `challenge_id`, `demo_code` and `expires_at`; submit `{ "challenge_id": "...", "code": "123456" }` to verify. Challenges expire after 120 seconds, permit at most five incorrect attempts, and are single use. Demo codes are displayed solely to exercise the prototype flow. High risk returns a block without a token.

## Request and voting

```json
{
  "resource_id": "research-vault",
  "justification": "I need scoped read access for the approved project evidence review due tomorrow.",
  "duration_hours": 4
}
```

The session supplies the requester; no client identity, reviewer IDs, vote weight or risk score is accepted in this body. Request risk is recomputed using the stored login context and server-owned resource sensitivity (internal 0.3, confidential 0.7, restricted 1.0), rather than accepting a client-selected resource score. Justifications must contain 20–2,000 characters. Requested duration is positive and at most 72 hours, additionally capped by the resource: research vault 24, finance reports 8, production logs 4 hours. Resource owners cannot request self-review. A requester may have at most ten pending requests.

Every request starts pending. Selected reviewers receive weights 1.5 (owner) or 1.0 (peer), calculated server-side. Submit `{ "approve": true, "comment": "Reviewed task scope" }` once as an eligible reviewer. Approval requires owner approval, at least two votes, and `approval_weight > 0.5 * total_selected_weight`; owner denial vetoes. Pending requests expire after 48 hours and deny by default. Approved grants expire from their creation time, and access is rechecked on the server.

## Errors and audit

Errors use FastAPI's `detail` field. `401` means invalid/expired credentials, challenge or session; `403` means ineligible reviewer; `404` means unknown request/resource; `409` means duplicate vote, terminal request or self-owner request; `422` means invalid input/duration; `429` means attempt or request limits. Five credential failures lock an account for 15 minutes; the login route also limits clients to 30 attempts/minute.

Audit verification proves consistency of the retained local chain. It cannot prove that an administrator did not replace/recompute the database or remove its tail. Audit payloads omit raw justifications and vote comments, credentials, tokens and OTPs.

When Web3 is configured, grant responses include pending/confirmed chain state. Protected access requires both local authority and the live Solidity grant. A successful vote quorum creates local approval; on-chain confirmation remains a separate state. RPC failure, registry/checkpoint mismatch, expiry or revocation denies protected access. `POST /api/blockchain/sync` returns `receipts` and `errors`; inspect actual receipt state rather than treating HTTP success as grant confirmation. Configuration and Docker persistence are documented in [deployment operations](../deployment/README.md).

## Registered website OAuth/OIDC

| Method / path | Authentication | Behavior |
| --- | --- | --- |
| `GET /.well-known/openid-configuration` | Public | Canonical issuer and protocol endpoints |
| `GET /oauth/jwks` | Public | Public RS256 verification keys |
| `GET /api/apps` | Console bearer | Actor-visible organization apps; security reviewers also see legacy registrations |
| `POST /api/apps` | App manager + fresh factor | Optional `organization_id`; exact callbacks/scopes/resources; confidential secret once. Legacy demo-only security registration retains compatibility |
| `DELETE /api/apps/{client_id}` | App manager + fresh factor | Soft-disable client and revoke tokens; legacy demo exception as above |
| `POST /api/apps/{client_id}/rotate-secret` | App manager + fresh factor | `{}`; active confidential client only; secret once, revoke tokens and pending codes |
| `GET /oauth/authorize` | Client request | Validate code flow, scope, state, nonce, exact redirect and S256 PKCE; redirect to console consent |
| `GET /api/oauth/authorization/{request_id}` | Public | Bounded consent packet, app identity, scopes and resources |
| `POST /api/oauth/consent` | Console bearer | `{request_id, approve}` produces validated `redirect_to` with state and issuer |
| `POST /oauth/token` | Client + code + verifier | Form-encoded code exchange; opaque access token, RS256 ID token, scope and ten-minute lifetime |
| `GET /oauth/userinfo` | App bearer | Subject and approved profile fields |
| `GET /oauth/permissions/{resource_id}` | App bearer | Check permission scope, registered resource and subject's current read grant |
| `POST /oauth/revoke` | Registered client | Form-encoded token revocation, client-bound; unknown/revoked tokens return success |

Registration accepts `public` or `confidential` clients and `openid`, `profile`, `iam:permissions` scopes. Confidential exchange/revocation supports secret-post or HTTP Basic. Permission responses bind `{allowed, sub, client_id, resource_id, scope, expires_at, reason}`; a website must validate those bindings and expiry rather than trusting `allowed` alone. Source: `backend/app/oauth.py`. [INTEGRATION.md](INTEGRATION.md) contains registration and complete server examples.

## Verified identity, onboarding and diagnostics

See [AUTHENTICATION.md](AUTHENTICATION.md) for complete passkey/TOTP/recovery and session contracts. In secure mode client context is ignored; server-observed request context is partial telemetry. First private password login issues an enrollment-only session, capped at five minutes. Protected actions return `detail.code=factor_enrollment_required` until a real factor is enrolled. Context changes and server password-failure spikes require step-up. Website codes/tokens depend on their source console session and fail after expiry, revocation, enrollment restriction or step-up; RP headers are not compared to browser headers.

| Method / path | Authentication | Behavior |
| --- | --- | --- |
| `GET /api/developer/workspace` | Console bearer | Membership-visible organizations/apps and prototype identity directory |
| `POST /api/developer/organizations` | Console + fresh factor | `{name}`; creator becomes admin, at most 10 created organizations |
| `POST /api/developer/organizations/{id}/members` | Org admin + fresh factor | `{user_id,role}`; existing research identities only; admin/developer/member |
| `DELETE /api/developer/organizations/{id}/members/{user_id}` | Org admin + fresh factor | Remove membership, revoke affected app tokens/codes; last admin cannot be removed |
| `POST /api/developer/callback-check` | Console bearer | `{redirect_uri,client_id?}`; URL and exact-registration checks only, no network fetch |
| `GET /api/lab/catalog` | Console bearer | Twelve bounded diagnostic scenarios |
| `POST /api/lab/run` | Console bearer | `{case_id}`; actual running model/NLP and owned policy observations; no votes/grants/session issued |
| `GET /api/lab/runs` | Console bearer | Latest 20 recorded runs for current actor |

Organization membership permits app administration/sign-in eligibility and resource mapping only when the resource owner is a member. Live permissions recheck current owner membership and the separate subject grant. The seeded identities/resources remain shared prototype infrastructure; this is not private tenant isolation or an invitation-based identity directory. The attack lab persists diagnostic readings, not measured detector correctness or human attack labels.
