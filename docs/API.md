# API contract

Base URL: `http://127.0.0.1:8000`. Interactive OpenAPI documentation: `/docs`. Source inputs: `backend/app/models.py`; routes: `backend/app/main.py`.

Protected routes require `Authorization: Bearer <token>`. Tokens expire after 30 minutes and are stored as hashes server-side. Login credentials, demo OTPs and token values must never appear in audit events.

## Routes

| Method / path | Authentication | Behavior |
| --- | --- | --- |
| `GET /api/health` | Public | Readiness, version and demo marker |
| `GET /api/bootstrap` | Public | Seeded demo identities/credentials, resources, policy and capabilities |
| `POST /api/risk/assess` | Public | Context simulation only; does not create an authenticated session |
| `POST /api/auth/login` | Credentials | Returns `authenticated`, `mfa_required` or `blocked` |
| `POST /api/auth/verify` | Challenge | Consume a valid demo challenge once and create a session |
| `GET /api/auth/me` | Bearer | Current server identity, session and login risk |
| `POST /api/auth/logout` | Bearer | Invalidate current session |
| `GET /api/overview` | Bearer | Research dashboard stats and recent activity |
| `GET /api/requests` | Bearer | Requests with reviewer policy and `can_vote` for current actor |
| `POST /api/requests` | Bearer | Create a pending identity-bound access request |
| `POST /api/requests/{request_id}/votes` | Eligible bearer | One binary vote with optional comment |
| `GET /api/grants` | Bearer | Current and expired demo grants |
| `GET /api/resources/{resource_id}/access` | Bearer | Server checks current actor's unexpired read grant before returning synthetic content |
| `GET /api/audit` | Bearer | Recent canonical chained events |
| `GET /api/audit/verify` | Bearer | Recompute local chain integrity |
| `GET /api/evaluation` | Public | Synthetic baseline/improved model and NLP evaluation |

`bootstrap` deliberately exposes public demo passwords. All routes are intended for loopback-only research; authenticated demo users see shared organization metadata.

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

The session supplies the requester; no client identity, reviewer IDs, vote weight or risk score is accepted in this body. Justifications must contain 20–2,000 characters. Requested duration is positive and at most 72 hours, additionally capped by the resource: research vault 24, finance reports 8, production logs 4 hours. Resource owners cannot request self-review. A requester may have at most ten pending requests.

Every request starts pending. Selected reviewers receive weights 1.5 (owner) or 1.0 (peer), calculated server-side. Submit `{ "approve": true, "comment": "Reviewed task scope" }` once as an eligible reviewer. Approval requires owner approval, at least two votes, and `approval_weight > 0.5 * total_selected_weight`; owner denial vetoes. Pending requests expire after 48 hours and deny by default. Approved grants expire from their creation time, and access is rechecked on the server.

## Errors and audit

Errors use FastAPI's `detail` field. `401` means invalid/expired credentials, challenge or session; `403` means ineligible reviewer; `404` means unknown request/resource; `409` means duplicate vote, terminal request or self-owner request; `422` means invalid input/duration; `429` means attempt or request limits. Five credential failures lock an account for 15 minutes; the login route also limits clients to 30 attempts/minute.

Audit verification proves consistency of the retained local chain. It cannot prove that an administrator did not replace/recompute the database or remove its tail. Audit payloads omit raw justifications and vote comments, credentials, tokens and OTPs.

