# Adaptive IAM frontend

React 19, TypeScript, Vite, and vanilla CSS. No chart or component framework. The browser is a client of the FastAPI research backend.

## Start

```powershell
cd frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. Start the backend on `http://127.0.0.1:8000`; Vite proxies `/api` there. Use `npm run build` to typecheck and create `dist/`.

## Interface

- **Overview:** live session risk, adaptive policy, scoped metrics, event history, and requests.
- **Security:** real passkey enrollment/sign-in, TOTP enrollment with single-use recovery codes, recent factor verification, and active-session revocation. The browser invokes WebAuthn; the server verifies every ceremony.
- **Attack lab:** 12 bounded authentication/language/authorization scenarios. Each run records actual model output and owned policy observations without creating requests, votes, or grants; the latest 20 runs remain inspectable.
- **Risk lab:** nine editable scenarios covering familiar sign-in, new device, travel, suspicious activity, new location, rapid retries, VPN, after-hours, and a new account. Every scenario uses actual model probabilities; tier boundaries come from `/api/bootstrap`.
- **Access requests:** justification analysis, selected reviewers, weighted voting, grant expiry, eligible owner/security-reviewer revocation, and real protected-resource checks.
- **Audit ledger:** event payloads, hash-chain verification, actual blockchain status, and security-reviewer synchronization of hashes and timed grants.
- **Experiments:** measured held-out metrics, protocol, limitations, and JSON export.
- **Developer portal:** organizations and administrator/developer/member roles, a three-step application wizard, exact callback diagnostics, resource mappings, one-time client secrets, rotation, app disable, and provider endpoints. Sensitive mutations require recent verification with an enrolled factor.
- **`/connect?request_id=...`:** app authorization packet, adaptive identity sign-in, and explicit consent before returning to the registered callback.

The seeded local password is `Demo@123!`. Before factor enrollment, demo MFA codes are displayed explicitly by the backend in demo mode. After enrollment, sign-in requires the actual factor. Secrets and recovery codes stay only in component memory and are cleared when leaving their view or changing the session. These seeded credentials are for the local research deployment.

## State and trust

Bearer sessions are kept in sessionStorage. Theme is persisted in localStorage. Identity changes clear cached protected data. Server responses control whether a user can vote, whether access is granted, and whether a callback is registered. The frontend never issues identity or OAuth tokens.

Visible tabs check `/auth/me` every minute and when visibility changes. A server-reported context change clears cached protected workspace data and opens Security for factor verification. Server checks enforce the boundary on every protected request; the timer is only a UI update. A revoked or expired console session is cleared from this tab.

Confirmed requests, votes, and revocations remain confirmed if a subsequent workspace refresh fails; the UI reports that refresh separately. Expired or consumed consent requests are disabled. Failed blockchain status reads clear prior readiness. API calls have a 30-second timeout, with a two-minute window for votes, revocation, and batched chain synchronization.

`src/api.ts` is the typed contract. `DESIGN.md` records the white/black/orange token system. `AGENTS.md` contains compact editing conventions.
