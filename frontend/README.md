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
- **Risk lab:** editable scenario inputs and actual model probabilities. The current tier boundaries come from `/api/bootstrap`.
- **Access requests:** justification analysis, selected reviewers, weighted voting, grant expiry, and real protected-resource checks.
- **Audit ledger:** event payloads, hash-chain verification, actual blockchain status, and security-reviewer synchronization of hashes and timed grants.
- **Experiments:** measured held-out metrics, protocol, limitations, and JSON export.
- **Connected apps:** security-reviewer application registration, exact callbacks, resource mappings, provider endpoints, and token revocation.
- **`/connect?request_id=...`:** app authorization packet, adaptive identity sign-in, and explicit consent before returning to the registered callback.

The seeded local password is `Demo@123!`. Demo MFA codes are displayed explicitly by the backend. These credentials are for the local research deployment.

## State and trust

Bearer sessions are kept in sessionStorage. Theme is persisted in localStorage. Identity changes clear cached protected data. Server responses control whether a user can vote, whether access is granted, and whether a callback is registered. The frontend never issues identity or OAuth tokens.

`src/api.ts` is the typed contract. `DESIGN.md` records the white/black/orange token system. `AGENTS.md` contains compact editing conventions.
