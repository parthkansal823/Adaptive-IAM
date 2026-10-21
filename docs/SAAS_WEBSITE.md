# Orbit Workspace with Adaptive IAM

Orbit is a separate SaaS demonstration at **http://127.0.0.1:3001/**. It has a product home, illustrative plans, authenticated dashboard, searchable sample projects, protected reports and account settings. Its white/black/orange UI supports light/dark modes and mobile layouts. Business charts/projects are clearly labeled sample data; identities and permission checks come from the running IAM provider.

The interface uses a shared navigation rail, readable type, a single orange accent and consistent project tables across pages. On mobile, navigation becomes a two-column menu and wide tables scroll inside their own panel. Projects support name/team search and a status filter; `/projects?q=product&status=on%20track` can open a filtered sample view. The four active projects and two on-track projects match the displayed list. All October dates remain illustrative, rather than claiming current business activity.

Theme controls follow the system preference until a local preference is saved. Every page offers a skip link and visible keyboard focus. Browser code handles presentation and sample filtering only. IAM verifies passwords and authentication factors; Orbit does not receive those credentials. Website access tokens and PKCE verifiers stay on the Orbit server.

## Run

Start Docker Desktop, then from the repository root:

```powershell
docker compose -f compose.yaml -f deployment/compose.website.yaml --profile website up --build -d --wait
```

Open Orbit on port 3001, the IAM console on port 5173 and API documentation on port 8000. The setup service registers an exact `http://127.0.0.1:3001/callback` confidential client and stores its credentials in the separate `website_config` volume. The website cannot read IAM signing keys. Existing credentials are authenticated before reuse without logging in as the demo setup identity. A rotated secret, disabled application, malformed file or provider outage stops setup with recovery guidance and preserves the file. See [demo website recovery](../deployment/README.md#demo-website-credential-recovery). This setup service is for the public loopback research demo; use the [organization onboarding steps](INTEGRATION.md#local-setup) for another website or private accounts.

## Authentication and authorization journey

1. Select **Sign in with Adaptive IAM** on Orbit. The website creates random state/nonce and PKCE S256, stores its verifier on the server and redirects to IAM.
2. Sign in on IAM, completing the enrolled real factor or explicit unenrolled demo challenge. Approve the displayed website consent.
3. Orbit validates callback state, issuer, code and single use, then exchanges the code on its server. The SDK verifies RS256 identity, issuer/audience/nonce/expiry and the matching UserInfo subject. Only a random HttpOnly cookie reaches the browser.
4. The dashboard rechecks provider identity on each visit. Sign-in alone opens the sample workspace; it does not grant report access.
5. Request a `research-vault` read grant through IAM Access requests. The resource owner and selected peer reviewers must satisfy the server quorum. When Web3 is configured, the contract grant must also be confirmed.
6. Open Orbit Reports. Each visit performs a fresh identity/client/resource/scope/expiry-bound permission check. No grant gives 403, an expired/revoked session gives 401, and unavailable IAM confirmation gives 503. The JSON `/protected` route retains the same enforcement.

The grant and website session have separate expiry. Website tokens also depend on their source console session: console logout, expiry, revocation, enrollment restriction or detected step-up removes website authority. Switching to another console identity creates a different console session; it does not change an existing website subject. Do not log out/revoke the source requester session while reviewing as a different identity in another session if the requester still needs website access.

## Routes and controls

| Route | Access |
| --- | --- |
| `/`, `/pricing`, `/assets/orbit.css`, `/assets/orbit.js` | Public |
| `/login`, `/callback` | Bound OAuth/OIDC code flow |
| `/dashboard`, `/projects`, `/settings`, `/api/session` | Fresh provider identity check |
| `/reports`, `/protected` | Live subject-bound read grant |
| `POST /logout` | Exact same-origin request; removes local session and attempts provider revocation |

Tokens/verifiers and client secrets stay on the server. HTML escapes identity fields; `/api/session` contains only nonsecret identity, expiry and report state. Responses use `no-store`, a self-only script/style policy, `frame-ancestors 'none'` and no-referrer. OAuth callbacks reject duplicate protocol fields; consumed transactions cannot replay. The browser script handles theme and sample-project filtering only, never authorization.

`npm --prefix integrations/node test` runs SDK and temporary HTTP-server security tests. The site tests inject a provider fixture to isolate each website boundary; the live smoke command `python -m integrations.tests.smoke_oidc` separately checks the running real provider/SDK and synthetic owner/quorum/contract flow without printing credentials. Fixtures are not production security evidence.

## Connect another business website

Use the IAM Developer portal to register its exact callback, allowed scopes and resource mappings. Keep a confidential client secret on that website's server. Use the Node/Python SDK for code exchange and **every** protected response. See [INTEGRATION.md](INTEGRATION.md) for reusable examples and [AUTHENTICATION.md](AUTHENTICATION.md) for real factors/private operator setup.

Docker stores website login flows and sessions in the separate `website_sessions` volume using encrypted SQLite; restarts retain unexpired authority and one-use callback state. Preserve its database and key together. Local host examples use memory unless `IAM_SITE_SESSION_DB` is configured. Shared workers must use the same local database, key and client configuration. This is same-host persistence; protected pages still consult IAM on every visit. See [session configuration](INTEGRATION.md#durable-node-website-sessions).

This local demonstration uses synthetic records and loopback HTTP. Production requires HTTPS, multi-host availability, managed keys, independently reviewed provider interoperability, invitation-based tenancy and operational recovery. An administrator able to restore database/key snapshots can replay retained state; encryption alone does not detect rollback. Product pricing is illustrative; the application does not charge or create subscriptions.
