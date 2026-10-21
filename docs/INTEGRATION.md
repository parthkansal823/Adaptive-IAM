# Connect your website to Adaptive IAM

Adaptive IAM acts as a local OAuth/OIDC provider. Register a website, redirect visitors to sign in and consent, then verify their identity and resource permission on your website's server. This integrates websites you control. It does not add authentication to unrelated third-party websites.

The supplied Node and Python examples implement Authorization Code with S256 PKCE, signed ID-token verification, server-side token storage, HttpOnly session cookies, and permission checks before serving protected content. Authentication and consent identify the visitor and permit the application to ask for access; a human-approved resource grant is still required.

## Local setup

For a complete Docker demonstration, start the provider and connected Node website together:

```powershell
docker compose -f compose.yaml -f deployment/compose.website.yaml --profile website up --build -d --wait
```

Open the IAM console at `http://127.0.0.1:5173` and the separate website at `http://127.0.0.1:3001`. A one-shot setup service registers the local demonstration website and retains its confidential-client configuration in a dedicated `website_config` volume. The website has no access to the provider's signing-key volume. Its public issuer remains `http://127.0.0.1:8000`; the container's fixed transport maps provider requests to the internal API. Website tokens still remain server-side, and protected content requires the same live grant checks. [Deployment operations](../deployment/README.md) explain the local trust boundary and persistence.

Sign in as Aisha in the console before starting the website's sign-in flow, approve consent, then try `/protected`. It should deny before Aisha has an approved `research-vault` grant. Create that access request in the console; sign in as its assigned reviewers to complete the owner/peer quorum. When Web3 is enabled, confirm the grant transaction before expecting website access. The website session and console session are separate, so switching console reviewer identities does not change the identity in an existing website session.

To register another website manually or run a host example, use the steps below.

Run from the repository root with the dependencies installed by `scripts/setup.ps1`:

```powershell
npm run dev
```

Open `http://127.0.0.1:5173`. Sign in as **Kavya** (`kavya`, public demo password `Demo@123!`), complete the displayed demo challenge if required, then prepare the application in **Developer portal**:

1. In **Security**, enroll TOTP or a passkey and complete a real-factor verification. Application and organization changes require recent verification; a displayed demo challenge does not satisfy this requirement.
2. In **Developer portal → Organizations**, create an organization. Add **Meera** (`meera`) as a member so her `research-vault` resource becomes eligible for mapping. Add **Aisha** (`aisha`) as a member so she can sign in to this organization's application. Organization membership permits app sign-in; it does not grant resource access.
3. Select **Register application**, choose that organization and complete the wizard with:

| Setting | Value |
| --- | --- |
| Name | My research website |
| Type | Confidential (the secret stays on your server) |
| Redirect URI | `http://127.0.0.1:3001/callback` |
| Scopes | `openid`, `profile`, `iam:permissions` |
| Resource | `research-vault` |

Copy the generated client ID and the one-time client secret. Keep these in your local server environment; never commit the secret. If the portal requests recent verification, return to **Security**, verify the enrolled factor and retry. Public clients are supported by the provider, but a browser-only client cannot safely enforce access to server content. Use a server for this example.

In a second terminal:

```powershell
$env:IAM_ISSUER = 'http://127.0.0.1:8000'
$env:IAM_CLIENT_ID = 'your-generated-client-id'
$env:IAM_CLIENT_SECRET = 'your-one-time-client-secret'
$env:SITE_ORIGIN = 'http://127.0.0.1:3001'
$env:IAM_ALLOW_LOCAL_HTTP = '1'
npm.cmd --prefix integrations/node ci
node integrations/examples/node-site.mjs
```

Alternatively, start the Python website with the same environment instead of the Node website:

```powershell
.venv\Scripts\python.exe -m uvicorn integrations.examples.fastapi_site:app --host 127.0.0.1 --port 3001
```

Run one example at a time on port 3001. Switch the console from Kavya to Aisha before opening the website flow. Open `http://127.0.0.1:3001`, select **Sign in with Adaptive IAM** and approve consent as Aisha. The callback verifies the signed identity before creating a website session. Keep Aisha's source console session active while reviewers use separate console sessions; logging it out or revoking it also removes the website token's authority.

`/protected` initially denies access without a grant. In the IAM console, Aisha requests `research-vault` access with a scoped business reason. Sign in as the selected reviewers and satisfy the owner/peer quorum. Once approved, the website serves its protected example content while the grant and site session remain valid. Logout removes the website session and attempts provider token revocation.

The Node website's `/protected` page displays success or denial as readable HTML in a browser; API clients retain JSON responses. Every visit checks the live grant again, so expiry, revocation or an unavailable permission check denies the protected content even after successful sign-in.

Use the same hostname everywhere: `localhost` and `127.0.0.1` are different redirect URIs and cookie hosts. The provider issuer defaults to `http://127.0.0.1:8000`. HTTP requires explicit loopback opt-in in the SDK; normal website deployments require HTTPS.

## Durable Node website sessions

The Node example defaults to isolated memory storage. To preserve pending logins and website sessions across restarts, opt into its SQLite store with Node 24 LTS:

```powershell
$env:IAM_SITE_SESSION_DB = "$PWD\.cache\orbit-sessions\sessions.sqlite"
node integrations/examples/node-site.mjs
```

The first start creates a random 32-byte encryption key at `<database path>.key`. Keep the database and key together in a persistent, private directory. An optional `IAM_SITE_SESSION_KEY_FILE` selects another key path. Key files contain raw key bytes; the store restricts them and the database to the running account (`0600` on POSIX; a protected Windows ACL grants only that account and SYSTEM). Windows requires PowerShell to apply that ACL. Filesystems must support atomic hard-link creation for publishing the initial key. Run concurrent workers under the same OS account.

Alternatively, supply `IAM_SITE_SESSION_KEY` from your secret manager as exactly 32 random bytes encoded as unpadded base64url (43 characters). This avoids creating a key file. Set either `IAM_SITE_SESSION_KEY` or `IAM_SITE_SESSION_KEY_FILE`, and set a database path whenever either is configured. Never commit either the key or database. Missing, malformed or incorrect keys and corrupt or unsupported databases stop the store; they never trigger an automatic reset. To invalidate all website sessions deliberately, stop every website worker, remove its dedicated database and key, and start with a new pair. This does not revoke provider tokens; use provider revocation for that purpose. Backups of the database and key contain recoverable credentials until their token expiry and require equivalent access controls.

AES-256-GCM encrypts complete login transactions and website sessions, including access tokens, identity details and PKCE verifiers. Cookie identifiers are stored as hashes. Encryption authenticates the application namespace, cookie hash, record type and expiry; changing those fields or ciphertext denies access. The application namespace binds the website origin, provider issuer and client ID. No key, token or verifier is returned in HTML/API responses, cookies or diagnostics.

Workers sharing one local database and key share current session authority. Atomic SQLite deletion consumes each login transaction once; logout removes the session before attempting provider revocation. Every private response checks that the website session still exists after provider calls, including when another worker logs it out during a pending request. Login transactions expire after five minutes, and website sessions expire no later than the provider's ten-minute token lifetime, with no sliding extension. The store caps pending logins at 256 and sessions at 1,024 across the database, caps each encrypted record's input at 32 KiB, and removes at most 128 expired records per cleanup call.

This supports restarts and concurrent workers on one host with a trustworthy local filesystem and clock. Use a local persistent volume with SQLite locking; this is not a cross-host or network-filesystem session service. A host administrator or an attacker controlling both database and key can recover credentials or restore old records. Live provider identity and permission checks continue on each private request, so persistence does not extend a revoked or expired grant. The Python example remains memory-only. The implementation uses [Node's built-in SQLite API](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html), without another package.

## Reuse the server SDK

The Node SDK is `integrations/node/adaptive-iam.mjs`; the Python SDK is `integrations/python/adaptive_iam.py`. Node uses the maintained `jose` library; Python uses PyJWT with cryptography from the backend requirements. HTTP transport and the website examples use their standard runtimes.

For another framework, keep the same server sequence:

1. Create random, short-lived state, nonce and PKCE verifier, tied to the visitor's login cookie.
2. Redirect to the SDK's authorization URL. Store the verifier on the server.
3. Consume the callback transaction once; compare state and returned issuer before code exchange.
4. Verify RS256 signature, issuer, audience, nonce, expiry and matching UserInfo subject. Store the returned access token in a server-side session.
5. Before every protected response, call the SDK's permission method for the required resource. Match subject, client, resource, scope and future expiry. Serve content only after success.

Node authorization middleware can call:

```javascript
await iam.permission(serverSession, 'research-vault')
// Only after success: return the protected response.
```

Python middleware can call:

```python
iam.permission(server_session, "research-vault")
# Only after success: return the protected response.
```

See the complete examples for state handling, callback verification, cookies and error responses. Tokens and client secrets must stay off frontend JavaScript and browser storage. UI visibility alone does not protect data.

## Provider contract and limits

Discovery: `/.well-known/openid-configuration`; signing keys: `/oauth/jwks`. Organization app registration and management through `/api/apps` require eligible organization administrators/developers and recent real-factor verification; legacy public-demo apps are managed by security reviewers. Exact registered redirects, approved scopes, PKCE, one-use short-lived codes and client-bound tokens are enforced. Confidential clients support secret-post and secret-basic authentication. App tokens expire after ten minutes and carry no console voting authority. Revocation uses `/oauth/revoke`.

`/oauth/permissions/{resource_id}` requires both the app's registered resource allowlist and a live grant for the authenticated subject. Default provisioned resources are `research-vault`, `finance-reports` and `production-logs`; arbitrary resource administration is future work. [API.md](API.md) lists the routes.

The SDK rejects timeouts, redirects to other origins, malformed/oversized responses, inconsistent identity/resource bindings, missing read scope and expired grants. The examples return a denial or service error without protected content. Memory mode loses login flows and sessions on restart; the Node example also supports the opt-in durable store described above. These are research examples, not a certified OIDC provider or a production session service. Evaluate deployment configuration, TLS, proxy/cookie handling, retention, rotation and operational threats before deployment.

## Verify

```powershell
npm.cmd --prefix integrations/node test
.venv\Scripts\python.exe scripts/run_tests.py -s integrations/python/tests
```

Tests sign real fixture ID tokens and cover wrong signatures, nonce/issuer/audience/expiry, subject mismatch, resource/client binding, denial, malformed responses, timeout and server-side revocation. Temporary-database tests additionally cover encrypted persistence, restart, shared logout, expiry boundaries, bounded cleanup/capacity, wrong or lost keys, corrupt storage, tampered records and atomic login consumption by concurrent Node workers. The provider's own tests cover registration, consent, code/client binding and grants. Unit fixtures do not establish third-party certification or production interoperability.

Protocol references: [PKCE RFC 7636](https://www.rfc-editor.org/info/rfc7636/), [OAuth security RFC 9700](https://www.rfc-editor.org/info/rfc9700/), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html).

## Organization onboarding

The Developer portal replaces the earlier Connected apps screen. Enroll TOTP or a passkey in Security, verify it recently, create an organization and assign app administrators. Include each intended signing-in identity and the resource owner as members. The three-step wizard collects app name/type, exact callback URLs and eligible resource mappings; the confidential client secret is returned once. Callback diagnostics never contact the entered host. Rotation invalidates existing tokens and pending codes immediately. Update the website server's stored secret before restarting its sign-in flow. The Docker setup service authenticates persisted credentials before reuse, preserves rejected or unreadable files and reports [recovery steps](../deployment/README.md#demo-website-credential-recovery).

Organization apps require the signing-in identity to remain a member. Mapping a resource requires its owner to be a member, but membership itself never grants permission. The existing seed identities/resources are shared research fixtures, not private tenant isolation. Legacy demo registration by Kavya is retained for the loopback setup service; new organization setup requires real factor verification.

OAuth app tokens now depend on the source IAM browser session. Logout, expiry, revocation, enrollment restrictions or detected step-up remove app authority. Website request headers are not compared to the original browser's headers. The website server must keep checking provider identity and live resource permissions; a cached name alone is not active authorization.
