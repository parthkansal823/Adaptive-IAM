# Connect your website to Adaptive IAM

Adaptive IAM acts as a local OAuth/OIDC provider. Register a website, redirect visitors to sign in and consent, then verify their identity and resource permission on your website's server. This integrates websites you control. It does not add authentication to unrelated third-party websites.

The supplied Node and Python examples implement Authorization Code with S256 PKCE, signed ID-token verification, server-side token storage, HttpOnly session cookies, and permission checks before serving protected content. Authentication and consent identify the visitor and permit the application to ask for access; a human-approved resource grant is still required.

## Local setup

Run from the repository root with the dependencies installed by `scripts/setup.ps1`:

```powershell
npm run dev
```

Open `http://127.0.0.1:5173`. Sign in as **Kavya** (`kavya`, public demo password `Demo@123!`), complete the displayed demo challenge if required, and open **Connected apps**. Register:

| Setting | Value |
| --- | --- |
| Name | My research website |
| Type | Confidential (the secret stays on your server) |
| Redirect URI | `http://127.0.0.1:3001/callback` |
| Scopes | `openid`, `profile`, `iam:permissions` |
| Resource | `research-vault` |

Copy the generated client ID and the one-time client secret. Keep these in your local server environment; never commit the secret. Public clients are supported by the provider, but a browser-only client cannot safely enforce access to server content. Use a server for this example.

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

Run one example at a time on port 3001. Open `http://127.0.0.1:3001`, select **Sign in with Adaptive IAM**, sign in as Aisha, and approve the consent screen. The callback verifies the signed identity before creating a website session.

`/protected` initially denies access without a grant. In the IAM console, Aisha requests `research-vault` access with a scoped business reason. Sign in as the selected reviewers and satisfy the owner/peer quorum. Once approved, the website serves its protected example content while the grant and site session remain valid. Logout removes the website session and attempts provider token revocation.

Use the same hostname everywhere: `localhost` and `127.0.0.1` are different redirect URIs and cookie hosts. The provider issuer defaults to `http://127.0.0.1:8000`. HTTP requires explicit loopback opt-in in the SDK; normal website deployments require HTTPS.

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

Discovery: `/.well-known/openid-configuration`; signing keys: `/oauth/jwks`. Registration and soft-disable are security-reviewer actions through `/api/apps`. Exact registered redirects, approved scopes, PKCE, one-use short-lived codes and client-bound tokens are enforced. Confidential clients support secret-post and secret-basic authentication. App tokens expire after ten minutes and carry no console voting authority. Revocation uses `/oauth/revoke`.

`/oauth/permissions/{resource_id}` requires both the app's registered resource allowlist and a live grant for the authenticated subject. Default provisioned resources are `research-vault`, `finance-reports` and `production-logs`; arbitrary resource administration is future work. [API.md](API.md) lists the routes.

The SDK rejects timeouts, redirects to other origins, malformed/oversized responses, inconsistent identity/resource bindings, missing read scope and expired grants. The examples return a denial or service error without protected content. Login flows and sessions are memory-resident: restart loses them, and multiple workers need a shared secure store. These are research examples, not a certified OIDC provider or a production session service. Evaluate deployment configuration, TLS, proxy/cookie handling, retention, rotation and operational threats before deployment.

## Verify

```powershell
npm.cmd --prefix integrations/node test
.venv\Scripts\python.exe scripts/run_tests.py -s integrations/python/tests
```

Tests sign real fixture ID tokens and cover wrong signatures, nonce/issuer/audience/expiry, subject mismatch, resource/client binding, denial, malformed responses, timeout and server-side revocation. The provider's own tests cover registration, consent, code/client binding and grants. Unit fixtures do not establish third-party certification or production interoperability.

Protocol references: [PKCE RFC 7636](https://www.rfc-editor.org/info/rfc7636/), [OAuth security RFC 9700](https://www.rfc-editor.org/info/rfc9700/), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html).
