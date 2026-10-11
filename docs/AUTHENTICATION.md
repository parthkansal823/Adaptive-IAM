# Verified authentication and session checks

The API now verifies WebAuthn passkeys and RFC 6238 authenticator codes. The research demo remains explicit (`IAM_DEMO_MODE=true` by default). After an identity enrolls a real factor, password login requires that factor even at low simulated risk; it never returns or accepts a public demo code for that identity. Passkey login proves possession directly and still runs the server risk gate. High-risk logins remain denied.

## Enrollment and recovery

From Security, confirm the password before enrolling the first factor. Later factor enrollment, deletion, recovery-code replacement and developer security changes require a factor verified within five minutes. Passkey registration and assertions validate the challenge, exact origin, RP ID, user verification, stored public key and authenticator counter. Challenges expire in two minutes and are single use, including failed cryptographic responses. Synced authenticators with zero counters are supported by the verification library; a counter is not a guarantee against cloned synced credentials.

TOTP enrollment generates a random 160-bit secret, returns its `otpauth://` URI once and requires a valid authenticator response before activation. Secrets are Fernet-encrypted with a separate runtime key (`IAM_FACTOR_KEY_FILE`, default `factor-encryption.key` in the data directory). Preserve that key in a protected backup; losing it makes enrolled TOTP factors unusable. Codes use six digits, SHA-1, 30-second steps and a ±1 step clock window. A used counter cannot authenticate again, including across parallel requests. Enrollment attempts and verification failures are bounded. Five failed session-factor verifications revoke the session.

Eight randomly generated recovery codes are returned once when TOTP is activated. Passkey users can generate them after a fresh passkey verification. Only hashes are stored; consumption is atomic and single use. These codes verify an existing login/session rather than acting as an unauthenticated password-reset service. Replacing them invalidates the previous set. Losing every factor and recovery code requires explicit offline operator reprovisioning; there is no insecure public recovery shortcut.

Removing the last enrolled factor in secure mode revokes other sessions and confines the current session to five-minute factor enrollment again. Reconfirming the password alone cannot restore protected app/resource authority. Removing a factor while another remains still requires recent verified factor possession.

All `/api/auth/*` responses carry `Cache-Control: no-store`. Factors, OTPs, passwords, recovery codes, credential responses and raw request headers are excluded from audit events.

## Continuous enforcement

Console sessions bind a keyed digest of the server-observed client address and User-Agent. A changed digest or three server-recorded password failures since the last verification within 15 minutes marks the session as requiring step-up, immediately denying resource access, votes, consent and app management. Recovery endpoints remain reachable. A valid enrolled factor binds the new context; a password alone cannot clear the changed context. An identity without a factor must sign in again. Security lists active sessions and supports revocation. OAuth codes and app tokens are also bound to the originating console session; expiration, logout, revocation or a detected step-up removes their authority.

This digest is a contextual anomaly signal, not a cryptographic device identifier. User-Agent can be copied, legitimate IP changes trigger step-up, and a stolen bearer used from an identical context may evade this check. Network/device context is checked on console requests. OAuth token exchange and app-token checks also re-evaluate durable server password failures, so three new failures can deny an app directly while the console is idle. The relying party's IP/User-Agent are never compared with the originating browser. A detected risk step-up persists until verification or a fresh sign-in; there is no claim of continuous device telemetry while the browser is idle. Use passkeys and trusted telemetry for stronger deployments.

The API ignores `X-Forwarded-For` unless the immediate peer exactly matches `IAM_TRUSTED_PROXY_IPS`. Even then, only one syntactically valid address is accepted; arbitrary forwarded chains are ignored. Configure an actual known ingress address, and ensure that proxy overwrites the header. No broad subnet trust is inferred.

## Secure mode and operator setup

Set `IAM_DEMO_MODE=false` to hide public bootstrap credentials and reject the public seed password. Sessions created in demo mode and sessions from earlier unbound builds fail closed. Client-submitted scenario values no longer affect secure-mode login risk. The server observes context familiarity, login velocity, UTC hour and durable authentication failures; unavailable VPN/location/travel/account-age/behavioral features use disclosed defaults. A synthetic model with partial observed features has no established deployment accuracy. Secure mode therefore remains a research deployment configuration, not a production certification.

Provision an identity while the API is stopped. Passwords are entered using `getpass`, never command-line arguments or environment variables:

```powershell
.venv/Scripts/python.exe scripts/provision_identity.py --database backend/data/iam.sqlite3 --user-id operator --name "Research operator" --department Security --role security_reviewer
```

Use a private passphrase of at least 14 characters. Reprovisioning an existing identity revokes its sessions and resets factors/recovery codes. The command changes only the explicitly named database; tests use temporary databases. The local `backend/data` example does not modify Docker's named IAM volume. For Docker, stop `api`, run the same script in an isolated Python API container with its IAM volume mounted at `/var/lib/iam`, and explicitly target `/var/lib/iam/iam.sqlite3`. Keep demo and private research volumes separate.

An operator-provisioned identity with no enrolled factor receives a five-minute **enrollment-only** session after a correct private password and a non-high-risk decision. A medium score from an unfamiliar first context does not create an enrollment dead end. This session permits only factor setup, password reconfirmation, security/session inspection and logout/current-session revocation; it cannot consent to a website, obtain an app token, submit/vote on requests, manage apps or access resources. Password reconfirmation preserves that restriction. Only cryptographically verified passkey registration or confirmed TOTP enrollment upgrades the session to the normal 30-minute lifetime. High-risk authentication remains denied. The first factor is consequently bootstrapped from the operator-provisioned password and bound request context; it is not independent proof of identity beyond that operator trust.

For passkeys, configure `IAM_WEBAUTHN_ORIGIN` as the exact console origin and `IAM_WEBAUTHN_RP_ID` as the matching host (default `http://127.0.0.1:5173`, `127.0.0.1`). Remote origins require HTTPS; only exact `localhost` and `127.0.0.1` allow HTTP. Port, scheme and host changes require matching configuration. WebAuthn needs a supported browser and authenticator; Windows application policy can block its Python CBOR dependency, so the supported verification runtime is Docker Linux. No security policy is weakened to load a native module.

## API contracts

| Endpoint | Contract |
| --- | --- |
| `GET /api/auth/security` | Factor status, nonsecret passkey metadata, recovery count, current session, enrollment/fresh-verification status, RP origin |
| `POST /api/auth/reauth` | `{password, code?, recovery_code?}`; enrolled identities must supply a factor |
| `POST /api/auth/step-up` | Exactly one `{code}` or `{recovery_code}`; success includes `fresh_until` and method |
| `POST /api/auth/totp/enroll` | Fresh verification; returns enrollment ID, secret, URI and five-minute expiry |
| `POST /api/auth/totp/confirm` | `{enrollment_id, code}`; activates factor and returns recovery codes once |
| `DELETE /api/auth/totp` | Recent factor; removes factor and revokes other console sessions |
| `POST /api/auth/recovery/regenerate` | Recent factor; returns the new code set once |
| `GET /api/auth/sessions` | `{items:[{id,created_at,expires_at,last_seen_at,verification_method,step_up_required,current}]}` |
| `POST /api/auth/sessions/{id}/revoke` | Removes a session belonging to the authenticated identity |
| `POST /api/auth/passkeys/register/options` | Fresh verification, `{label}` → `{challenge_id,options}` |
| `POST /api/auth/passkeys/register/verify` | `{challenge_id,credential}` → stored nonsecret passkey metadata |
| `DELETE /api/auth/passkeys/{id}` | Recent factor; revokes other sessions |
| `POST /api/auth/passkeys/login/options` | `{user_id}` → `{challenge_id,options}` |
| `POST /api/auth/passkeys/login/verify` | `{challenge_id,credential}` → login result, or policy block |
| `POST /api/auth/passkeys/step-up/options` | Authenticated identity → `{challenge_id,options}` |
| `POST /api/auth/passkeys/step-up/verify` | `{challenge_id,credential}` → fresh verification |

`/api/auth/verify` accepts exactly one code/recovery code with its password-login challenge. Real-factor challenges identify their available `methods`; only an unenrolled demo identity receives `demo_code`. Private first-factor login returns the normal authenticated packet plus `enrollment_required:true` and `session_scope:"factor_enrollment"`; `/auth/me` exposes the restriction as `session.enrollment_required`. Protected calls made with this session return HTTP 403 with `detail.code=factor_enrollment_required`. A risk-gated session returns `step_up_required`. Sensitive changes without recent factor verification return `recent_verification_required`. Verification failures return 401; bounded limits return 429. No arbitrary credential response can create a grant or cast a vote.

Cryptographic tests construct real P-256 COSE keys and ECDSA assertions, then verify HTTP registration/login/step-up and rejection of wrong origins, RP IDs, signatures, UV flags, handles, counters and replay. These are software-generated authenticators; physical-device browser enrollment and usability require separate observation.
