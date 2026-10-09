# Security boundaries

This is a local research prototype with synthetic data and demo identities. Do not expose it publicly or use it to gate sensitive enterprise resources without the production work below.

## Controls the implementation must preserve

- Authenticate identities server-side; never trust a submitted `user_id`, role, risk score or reviewer weight as proof of identity or authority.
- Challenge elevated-risk logins, limit challenge reuse, and deny high-risk attempts according to explicit policy.
- Recompute authorization and expiry for every protected access. UI state is advisory.
- Restrict voting to selected eligible reviewers; exclude self-review, duplicate votes and arbitrary client weights.
- Resolve voting using the selected reviewers' total possible weight, at least two votes and owner approval. Deny on owner veto, final ties and expired unresolved requests.
- Validate optional model output against an allowlist. Fail back to deterministic selection when a model times out, returns invalid data or proposes an ineligible reviewer.
- Avoid secrets in events and prompt logs. An access reason may contain sensitive business data; set retention and access policies before real use.
- Verify audit links and canonical hashes. Local integrity detection does not prevent authorized database replacement, truncation or recomputation.

## Known prototype limitations

Synthetic identity/context signals are demonstrative and can be chosen by the tester. They are not trusted device telemetry. Public bootstrap credentials and UI-displayed demo challenges are not production authentication factors. Local process memory and SQLite are not a high-availability identity provider. Audit and resource access use the same host trust boundary. Requests/audit views are scoped to the requester and selected reviewers; grants are scoped to the grantee and resource owner. Security reviewers have organization-wide visibility. This demo does not implement separate organization tenancy.

LLM justification text is untrusted input. Reviewer recommendations must remain recommendations. A generic pretrained transformer does not supply calibrated suspicious-request probabilities without task-specific training.

## Website identity and permission

Registered clients use exact callback matching, S256 PKCE, consent, one-use codes and client-bound scopes/resources. App access tokens have no console-session authority. Relying-party SDKs validate RS256 signing keys, issuer, audience, nonce, expiry and UserInfo subject before creating their server-side website session. Every protected response checks a subject/client/resource-bound live read grant. Identity consent alone grants no resource access. Website cookies contain random session keys; access tokens and confidential client secrets stay on the server. Timeout, malformed data or unavailable permission checks deny protected content.

The supplied website examples use process-memory sessions and loopback HTTP opt-in. Production needs HTTPS, protected shared session/key storage, rotation, verified MFA and an independent protocol/security review. This implementation does not claim OIDC certification. See [INTEGRATION.md](INTEGRATION.md).

## Production work

Validate the OIDC deployment and add WebAuthn or a verified MFA provider; bind sessions to trusted context; strengthen abuse controls, CSRF protections as applicable, secure cookie/TLS settings, managed secret rotation, backup/retention, external audit checkpoints, migration tests and threat-model review. Validate independent data and business approvals before automated decisions.

For a suspected issue, record reproducible steps, affected module, impact and a proposed fix in a private channel. Never include credentials or sensitive request content in a public issue.
