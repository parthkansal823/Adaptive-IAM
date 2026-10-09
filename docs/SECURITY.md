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

Synthetic identity/context signals are demonstrative and can be chosen by the tester. They are not trusted device telemetry. Public bootstrap credentials and UI-displayed demo challenges are not production authentication factors. Local process memory and SQLite are not a high-availability identity provider. Audit and resource access use the same host trust boundary. The console exposes organization-wide review/audit metadata to its authenticated demo users; it does not implement tenant isolation or private enterprise log-reader roles.

LLM justification text is untrusted input. Reviewer recommendations must remain recommendations. A generic pretrained transformer does not supply calibrated suspicious-request probabilities without task-specific training.

## Production work

Integrate OIDC/SSO and WebAuthn or a verified MFA provider; bind sessions to trusted context; add rate limits and lockout policies, CSRF protections as applicable, secure cookie/TLS settings, managed secret rotation, backup/retention, external audit checkpoints, migration tests and threat-model review. Validate independent data and business approvals before automated decisions.

For a suspected issue, record reproducible steps, affected module, impact and a proposed fix in a private channel. Never include credentials or sensitive request content in a public issue.
