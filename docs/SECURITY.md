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
- When Web3 is configured, require a live identity/resource-bound contract grant and a matching audit checkpoint. Deny access on chain outage, wrong chain/registry, mismatch, pending grant, expiry or revocation.

## Known prototype limitations

Demo context signals can be chosen by the tester; secure mode instead observes partial request context and ignores client scenario claims. Neither supplies comprehensive trusted device telemetry. Public bootstrap passwords/displayed demo challenges are not production factors. Enrolled passkeys/TOTP and recovery codes are verified server-side. Local process memory and SQLite are not a high-availability identity provider. Requests/audit views are scoped to requester/reviewers; grants to grantee/owner. Organizations scope application management and membership, but shared research identities/resources are not fully isolated tenants.

LLM justification text is untrusted input. Reviewer recommendations must remain recommendations. A generic pretrained transformer does not supply calibrated suspicious-request probabilities without task-specific training.

## Website identity and permission

Registered clients use exact callback matching, S256 PKCE, consent, one-use codes and client-bound scopes/resources. App access tokens have no console-session authority. Relying-party SDKs validate RS256 signing keys, issuer, audience, nonce, expiry and UserInfo subject before creating their server-side website session. Every protected response checks a subject/client/resource-bound live read grant. Identity consent alone grants no resource access. Website cookies contain random session keys; access tokens and confidential client secrets stay on the server. Timeout, malformed data or unavailable permission checks deny protected content.

The Node website supports encrypted SQLite login/session persistence on a shared local filesystem; Docker enables it in a separate private volume. Memory mode and the Python example remain available. Cookie IDs are hashed in storage; AES-GCM binds encrypted tokens and PKCE state to their scope, kind, ID and expiry. Login state is consumed atomically, and protected responses recheck local session authority after provider calls. The database, encryption key and parent directory require trusted OS control. Encryption does not detect restoration of an older valid snapshot or protect against an administrator who can read both database and key. This is same-host persistence, not multi-host availability.

Codes/app tokens also depend on their originating console session: logout, expiry, revocation, enrollment restrictions and detected step-up deny authority. Loopback HTTP remains an explicit development opt-in. Production needs HTTPS, managed key custody/rotation, multi-host session infrastructure, operational factor recovery and an independent protocol/security review. This implementation does not claim OIDC certification. See [INTEGRATION.md](INTEGRATION.md), [verified authentication](AUTHENTICATION.md), and [offline backup/restore](BACKUP.md). Backups contain plaintext private credentials and must stay in protected storage; SQLite/hash validation does not authenticate their provenance.

## Docker and local Web3

The Docker stack uses non-root users, read-only root filesystems, dropped capabilities, no privilege escalation and bounded resources. The chain/deployer use an internal bridge; API/UI and the optional website also join an edge bridge that permits their outbound traffic. Ethereum RPC is unpublished; exposed web ports bind to host loopback. Persistent volumes hold chain state, IAM state/signing key and model cache. Avoid independently resetting one state volume: mismatched retained checkpoints deliberately deny access. [Deployment operations](../deployment/README.md) document shutdown and persistence.

The local Ethereum writer uses an unlocked development account on chain 31337. The adapter rejects external RPC hosts and other chain IDs. Do not fund or use this wallet on a public network. Solidity only accepts the trusted writer; human eligibility/quorum is enforced by the API before mirroring, not independently by the contract. A host/chain administrator can reset the single local chain. Hashes of demo identities remain guessable and linkable; credentials, tokens, OTPs and raw justification text are excluded from on-chain data. This is real EVM execution with a local trust boundary, not production decentralization or anonymization.

On 21 October 2026, `npm audit --omit=dev` reported seven vulnerable packages in the [Ganache dependency tree](WEB3_UPGRADES.md#dependency-findings-and-next-development-chain): one critical, five high and one moderate, including the [elliptic signing advisory](https://github.com/advisories/GHSA-vjh7-7g9h-fjfh). These remain a limitation of the local development chain. The npm registry still lists our pinned Ganache 7.9.2 as latest; no newer upstream release is available, and npm's proposed downgrade to 6.4.5 was not applied. The separately packaged QBFT signer uses its own ethers/solc manifest; its read-only lockfile audit reported zero findings in this run. That result does not certify the service, operating system or JVM as vulnerability-free.

## Production work

Validate OIDC interoperability and physical passkey/authenticator usability; strengthen trusted device telemetry, abuse controls, cookie/TLS settings, managed key rotation, backup/retention, database migrations and threat-model review. Test independent data and business approvals before automated decisions. The optional [four-validator QBFT network](WEB3_NETWORK.md) has real measured crash behavior but shares one administrative host; independent operators, Byzantine testing, signer HSM and resilient submission endpoints remain operational work.

For a suspected issue, record reproducible steps, affected module, impact and a proposed fix in a private channel. Never include credentials or sensitive request content in a public issue.
