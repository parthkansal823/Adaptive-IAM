# Web3 upgrade decisions

Reviewed 14 October 2026. This project uses a private EVM registry for audit checkpoints and expiring grants. Authentication and human authorization remain server enforced. Wallet ownership alone never grants a protected SaaS resource.

## Implemented

The isolated signer now uses ethers **6.17.0** with four fixed private RPC origins (`qbft1`–`qbft4`, port 8545), equal weight and a **three-response read quorum**. Each HTTP request has a 1500 ms timeout, retries are bounded, redirects cannot introduce another RPC destination, and there is no public-chain fallback. Before a signature, three validators must report a fresh, agreeing common block on research chain **31337**. A responding foreign-chain node rejects signing. The original narrow authenticated registry operations and signer-only writer key remain in place.

Signed bytes can be broadcast through the other validators when validator 1 is unavailable. A returned transaction hash is insufficient: the signer requires a successful receipt, and the backend independently verifies its writer, destination and status. The backend now selects a reader from the fresh common-block majority and rebuilds its Web3 connection when that alias changes. Local policy, audit-prefix validation, identity-bound grants, expiration and revocation still gate access. No cached receipt bypasses these checks.

Two compatibility problems were reproduced and addressed:

- ethers' fuzzy block-height path can attempt to parse an offline peer's transport error as a number. Height reads therefore use the stricter fresh common-block guard.
- Besu nodes may return the same finalized block hash with different commit-seal sets/order. Block comparison preserves all other RPC fields and the QBFT extra-data prefix, normalizes only commit seals and encoded size, and returns an original header with its seals intact. Other header disagreement still rejects the operation.

The provider supplements Besu consensus; it does not independently verify validator signatures. Three aliases on one Docker host remain one administrative trust boundary. See [network operation and limitations](WEB3_NETWORK.md), [ethers provider quorum](https://docs.ethers.org/v6/api/providers/fallback-provider/), [HTTP timeouts](https://docs.ethers.org/v6/api/utils/fetching/) and [Besu QBFT configuration](https://docs.besu-eth.org/private-networks/how-to/configure/consensus/qbft).

The official [Besu release list](https://github.com/besu-eth/besu/releases) still identifies **26.9.0** as the latest release at this review. Its existing image digest remains pinned. The legacy development tools now also pin ethers 6.17.0, Solidity **0.8.37** and advisory-fixed `tmp` **0.2.7**. Ganache bytecode still targets Shanghai; QBFT bytecode targets London. Retained chain data is not migrated or reset by these dependency changes.

## Verification

`blockchain/tests/rpc.test.mjs` uses real ephemeral HTTP JSON-RPC fixtures, mapped from the fixed private aliases inside the test transport. Eleven cases cover primary outage, two-node loss, wrong chain, stale/future heads, hash and state disagreement, QBFT seal normalization, a hung node, fixed endpoint enforcement and identical signed-byte broadcast. These are transport/security tests, not a consensus benchmark. Seven additional Python reader tests cover majority selection, primary failure, stale common blocks and connection refresh.

The reserved disposable live study supports:

```powershell
python blockchain/scripts/qbft-study.py --primary-outage
```

It writes `experiments/qbft-failover-results.json`, preserving the earlier `qbft-results.json`. Initial RPC chain-ID health can precede fresh QBFT finalization, so the driver permits a bounded 180-second signer readiness period. The recorded artifact must be consulted for completed live phases and latency; fixture counts do not establish those results.

The [14 October live artifact](../experiments/qbft-failover-results.json) records all five phases passing. With validator 1 stopped, IAM selected `qbft2`, allowed the existing approved grant and confirmed a new signed audit checkpoint. A second single-node outage also passed. Two stopped validators denied protected access/new anchors and held block height 143 over four seconds. Restarting the nodes restored access; the subsequent on-chain revocation denied the prior grant. Seven sequential confirmed transactions had median **887.89 ms**, range **755.19–6700.12 ms**; recovery plus revocation took **40.624 seconds**. These are local crash-outage readings, not production performance or Byzantine-resilience claims.

## Dependency findings and next development chain

After the direct upgrades and lockfile cleanup, the 14 October npm lockfile audit reports **7 vulnerable packages: 1 critical, 5 high and 1 moderate** in the legacy Ganache dependency tree. Earlier counts included extraneous bundled development metadata; they are not directly comparable to a clean installed tree. The separately built QBFT tools report **0 npm advisories** at this check. Neither number is a security certification or a claim about OS/JVM vulnerabilities.

Remaining legacy findings include Ganache's elliptic/secp256k1, WebSocket, lodash and bn.js dependency paths. `npm audit fix --force` proposes a Ganache **downgrade to 6.4.5** for some paths, which is not adopted. Verify current advisories with `npm audit --package-lock-only --omit=dev` in `blockchain/`; the registry can change after this review.

Consensys has [sunset Ganache](https://archive.trufflesuite.com/blog/consensys-announces-the-sunset-of-truffle-and-ganache-and-new-hardhat-partnership/). [Foundry Anvil](https://github.com/foundry-rs/foundry/tree/master/crates/anvil) is the selected candidate for a subsequent local-development replacement. That migration needs a pinned release/image, matching chain/fork configuration, contract and RPC compatibility checks, and an explicit retained-state plan. It has not been implemented in this change. Besu QBFT remains the implemented permissioned-consensus option.

## Wallet features researched, not enabled

| Option | Useful next step | Required boundary |
| --- | --- | --- |
| [ERC-4361 / Sign-In with Ethereum](https://eips.ethereum.org/EIPS/eip-4361) | Optional wallet authentication alongside the existing OIDC provider | Parse the standard message; verify exact origin/domain, URI, chain, signature, time window and one-use server nonce. Link an existing identity only after recent verified authentication. Keep resource approval separate. |
| [ERC-1271 contract signatures](https://eips.ethereum.org/EIPS/eip-1271) | Support smart-account or multisig owners in a future wallet login | Resolve verification on the specified chain; account for changing contract signature validity and invalidate affected sessions. A recovered EOA signature alone is insufficient. |
| [ERC-4337 account abstraction](https://eips.ethereum.org/EIPS/eip-4337) | Evaluate smart-account recovery or sponsored registry operations | Requires audited account logic and bundler/paymaster controls; no such infrastructure is deployed here. |
| [EIP-7702 delegated EOA code](https://eips.ethereum.org/EIPS/eip-7702) | Research wallet delegation only after the basic identity-link flow is reviewed | Delegation code can act with account authority. Avoid broad signing/delegation prompts and never present delegation as necessary for ordinary login. No delegation transaction is requested by this project. |

These options add different trust and operational requirements. None improves risk-model accuracy by itself. Independent operator administration, encrypted authenticated inter-host transport, HSM-backed signing, contract review and Byzantine fault campaigns remain external validation work.
