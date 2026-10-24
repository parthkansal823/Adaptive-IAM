# Private Web3 network

Adaptive IAM now supports a four-validator **Besu QBFT** network with an isolated registry signer. The original Ganache development mode remains available. Both use research chain **31337** and the same `AccessGrantRegistry` authorization contract; neither connects to Mainnet, transfers funds, or uses a real user wallet.

The four containers run on one Docker host under one administrator. This tests actual signed, multi-validator EVM consensus and crash outages. It does **not** establish independent administration, Byzantine attack resilience or production decentralization. Besu's [QBFT tutorial](https://docs.besu-eth.org/private-networks/tutorials/qbft) requires four validators for Byzantine fault tolerance and recommends a properly configured firewall. The [consensus reference](https://docs.besu-eth.org/private-networks/how-to/configure/consensus/qbft) describes validator configuration and round timeout backoff.

## Start the optional console

From the repository root, with Docker Desktop Linux running:

```powershell
docker compose -f deployment/compose.qbft.yaml --profile console up --build -d --wait
```

Open the separate console at **http://127.0.0.1:15173/**. Its API and OAuth issuer are **http://127.0.0.1:18000/**. The default console at port 5173, its Ganache registry and its IAM data remain separate. Demo identities use the public password described in the main README; the new factor enrollment and secure-mode boundaries also apply to this console.

WebAuthn uses exact origin `http://127.0.0.1:15173` and RP ID `127.0.0.1`. OAuth redirects and registered website callbacks must match this issuer's application registrations. This separate installation has its own SQLite database, signing key, model cache and app registrations. Like the default stack, its API forwards `IAM_DEMO_MODE` from the environment and defaults to `true`; set it to `false` and follow [private identity provisioning](AUTHENTICATION.md) to disable public demo authentication.

Use `docker compose -f deployment/compose.qbft.yaml --profile console down` to stop this installation while preserving its volumes. Do not use `--volumes` for retained application evidence. The network prefix defaults to `172.29.83` and subnet to `172.29.83.0/24`; set `IAM_QBFT_PREFIX` and `IAM_QBFT_SUBNET` together if another local network already occupies that range.

## Key and network boundaries

- Four distinct validator private keys and four ledger volumes are generated once. Each validator mounts only its own key; the one-shot initializer has broader bootstrap access. Existing identities are retained; incomplete identity state causes initialization to fail, including an interrupted first run with keys but no final genesis marker. Creation uses exclusive writes. Retained registry metadata must also be readable, complete and bound to chain 31337; malformed metadata never triggers automatic redeployment. When metadata is absent, deployment requires an unused writer with both confirmed and pending transaction counts of zero. Missing metadata for a previously used writer requires recovery, including a crash between deployment and metadata publication. Restore a matching complete backup before retrying an interrupted or damaged installation.
- The writer key is a random Ethereum account held in an encrypted JSON keystore in the **signer-only** volume. Its unlock password co-resides there. This is container isolation and disk-format encryption, **not an HSM or protection against the Docker host administrator**.
- IAM receives only a read-only, random 256-bit signer authentication token and public network configuration. It never mounts the writer keystore, unlock password or validator keys. Public deployment metadata is read from the signer's `/registry` endpoint.
- The signer has one authenticated write endpoint. It only calls `anchorAudit`, `recordGrant` or `revokeGrant` on the single deployed registry. It accepts no arbitrary destination, transfer value, gas override, ABI, bytecode or calldata. Deploying the compiled registry happens at signer initialization, not through a public signing endpoint. Hash shape and the 72-hour grant limit are independently checked; the Solidity contract also enforces them.
- Besu has no unlocked accounts. Transactions use a signed, chain-ID-bound transaction. The adapter verifies the receipt's destination, writer, success status and a live grant separately.
- Validators and signer occupy an internal Docker bridge. **No RPC, peer or signer port is published.** Validators enable only ETH/NET/QBFT RPC, exact host allowlists, static peers and local node permissioning. Console/API additionally join an edge bridge for loopback publishing; that bridge permits their outbound traffic.
- Containers use non-root users, read-only root filesystems, dropped capabilities and no-new-privileges. Besu's temporary mount permits execution because it extracts its packaged JNA/RocksDB native libraries there. Other scratch mounts remain `noexec`.

The network image is official **Besu 26.9.0**, verified again on 14 October 2026 against its [release page](https://github.com/besu-eth/besu/releases/tag/26.9.0), pinned to multiarch digest `sha256:fc1813d67d630d7660eea6ee555c01e73bfecda3e54d24f9484c1c4a52c6fcb0`. The signer toolchain separately pins ethers 6.17.0, Solidity 0.8.37 and the advisory-fixed `tmp` 0.2.7 override; its clean build reported zero npm advisories at this review. The legacy Ganache tools now use these same direct ethers/compiler versions but retain bundled Ganache advisories; see [upgrade decisions](WEB3_UPGRADES.md). QBFT bytecode targets London; Ganache bytecode retains Shanghai.

## Live authority and outages

Set `IAM_WEB3_NETWORK=qbft`, RPC `http://qbft1:8545`, signer `http://registry-signer:9100`, and token path `/run/iam-signer/token` to use this adapter. Only exact private validator aliases `qbft1` through `qbft4`, port 8545, and exact signer alias/port 9100 are accepted. Explicit QBFT mode with a missing RPC fails closed.

Every protected grant lookup requires at least **three responsive validators** on chain 31337, each reporting a head no older than eight seconds, and three agreeing on a recent common block hash. This check is uncached. The normal audit-prefix, local owner/quorum, grant identity, expiry and revocation checks remain authoritative. Fewer than three validators, disagreement, a stale head, signer failure or registry mismatch denies access/confirmation. This read guard supplements Besu consensus; it does not independently reimplement block signature verification.

One validator crash leaves three validators and permits consensus. Losing two prevents finality and denies access. Returning nodes can take longer than the one-second configured block period: Besu consensus round timeouts back off after quorum loss. Recovery and outage delays must be measured rather than inferred from nominal block time. The signer now uses all four fixed aliases with three-response read/receipt agreement, a per-write fresh common-block guard and identical signed-byte broadcast. Backend readers select only an alias in the fresh agreeing majority. Validator 1 is a preference rather than the only submission or read endpoint. [Upgrade decisions](WEB3_UPGRADES.md) describe the QBFT block normalization and test evidence.

Revocation removes local permission immediately. A signed on-chain revocation is then retried/confirmed through the existing outbox. A receipt displayed in the UI is evidence, not authority to bypass a live check.

## Reproduce the measured study

Build the existing Linux analysis image as described in deployment documentation, then run:

```powershell
python blockchain/scripts/qbft-study.py
```

This host-side driver only controls the reserved disposable project `adaptive-iam-qbft-check`, using private subnet `172.29.84.0/24`. It never mounts a Docker socket into an application container and never connects to the normal IAM/Ganache or retained optional-console volumes. It runs baseline, one-node outage, two-node loss, then recovery/revocation and removes its own containers and volumes. `--keep` preserves only that disposable test project for diagnosis; a subsequent study resets its state.

Add `--primary-outage` to include a real validator-1 outage and write the separate artifact `experiments/qbft-failover-results.json`. The original result below remains historical evidence for its original implementation. The current driver waits up to 180 seconds for a fresh signer at startup; RPC chain-ID health alone does not prove that initial finality is ready.

The measured artifact is [experiments/qbft-results.json](../experiments/qbft-results.json). The 10 October 2026 run recorded:

| Case | Observed behavior |
| --- | --- |
| Four distinct validators | Signed checkpoints and identity-bound approved grant confirmed; no unlocked account |
| Missing signer token / arbitrary operation / extra destination / excessive grant duration | Rejected |
| One validator stopped | Three responsive validators; existing access allowed and a new checkpoint confirmed |
| Two validators stopped | Protected access and new anchors denied; block height stayed 21 over a four-second observation |
| Validators returned | Access resumed; signed revocation denied the previously valid grant |
| Six sequential confirmed transactions | Median 1010.445 ms; range 769.14–1415.76 ms |
| Recovery plus final revocation | 44.552 seconds from restarting the two nodes, including startup, polling and revocation |

Six Python boundary tests and four actual phase flows passed, as did two operator-export security tests. This is a small local crash-outage study with synthetic IAM state, not a throughput benchmark, production SLO or Byzantine fault campaign. The latency includes signer submission-to-receipt finality, not the entire human review process. No gains in model accuracy follow from using this chain.

The upgraded provider was separately measured on **14 October 2026** in [qbft-failover-results.json](../experiments/qbft-failover-results.json). All five phases passed, including validator 1 loss: reads selected `qbft2`, the existing approved grant remained available and a new signed checkpoint confirmed. Two-node loss denied access/anchors and held height 143 for four seconds. Recovery and on-chain revocation passed. The seven sequential transaction samples had median **887.89 ms**, range **755.19–6700.12 ms**; recovery plus revocation took **40.624 seconds**. Thirteen Python boundary/reader checks and the real phase check passed in each of the five phase executions. Eleven separate HTTP fixture tests cover malformed/disagreeing/stale state and transport failover. The same one-host and small-sample limitations apply.

## Prepare independently administered operators

The exporter `blockchain/scripts/qbft-operator-export.mjs` accepts **public identities supplied by four operators**. It validates that each address matches its public key, that all identities and private IPv4 addresses are distinct, and that endpoints lie in RFC 1918 private space. It outputs four separate Linux-host configuration packages. It never generates, reads or exports a private key and performs no deployment.

Each operator must generate and retain its own validator key locally. Use Besu's [public-key export/export-address subcommands](https://docs.besu-eth.org/public-networks/reference/subcommands#public-key) with an explicit local data/key path, and supply only the resulting public key/address to the coordinator. Prepare a public manifest of this shape:

```json
{
  "writer_address": "0x<public isolated writer address>",
  "validators": [
    {"alias": "qbft1", "address": "0x<validator address>", "public_key": "0x<128 hexadecimal public-key characters>", "private_ipv4": "10.80.0.10"},
    {"alias": "qbft2", "address": "0x<validator address>", "public_key": "0x<128 hexadecimal public-key characters>", "private_ipv4": "10.80.0.11"},
    {"alias": "qbft3", "address": "0x<validator address>", "public_key": "0x<128 hexadecimal public-key characters>", "private_ipv4": "10.80.0.12"},
    {"alias": "qbft4", "address": "0x<validator address>", "public_key": "0x<128 hexadecimal public-key characters>", "private_ipv4": "10.80.0.13"}
  ]
}
```

Placeholders deliberately do not form runnable identities. Run the exporter using installed Node dependencies:

```powershell
node blockchain/scripts/qbft-operator-export.mjs public-manifest.json artifacts/operators
```

Each package contains genesis, static peers, node permissions, compose and a README; it omits `node-key/key`. Review the identical genesis and public keys out-of-band before each operator supplies only its own local key and data directory owned by UID 10001. Keep those keys outside Git. Do not export the locally centrally generated development validator keys as independent operator identities.

The operator templates use Linux host networking, bind RPC/P2P to the explicitly supplied private interface and require a preconfigured authenticated private mesh plus firewall. Permit peer port 30303 only among the four operators; permit RPC 8545 only from authorized IAM/signer hosts. Supply private DNS aliases `qbft1`–`qbft4` to the IAM host. Keep signer token distribution and writer-keystore management with a separate trusted operator; use an external secret store/HSM and authenticated encrypted transport for a real deployment. These operational systems are not automatically provisioned or measured by the exporter. Multi-host deployment, administrator separation, governance/key rotation, backups and Byzantine fault testing remain external validation work.
