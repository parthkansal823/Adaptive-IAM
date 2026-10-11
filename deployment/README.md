# Docker research environment

From the project root, start Docker Desktop, then run:

```powershell
docker compose up --build -d
docker compose ps
```

Open http://127.0.0.1:5173. API discovery is at http://127.0.0.1:8000/.well-known/openid-configuration. These are deliberately HTTP loopback research endpoints, with public demo users/passwords. The stack is not an Internet identity provider and must not be exposed through a public tunnel.

The startup sequence is a persisted Ganache Ethereum chain (31337), a one-shot Solidity registry deployment, the API, then the frontend. The deployment metadata shares the API data volume. It reuses the existing registry on subsequent starts. A new chain requires matching new IAM state; independently deleting only one volume can produce a checkpoint mismatch that denies protected access.

Containers run without root, use a read-only root filesystem, drop Linux capabilities, disallow privilege escalation, and have memory/process limits. Temporary writable mounts and three named volumes hold chain data, IAM state/signing key, and model cache. The chain/deployer bridge is internal; RPC port 8545 is not published. API/frontend also join an edge bridge so Docker Desktop can publish their ports; only API 8000 and console 5173 are published to 127.0.0.1. That edge bridge permits outbound networking from the web services, so this configuration is not a complete outbound firewall. Docker isolation does not replace HTTPS, independent MFA, telemetry, key management, backups or a production security review.

## Real local Web3 behavior

`blockchain/contracts/AccessGrantRegistry.sol` is compiled with solc 0.8.30 for the Shanghai EVM. An unlocked, publicly known development writer anchors SHA-256 audit hashes and records hashed identity/resource grants with expiry. The contract enforces writer identity, monotonic hash-head linking, non-duplicate grants, bound identities/resources, revocation, and expiry on each read. No password, OTP, token, raw justification or wallet private key is written into the registry.

The backend's retryable outbox mirrors approved grants only after audit anchoring and a valid human owner/quorum decision. A security reviewer can invoke `POST /api/blockchain/sync`. Votes attempt an immediate sync after approval. Every protected console or website permission check requires both an active local grant and a live contract grant when Web3 is enabled. RPC outage, incompatible registry, wrong chain, revoked/expired grant or a changed checkpoint denies access. The UI should distinguish an approved local request from an on-chain confirmed grant.

This is one local Ethereum validator with a trusted writer, not decentralized production consensus. A privileged Docker/chain administrator can reset or manipulate that local chain. Identity hashes can be guessed from known demo names; hashes are not anonymization. Blockchain improves retained external checkpoint checking within this prototype, not the quality of attack labels or authentication telemetry.

## Operations

```powershell
docker compose logs --tail 60 api
docker compose stop
docker compose up -d
docker compose down
```

`down` preserves data volumes. Deleting named volumes permanently deletes research state and signing keys; do that only for an intentional reset. Do not add public RPC endpoints, fund the development wallet, or mount the Docker socket into a container.

Tests use isolated temporary IAM databases and ephemeral Ganache instances:

```powershell
npm --prefix blockchain test
python scripts/run_tests.py -s backend/tests
```

For the opt-in real RPC/API test, first build the analysis image (`docker build -f deployment/Dockerfile.analysis -t adaptive-iam-analysis:local .`), then:

```powershell
docker compose -f deployment/compose.web3-tests.yaml run --rm contract-tests
docker compose -f deployment/compose.web3-tests.yaml run --rm tests
docker compose -f deployment/compose.web3-tests.yaml down --volumes
```

That separate project has no published ports, uses an ephemeral chain, and stores public deployment metadata in its own test volume. The final command removes only the isolated test project's state. The ordinary backend suite skips its real RPC case unless `IAM_TEST_WEB3_RPC_URL` is explicitly supplied.

Image tags select supported runtime families; they are not immutable digest pins. For reproducible production packaging, review and record image digests and perform dependency/image vulnerability scans.

The checked-in blockchain npm lockfile explicitly marks Ganache's bundled macOS-only `fsevents` dependency as optional, matching its parent Chokidar declaration. Ganache's generated bundled lock omitted that flag and caused `npm ci` to reject Linux; the correction preserves its version and integrity and does not use `--force`.

## Private identity configuration

`IAM_DEMO_MODE` is explicitly passed through Compose (default `true`). For private research use, set it to `false`, provision private identities offline and keep a separate project/volume set. Stop the default stack before binding the same ports. Do not run this operator workflow while its API is serving requests.

```powershell
$env:IAM_DEMO_MODE = 'false'
docker compose -p adaptive-iam-private up -d chain registry-deploy
docker compose -p adaptive-iam-private run --rm --no-deps -it --volume "${PWD}/scripts/provision_identity.py:/app/scripts/provision_identity.py:ro" api python scripts/provision_identity.py --database /var/lib/iam/iam.sqlite3 --user-id operator --name "Research operator" --department Security --role security_reviewer
docker compose -p adaptive-iam-private up -d --wait api frontend
```

The passphrase prompt never enters a command-line argument. First private sign-in permits only five minutes of factor enrollment. Complete TOTP/passkey enrollment before requesting resources or managing applications. Public seed passwords, previous demo sessions and arbitrary browser context do not authenticate private identities. The automatic `website-register` service uses public demo setup and is not the private onboarding mechanism; register a private website through the Developer portal after verified enrollment, then supply its one-time credentials to its server. See [authentication contracts](../docs/AUTHENTICATION.md).

The optional [QBFT deployment](../docs/WEB3_NETWORK.md) runs four Besu validators and an isolated constrained signer in a different project on ports 15173/18000. Its outage readings are real local consensus observations, with shared-host administration and a small sample explicitly disclosed.
