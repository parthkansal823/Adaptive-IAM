import fs from 'node:fs/promises';
import http from 'node:http';
import {timingSafeEqual} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {Contract, ContractFactory, JsonRpcProvider, NonceManager, Wallet, keccak256, toUtf8Bytes} from 'ethers';

const provider = new JsonRpcProvider('http://qbft1:8545', 31337, {staticNetwork: false, pollingInterval: 150});
if ((await provider.getNetwork()).chainId !== 31337n) throw new Error('Research chain only');
const password = (await fs.readFile('/signer/password', 'utf8')).trim();
const wallet = await Wallet.fromEncryptedJson(await fs.readFile('/signer/writer.json', 'utf8'), password);
const writer = new NonceManager(wallet.connect(provider));
const authToken = (await fs.readFile('/auth/token', 'utf8')).trim();
if (!/^[a-f0-9]{64}$/.test(authToken)) throw new Error('Missing isolated signer authentication');
const artifact = JSON.parse(await fs.readFile('/app/blockchain/artifacts/AccessGrantRegistry.json', 'utf8'));
const file = '/signer/deployment.json';
let metadata = await fs.readFile(file, 'utf8').then(JSON.parse).catch(() => null);
let registry;
if (metadata) {
  if (metadata.chain_id !== 31337 || await provider.getCode(metadata.contract_address) === '0x') throw new Error('Signer state does not match retained chain; refuse redeployment');
  registry = new Contract(metadata.contract_address, artifact.abi, writer);
} else {
  registry = await new ContractFactory(artifact.abi, artifact.bytecode, writer).deploy({gasLimit: 3000000, gasPrice: 0, type: 0});
  await registry.waitForDeployment();
  metadata = {network: 'qbft', chain_id: 31337, contract_address: await registry.getAddress(), writer_address: wallet.address, besu_version: '26.9.0', compiler_version: artifact.compilerVersion, evm_version: artifact.evmVersion};
  await fs.writeFile(file, JSON.stringify(metadata, null, 2), {mode: 0o600});
}
if ((await registry.writer()).toLowerCase() !== wallet.address.toLowerCase() || await registry.REGISTRY_VERSION() !== keccak256(toUtf8Bytes('AdaptiveIAM.AccessGrantRegistry.v1'))) throw new Error('Unexpected registry identity');
const hash = value => typeof value === 'string' && /^0x[a-fA-F0-9]{64}$/.test(value) && value !== '0x' + '00'.repeat(32);
export function validateOperation(packet) {
  if (!packet || typeof packet !== 'object' || Array.isArray(packet) || Object.keys(packet).sort().join(',') !== 'arguments,kind' || !Array.isArray(packet.arguments)) throw new Error('Unsupported operation');
  const args = packet.arguments;
  if (packet.kind === 'audit' && args.length === 2 && hash(args[0]) && typeof args[1] === 'string' && /^0x[a-fA-F0-9]{64}$/.test(args[1])) return 'anchorAudit';
  if (packet.kind === 'grant' && args.length === 4 && args.slice(0, 3).every(hash) && Number.isSafeInteger(args[3]) && args[3] > Math.floor(Date.now() / 1000) && args[3] <= Math.floor(Date.now() / 1000) + 72 * 3600) return 'recordGrant';
  if (packet.kind === 'revoke' && args.length === 1 && hash(args[0])) return 'revokeGrant';
  throw new Error('Invalid fixed registry operation');
}
let queue = Promise.resolve();
const server = http.createServer(async (req, res) => {
  const send = (status, payload) => {res.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'}); res.end(JSON.stringify(payload));};
  if (req.method === 'GET' && req.url === '/registry') return send(200, metadata);
  if (req.method !== 'POST' || req.url !== '/transaction') return send(404, {error: 'Unsupported signer endpoint'});
  const supplied = Buffer.from((req.headers.authorization ?? '').replace(/^Bearer /, ''));
  const expected = Buffer.from(authToken);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return send(401, {error: 'Signer authentication required'});
  let body = '';
  try {
    for await (const chunk of req) {body += chunk; if (body.length > 4096) return send(413, {error: 'Request too large'});}
    const packet = JSON.parse(body);
    const method = validateOperation(packet);
    const run = async () => {
      if ((await provider.getNetwork()).chainId !== 31337n) throw new Error('Research chain only');
      const started = performance.now();
      const tx = await registry[method](...packet.arguments, {gasLimit: 350000, gasPrice: 0, type: 0});
      const receipt = await Promise.race([tx.wait(), new Promise((_, reject) => setTimeout(() => reject(new Error('Confirmation timeout')), 12000))]);
      if (!receipt || receipt.status !== 1) throw new Error('Registry reverted');
      return {transaction_hash: receipt.hash, block_number: receipt.blockNumber, confirmation_ms: Math.round((performance.now() - started) * 100) / 100};
    };
    const job = queue.then(run);
    queue = job.catch(() => {writer.reset();});
    return send(200, await job);
  } catch {return send(400, {error: 'Registry operation rejected or not confirmed'});}
});
server.headersTimeout = 5000;
server.requestTimeout = 10000;
server.maxConnections = 32;
server.listen(9100, '0.0.0.0', () => console.log('Authenticated fixed-operation registry signer ready.'));
