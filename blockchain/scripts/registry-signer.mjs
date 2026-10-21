import fs from 'node:fs/promises';
import http from 'node:http';
import {timingSafeEqual} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import {Contract, ContractFactory, NonceManager, Wallet, keccak256, toUtf8Bytes} from 'ethers';
import {createQbftProvider, requireFreshQbftQuorum} from './qbft-provider.mjs';
import {validateOperation} from './signer-operations.mjs';
export {validateOperation} from './signer-operations.mjs';

const provider = createQbftProvider();
await requireFreshQbftQuorum(provider);
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
      await requireFreshQbftQuorum(provider);
      if ((await provider.getNetwork()).chainId !== 31337n) throw new Error('Research chain only');
      const started = performance.now();
      const tx = await registry[method](...packet.arguments, {gasLimit: 350000, gasPrice: 0, type: 0});
      let timeout;
      let receipt;
      try {
        receipt = await Promise.race([tx.wait(), new Promise((_, reject) => {timeout = setTimeout(() => reject(new Error('Confirmation timeout')), 12000);})]);
      } finally {clearTimeout(timeout);}
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
