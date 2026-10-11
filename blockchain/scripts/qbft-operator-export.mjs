import fs from 'node:fs/promises';
import path from 'node:path';
import {computeAddress, encodeRlp, isAddress} from 'ethers';

// Accept only public independently supplied validator identities. This tool
// cannot create, import, print or export a private key.
const [manifestFile, outputDirectory] = process.argv.slice(2);
if (!manifestFile || !outputDirectory) throw new Error('Usage: node qbft-operator-export.mjs public-manifest.json output-directory');
const manifest = JSON.parse(await fs.readFile(manifestFile, 'utf8'));
const validators = manifest.validators;
if (!Array.isArray(validators) || validators.length !== 4 || !isAddress(manifest.writer_address)) throw new Error('Four public validators and a writer address required');
const privateAddress = value => {
  if (typeof value !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return false;
  const parts = value.split('.').map(Number);
  return parts.every(p => p <= 255) && (parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168));
};
for (let i = 0; i < 4; i++) {
  const node = validators[i];
  if (node.alias !== `qbft${i + 1}` || !isAddress(node.address) || !/^0x[0-9a-fA-F]{128}$/.test(node.public_key) || !privateAddress(node.private_ipv4) || computeAddress('0x04' + node.public_key.slice(2)).toLowerCase() !== node.address.toLowerCase()) throw new Error('Invalid public validator identity or private IP');
}
if (new Set(validators.map(node => node.address.toLowerCase())).size !== 4 || new Set(validators.map(node => node.private_ipv4)).size !== 4) throw new Error('Independent validator identities and IPs must be distinct');
const sorted = validators.map(node => node.address.toLowerCase()).sort();
const genesis = {config: {chainId: 31337, homesteadBlock: 0, eip150Block: 0, eip155Block: 0, eip158Block: 0, byzantiumBlock: 0, constantinopleBlock: 0, petersburgBlock: 0, istanbulBlock: 0, berlinBlock: 0, londonBlock: 0, zeroBaseFee: true, qbft: {blockperiodseconds: 1, epochlength: 30000, requesttimeoutseconds: 4}}, nonce: '0x0', timestamp: '0x0', extraData: encodeRlp(['0x'+'00'.repeat(32), sorted, [], '0x', []]), gasLimit: '0x1c9c380', difficulty: '0x1', mixHash: '0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365', coinbase: '0x'+'00'.repeat(20), alloc: {[manifest.writer_address.toLowerCase().slice(2)]: {balance: '0x0'}}};
const enodes = validators.map(node => `enode://${node.public_key.slice(2)}@${node.private_ipv4}:30303`);
const output = path.resolve(outputDirectory);
await fs.mkdir(output, {recursive: true});
for (const node of validators) {
  const directory = path.join(output, node.alias);
  await fs.mkdir(directory, {recursive: true});
  await fs.writeFile(path.join(directory, 'genesis.json'), JSON.stringify(genesis, null, 2)+'\n');
  await fs.writeFile(path.join(directory, 'static-nodes.json'), JSON.stringify(enodes, null, 2)+'\n');
  await fs.writeFile(path.join(directory, 'permissions_config.toml'), `nodes-allowlist=[${enodes.map(value => JSON.stringify(value)).join(',')}]\n`);
  await fs.writeFile(path.join(directory, 'compose.yaml'), `name: iam-operator-${node.alias}\nservices:\n  validator:\n    image: hyperledger/besu:26.9.0@sha256:fc1813d67d630d7660eea6ee555c01e73bfecda3e54d24f9484c1c4a52c6fcb0\n    user: '10001:10001'\n    network_mode: host\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    restart: unless-stopped\n    mem_limit: 1g\n    environment: {JAVA_OPTS: '-Xms128m -Xmx512m'}\n    tmpfs: ['/tmp:rw,exec,nosuid,size=64m']\n    volumes: ['./node-key:/node-key:ro', './genesis.json:/config/genesis.json:ro', './static-nodes.json:/var/lib/besu/static-nodes.json:ro', './permissions_config.toml:/config/permissions_config.toml:ro', './data:/var/lib/besu']\n    command: ['--node-private-key-file=/node-key/key', '--data-path=/var/lib/besu', '--genesis-file=/config/genesis.json', '--sync-mode=FULL', '--discovery-enabled=false', '--p2p-interface=${node.private_ipv4}', '--p2p-host=${node.private_ipv4}', '--rpc-http-enabled=true', '--rpc-http-host=${node.private_ipv4}', '--rpc-http-api=ETH,NET,QBFT', '--host-allowlist=${node.alias},${node.private_ipv4}', '--permissions-nodes-config-file-enabled=true', '--permissions-nodes-config-file=/config/permissions_config.toml', '--min-gas-price=0']\n`);
  await fs.writeFile(path.join(directory, 'README.md'), `# ${node.alias} operator package\n\nLinux host private address: ${node.private_ipv4}. Independently generated public validator: ${node.address}. Supply only this operator's private key at node-key/key; it is deliberately absent from this package. Prepare data/ owned by UID 10001, private mesh routing and firewall before starting. The RPC binds only to the listed private interface. No deployment was performed by the exporter. Read docs/WEB3_NETWORK.md in the source project.\n`);
}
console.log('Exported four public configuration packages; no keys exported and no network deployed.');
