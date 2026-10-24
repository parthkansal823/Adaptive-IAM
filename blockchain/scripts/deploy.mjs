import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Contract, ContractFactory, JsonRpcProvider} from 'ethers';
import {compile, root} from './compile.mjs';
import {readRetainedDeployment, requireUnusedRegistryWriter} from './registry-state.mjs';

const rpc = process.env.IAM_WEB3_RPC_URL ?? 'http://127.0.0.1:8545';
const parsed = new URL(rpc);
if (parsed.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]', 'chain'].includes(parsed.hostname) || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error('Only local HTTP research RPC is allowed');
const provider = new JsonRpcProvider(rpc, undefined, {staticNetwork: false});
const network = await provider.getNetwork();
if (network.chainId !== 31337n) throw new Error('Refusing any network except local chain 31337');
const artifact = compile();
const output = process.env.IAM_WEB3_DEPLOYMENT_FILE ?? path.resolve(root, '../backend/data/deployment.json');
fs.mkdirSync(path.dirname(output), {recursive: true});
let deployed;
const previous = await readRetainedDeployment(output);
if (previous) {
  if (await provider.getCode(previous.contract_address) === '0x') throw new Error('Retained deployment does not match this chain; refuse redeployment');
  deployed = new Contract(previous.contract_address, artifact.abi, provider);
  if (await deployed.writer() !== await (await provider.getSigner(0)).getAddress()) throw new Error('Existing deployment has an unexpected writer');
}
if (!deployed) {
  const writer = await provider.getSigner(0); // Local unlocked account; no embedded private key.
  await requireUnusedRegistryWriter(provider, await writer.getAddress());
  deployed = await new ContractFactory(artifact.abi, artifact.bytecode, writer).deploy();
  await deployed.waitForDeployment();
}
const metadata = {chain_id: 31337, contract_address: await deployed.getAddress(), writer_address: await deployed.writer(), contract_name: artifact.contractName, compiler_version: artifact.compilerVersion, evm_version: artifact.evmVersion, deployed_at: new Date().toISOString()};
fs.writeFileSync(output, `${JSON.stringify(metadata, null, 2)}\n`);
console.log(JSON.stringify(metadata)); // All fields are public chain metadata, never wallet secrets.
provider.destroy();
