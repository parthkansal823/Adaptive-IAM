import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import solc from 'solc';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export function compile() {
  const source = fs.readFileSync(path.join(root, 'contracts/AccessGrantRegistry.sol'), 'utf8');
  const input = {language: 'Solidity', sources: {'AccessGrantRegistry.sol': {content: source}}, settings: {
    optimizer: {enabled: true, runs: 200}, evmVersion: 'shanghai',
    outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object']}}
  }};
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter(item => item.severity === 'error');
  if (errors.length) throw new Error(errors.map(item => item.formattedMessage).join('\n'));
  const contract = output.contracts['AccessGrantRegistry.sol'].AccessGrantRegistry;
  const artifact = {contractName: 'AccessGrantRegistry', compilerVersion: solc.version(), evmVersion: 'shanghai', abi: contract.abi, bytecode: `0x${contract.evm.bytecode.object}`, deployedBytecode: `0x${contract.evm.deployedBytecode.object}`};
  fs.mkdirSync(path.join(root, 'artifacts'), {recursive: true});
  fs.writeFileSync(path.join(root, 'artifacts/AccessGrantRegistry.json'), `${JSON.stringify(artifact, null, 2)}\n`);
  return artifact;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  compile();
  console.log('Compiled AccessGrantRegistry for the Shanghai EVM.');
}
