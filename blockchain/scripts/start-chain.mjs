import fs from 'node:fs';
import path from 'node:path';
import ganache from 'ganache';
import {root} from './compile.mjs';

// This is a publicly known development mnemonic, never a secret or funded wallet.
export const TEST_MNEMONIC = 'test test test test test test test test test test test junk';
const host = process.env.CHAIN_HOST ?? '127.0.0.1';
if (!['127.0.0.1', 'localhost', '0.0.0.0'].includes(host)) throw new Error('Only local development bind hosts are supported');
if (host === '0.0.0.0' && process.env.IAM_DOCKER_CHAIN !== '1') throw new Error('All-interface binding is permitted only in the internal Docker chain service');
const data = process.env.CHAIN_DATA_DIR ?? path.join(root, 'data');
fs.mkdirSync(data, {recursive: true});
const server = ganache.server({chain: {chainId: 31337, networkId: 31337, hardfork: 'shanghai'}, wallet: {mnemonic: TEST_MNEMONIC, totalAccounts: 3, defaultBalance: 1000}, database: {dbPath: data}, logging: {quiet: true}});
await server.listen(Number(process.env.CHAIN_PORT ?? 8545), host);
console.log('Local research Ethereum chain ready (chain 31337). Development accounts are public test identities; no wallet keys are printed.');
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {await server.close(); process.exit(0);});
