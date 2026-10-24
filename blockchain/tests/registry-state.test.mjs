import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import ganache from 'ganache';
import {BrowserProvider} from 'ethers';
import {readRetainedDeployment, requireUnusedRegistryWriter} from '../scripts/registry-state.mjs';

const identity = {chain_id: 31337, contract_address: '0x'+'11'.repeat(20), writer_address: '0x'+'22'.repeat(20)};
async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'iam-registry-state-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  return path.join(directory, 'deployment.json');
}

test('only absent deployment metadata permits first deployment', async t => {
  const filename = await fixture(t);
  assert.equal(await readRetainedDeployment(filename), null);
  await fs.writeFile(filename, JSON.stringify(identity));
  assert.deepEqual(await readRetainedDeployment(filename), identity);
  assert.equal(await fs.readFile(filename, 'utf8'), JSON.stringify(identity));
});

test('broken, oversized and foreign retained metadata is preserved and never treated as absent', async t => {
  const filename = await fixture(t);
  for (const body of ['', '{', 'null', '[]', '{}', JSON.stringify({...identity, chain_id: 1}), JSON.stringify({...identity, writer_address: 'bad'}), JSON.stringify({...identity, contract_address: null}), 'x'.repeat(65537)]) {
    await fs.writeFile(filename, body);
    await assert.rejects(readRetainedDeployment(filename), /existing state preserved/);
    assert.equal(await fs.readFile(filename, 'utf8'), body);
  }
});

test('missing metadata cannot redeploy after a confirmed or pending writer transaction', async () => {
  for (const counts of [[0, 0], [1, 1], [0, 1], [1, 0], [undefined, 0]]) {
    const seen = [];
    const provider = {getTransactionCount: async (writer, tag) => { seen.push({writer, tag}); return counts[tag === 'latest' ? 0 : 1]; }};
    if (counts.every(count => count === 0)) await requireUnusedRegistryWriter(provider, identity.writer_address);
    else await assert.rejects(requireUnusedRegistryWriter(provider, identity.writer_address), /refuse redeployment/);
    assert.deepEqual(seen, [{writer: identity.writer_address, tag: 'latest'}, {writer: identity.writer_address, tag: 'pending'}]);
  }
});

test('an actual EVM writer becomes ineligible for metadata-free deployment after its first transaction', async () => {
  const rpc = ganache.provider({chain: {chainId: 31337}, logging: {quiet: true}});
  const provider = new BrowserProvider(rpc, 31337, {cacheTimeout: -1});
  try {
    const writer = await provider.getSigner();
    const address = await writer.getAddress();
    await requireUnusedRegistryWriter(provider, address);
    await (await writer.sendTransaction({to: address, value: 0})).wait();
    await assert.rejects(requireUnusedRegistryWriter(provider, address), /refuse redeployment/);
  } finally {
    provider.destroy();
    await rpc.disconnect();
  }
});
