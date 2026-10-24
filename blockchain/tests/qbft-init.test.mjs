import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {Wallet} from 'ethers';
import {initializeQbft} from '../scripts/qbft-init.mjs';

const managed = ['network/genesis.json', 'network/static-nodes.json', 'network/permissions_config.toml', 'network/operators.json', 'validator1/key', 'validator2/key', 'validator3/key', 'validator4/key', 'signer/writer.json', 'signer/password', 'auth/token'];
async function fixture(t) {
  const rootDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'iam-qbft-init-'));
  t.after(() => fs.rm(rootDirectory, {recursive: true, force: true}));
  await Promise.all(['network', 'validator1', 'validator2', 'validator3', 'validator4', 'signer', 'auth'].map(name => fs.mkdir(path.join(rootDirectory, name))));
  return rootDirectory;
}

test('interrupted initialization never overwrites a retained validator or signer identity', async t => {
  for (const retained of ['validator1/key', 'signer/writer.json', 'network/operators.json']) {
    const rootDirectory = await fixture(t);
    await fs.writeFile(path.join(rootDirectory, retained), 'retained-identity-fixture');
    await assert.rejects(initializeQbft({rootDirectory, log: () => {}}), /Incomplete QBFT state/);
    assert.equal(await fs.readFile(path.join(rootDirectory, retained), 'utf8'), 'retained-identity-fixture');
    await assert.rejects(fs.stat(path.join(rootDirectory, 'network/genesis.json')), {code: 'ENOENT'});
  }
});

test('a complete network is reused without writing any managed file', async t => {
  const rootDirectory = await fixture(t);
  for (const name of managed) await fs.writeFile(path.join(rootDirectory, name), `retained-${name}`);
  const messages = [];
  await initializeQbft({rootDirectory, log: message => messages.push(message)});
  assert.deepEqual(messages, ['Existing private network identities preserved.']);
  for (const name of managed) assert.equal(await fs.readFile(path.join(rootDirectory, name), 'utf8'), `retained-${name}`);
});

test('a final genesis marker never hides missing or truncated retained state', async t => {
  for (const truncated of [false, true]) {
    const rootDirectory = await fixture(t);
    await fs.writeFile(path.join(rootDirectory, 'network/genesis.json'), 'retained-genesis');
    if (truncated) await fs.writeFile(path.join(rootDirectory, 'validator1/key'), '');
    await assert.rejects(initializeQbft({rootDirectory, log: () => {}}), /retained QBFT state|Incomplete QBFT state/);
    assert.equal(await fs.readFile(path.join(rootDirectory, 'network/genesis.json'), 'utf8'), 'retained-genesis');
  }
});

test('first initialization creates usable identities and a retry preserves their exact bytes', async t => {
  const rootDirectory = await fixture(t);
  await initializeQbft({rootDirectory, log: () => {}});
  const original = await Promise.all(managed.map(name => fs.readFile(path.join(rootDirectory, name))));
  const operators = JSON.parse(await fs.readFile(path.join(rootDirectory, 'network/operators.json'), 'utf8'));
  assert.equal(new Set(operators.validators.map(node => node.address)).size, 4);
  const password = await fs.readFile(path.join(rootDirectory, 'signer/password'), 'utf8');
  const writer = await Wallet.fromEncryptedJson(await fs.readFile(path.join(rootDirectory, 'signer/writer.json'), 'utf8'), password);
  assert.equal(writer.address, operators.writer_address);
  await initializeQbft({rootDirectory, log: () => {}});
  const reused = await Promise.all(managed.map(name => fs.readFile(path.join(rootDirectory, name))));
  assert.deepEqual(reused, original);
});
