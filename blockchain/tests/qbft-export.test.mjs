import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {SigningKey, Wallet, decodeRlp} from 'ethers';

const script = fileURLToPath(new URL('../scripts/qbft-operator-export.mjs', import.meta.url));
function manifest() {
  const validators = Array.from({length: 4}, (_, i) => {
    const wallet = Wallet.createRandom();
    return {alias: `qbft${i+1}`, address: wallet.address, public_key: '0x'+SigningKey.computePublicKey(wallet.privateKey, false).slice(4), private_ipv4: `10.80.0.${i+10}`};
  });
  return {validators, writer_address: Wallet.createRandom().address};
}
test('operator export produces public genesis and four isolated packages without key material', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'iam-qbft-export-'));
  try {
    const packet = manifest();
    const input = path.join(directory, 'public.json');
    const output = path.join(directory, 'operators');
    await fs.writeFile(input, JSON.stringify(packet));
    const result = spawnSync(process.execPath, [script, input, output], {encoding: 'utf8'});
    assert.equal(result.status, 0, result.stderr);
    const genesis = JSON.parse(await fs.readFile(path.join(output, 'qbft1/genesis.json'), 'utf8'));
    assert.equal(genesis.config.chainId, 31337);
    assert.equal(decodeRlp(genesis.extraData)[1].length, 4);
    const files = await fs.readdir(path.join(output, 'qbft1'));
    assert.equal(files.length, 5);
    assert.ok(!files.includes('key'));
    const compose = await fs.readFile(path.join(output, 'qbft1/compose.yaml'), 'utf8');
    assert.ok(compose.includes('--rpc-http-host=10.80.0.10'));
    assert.ok(compose.includes('sha256:fc1813'));
    assert.ok(!compose.includes('privateKey'));
  } finally {await fs.rm(directory, {recursive: true, force: true});}
});
test('operator export rejects public endpoints, mismatched identities and duplicate validators', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'iam-qbft-invalid-'));
  try {
    for (const corrupt of [packet => {packet.validators[0].private_ipv4 = '8.8.8.8';}, packet => {packet.validators[0].address = Wallet.createRandom().address;}, packet => {packet.validators[1] = {...packet.validators[0], alias: 'qbft2', private_ipv4: '10.80.0.11'};}]) {
      const packet = manifest();
      corrupt(packet);
      const input = path.join(directory, 'public.json');
      await fs.writeFile(input, JSON.stringify(packet));
      const result = spawnSync(process.execPath, [script, input, path.join(directory, 'operators')], {encoding: 'utf8'});
      assert.notEqual(result.status, 0);
    }
  } finally {await fs.rm(directory, {recursive: true, force: true});}
});
