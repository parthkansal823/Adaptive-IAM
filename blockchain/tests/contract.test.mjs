import assert from 'node:assert/strict';
import test from 'node:test';
import ganache from 'ganache';
import {BrowserProvider, ContractFactory, sha256, toUtf8Bytes, ZeroHash} from 'ethers';
import {compile} from '../scripts/compile.mjs';

const TEST_MNEMONIC = 'test test test test test test test test test test test junk';
const hash = value => sha256(toUtf8Bytes(value));
// A submitted transaction is not a success: Ganache can return a hash for a
// reverted transaction when ethers reuses a cached estimate for identical input.
const rejectedTransaction = send => assert.rejects(async () => {
  const transaction = await send();
  await transaction.wait();
});

test('real EVM audit anchors, trusted writer, identity-bound grants, revocation and expiry', async () => {
  const rpc = ganache.provider({chain: {chainId: 31337, hardfork: 'shanghai'}, wallet: {mnemonic: TEST_MNEMONIC, totalAccounts: 2}, logging: {quiet: true}});
  const provider = new BrowserProvider(rpc);
  const owner = await provider.getSigner(0), outsider = await provider.getSigner(1);
  const artifact = compile();
  const registry = await new ContractFactory(artifact.abi, artifact.bytecode, owner).deploy();
  await registry.waitForDeployment();
  assert.equal(await registry.writer(), await owner.getAddress());
  await (await registry.anchorAudit(hash('event-1'), ZeroHash)).wait();
  assert.equal(await registry.auditCount(), 1n);
  assert.equal(await registry.auditHead(), hash('event-1'));
  await rejectedTransaction(() => registry.anchorAudit(ZeroHash, hash('event-1')));
  await rejectedTransaction(() => registry.anchorAudit(hash('tampered-event'), ZeroHash));
  await rejectedTransaction(() => registry.connect(outsider).anchorAudit(hash('event-2'), hash('event-1')));
  const timestamp = (await provider.getBlock('latest')).timestamp;
  await rejectedTransaction(() => registry.recordGrant(hash('too-long'), hash('aisha'), hash('resource'), timestamp+73*3600));
  await rejectedTransaction(() => registry.recordGrant(hash('empty-subject'), ZeroHash, hash('resource'), timestamp+90));
  await rejectedTransaction(() => registry.revokeGrant(hash('unknown-grant')));
  await (await registry.recordGrant(hash('grant-1'), hash('aisha'), hash('research-vault'), timestamp+90)).wait();
  assert.equal(await registry.hasAccess(hash('grant-1'), hash('aisha'), hash('research-vault')), true);
  assert.equal(await registry.hasAccess(hash('grant-1'), hash('outsider'), hash('research-vault')), false);
  assert.equal(await registry.hasAccess(hash('grant-1'), hash('aisha'), hash('other-resource')), false);
  await rejectedTransaction(() => registry.connect(outsider).revokeGrant(hash('grant-1')));
  await rejectedTransaction(() => registry.connect(outsider).recordGrant(hash('grant-2'), hash('aisha'), hash('resource'), timestamp+90));
  await rejectedTransaction(() => registry.recordGrant(hash('grant-1'), hash('aisha'), hash('research-vault'), timestamp+90));
  await (await registry.revokeGrant(hash('grant-1'))).wait();
  assert.equal(await registry.hasAccess(hash('grant-1'), hash('aisha'), hash('research-vault')), false);
  await (await registry.recordGrant(hash('grant-3'), hash('aisha'), hash('research-vault'), timestamp+90)).wait();
  await rpc.request({method: 'evm_increaseTime', params: [120]});
  await rpc.request({method: 'evm_mine', params: []});
  assert.equal(await registry.hasAccess(hash('grant-3'), hash('aisha'), hash('research-vault')), false);
  await rejectedTransaction(() => registry.recordGrant(hash('expired'), hash('aisha'), hash('resource'), timestamp+1));
  await rpc.disconnect();
});

test('contract refuses deployment on another chain', async () => {
  const rpc = ganache.provider({chain: {chainId: 1, hardfork: 'shanghai'}, logging: {quiet: true}});
  const provider = new BrowserProvider(rpc);
  const artifact = compile();
  await assert.rejects(async () => {
    const registry = await new ContractFactory(artifact.abi, artifact.bytecode, await provider.getSigner()).deploy();
    await registry.waitForDeployment();
  });
  await rpc.disconnect();
});
