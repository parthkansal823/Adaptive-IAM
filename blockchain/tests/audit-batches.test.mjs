import assert from 'node:assert/strict';
import test from 'node:test';
import ganache from 'ganache';
import {BrowserProvider, ContractFactory, concat, sha256, solidityPacked, toUtf8Bytes, ZeroHash} from 'ethers';
import {compile} from '../scripts/compile.mjs';
import {validateOperation} from '../scripts/signer-operations.mjs';

const hash = value => sha256(toUtf8Bytes(value));
const leaf = (sequence, eventHash) => sha256(solidityPacked(['bytes1', 'uint64', 'bytes32'], ['0x00', sequence, eventHash]));
const pair = (left, right) => sha256(concat(['0x01', left, right]));
const splitAt = count => 2 ** Math.floor(Math.log2(count - 1));
function root(leaves) {
  if (leaves.length === 1) return leaves[0];
  const split = splitAt(leaves.length);
  return pair(root(leaves.slice(0, split)), root(leaves.slice(split)));
}
function pathFor(leaves, index) {
  if (leaves.length === 1) return [];
  const split = splitAt(leaves.length);
  return index < split ? [...pathFor(leaves.slice(0, split), index), root(leaves.slice(split))]
    : [...pathFor(leaves.slice(split), index - split), root(leaves.slice(0, split))];
}
const reverted = send => assert.rejects(async () => { await (await send()).wait(); });

test('EVM batch roots bind contiguous anchored history; ragged, balanced and singleton proofs verify', async () => {
  const rpc = ganache.provider({chain: {chainId: 31337, hardfork: 'shanghai'}, wallet: {deterministic: true, totalAccounts: 2}, logging: {quiet: true}});
  try {
    const provider = new BrowserProvider(rpc);
    const writer = await provider.getSigner(0), outsider = await provider.getSigner(1);
    const artifact = compile();
    const registry = await new ContractFactory(artifact.abi, artifact.bytecode, writer).deploy();
    await registry.waitForDeployment();
    const events = Array.from({length: 8}, (_, index) => hash(`fixture-event-${index + 1}`));
    let previous = ZeroHash;
    for (const eventHash of events) { await (await registry.anchorAudit(eventHash, previous)).wait(); previous = eventHash; }
    const first = events.slice(0, 3).map((eventHash, index) => leaf(index + 1, eventHash));
    const firstRoot = root(first);
    await reverted(() => registry.connect(outsider).anchorAuditBatch(1, 3, firstRoot, events[2], ZeroHash));
    await reverted(() => registry.anchorAuditBatch(1, 3, firstRoot, hash('wrong-end'), ZeroHash));
    await reverted(() => registry.anchorAuditBatch(1, 3, firstRoot, events[2], hash('wrong-parent')));
    await reverted(() => registry.anchorAuditBatch(1, 3, ZeroHash, events[2], ZeroHash));
    await reverted(() => registry.anchorAuditBatch(1, 9, firstRoot, events[7], ZeroHash));
    await (await registry.anchorAuditBatch(1, 3, firstRoot, events[2], ZeroHash)).wait();
    assert.equal(await registry.auditBatchCount(), 1n);
    assert.equal(await registry.auditBatchEnd(), 3n);
    assert.equal(await registry.auditBatchHead(), firstRoot);
    assert.deepEqual(Array.from(await registry.auditBatches(1)), [1n, 3n, firstRoot, events[2], ZeroHash]);
    for (let index = 0; index < first.length; index++) assert.equal(await registry.verifyAuditBatchInclusion(1, index + 1, events[index], pathFor(first, index)), true);
    assert.equal(await registry.verifyAuditBatchInclusion(1, 1, hash('tampered'), pathFor(first, 0)), false);
    assert.equal(await registry.verifyAuditBatchInclusion(1, 1, events[0], pathFor(first, 0).slice(1)), false);
    assert.equal(await registry.verifyAuditBatchInclusion(1, 1, events[0], [...pathFor(first, 0), hash('extra')]), false);
    assert.equal(await registry.verifyAuditBatchInclusion(1, 1, events[0], pathFor(first, 0).reverse()), false);
    assert.equal(await registry.verifyAuditBatchInclusion(1, 4, events[3], []), false);
    assert.equal(await registry.verifyAuditBatchInclusion(2, 1, events[0], []), false);
    assert.equal(await registry.verifyAuditBatchInclusion(1, 1, ZeroHash, []), false);
    assert.equal(await registry.verifyAuditBatchInclusion(1, 1, events[0], Array(9).fill(hash('oversized'))), false);
    await reverted(() => registry.anchorAuditBatch(1, 3, firstRoot, events[2], firstRoot));
    await reverted(() => registry.anchorAuditBatch(5, 7, firstRoot, events[6], firstRoot));
    await reverted(() => registry.anchorAuditBatch(4, 260, firstRoot, events[6], firstRoot));
    const second = events.slice(3, 7).map((eventHash, index) => leaf(index + 4, eventHash));
    const secondRoot = root(second);
    await (await registry.anchorAuditBatch(4, 7, secondRoot, events[6], firstRoot)).wait();
    for (let index = 0; index < second.length; index++) assert.equal(await registry.verifyAuditBatchInclusion(2, index + 4, events[index + 3], pathFor(second, index)), true);
    const singletonRoot = leaf(8, events[7]);
    await (await registry.anchorAuditBatch(8, 8, singletonRoot, events[7], secondRoot)).wait();
    assert.equal(await registry.verifyAuditBatchInclusion(3, 8, events[7], []), true);
    assert.equal(await registry.auditCount(), 8n);
    assert.equal(await registry.hasAccess(hash('proof-is-not-a-grant'), hash('subject'), hash('resource')), false);
  } finally { await rpc.disconnect(); }
});

test('isolated signer validates bounded batch fields and continues to reject arbitrary operations', () => {
  const args = [1, 256, hash('root'), hash('end'), ZeroHash];
  assert.equal(validateOperation({kind: 'audit_batch', arguments: args}), 'anchorAuditBatch');
  for (const invalid of [
    [0, 1, ...args.slice(2)], [2, 1, ...args.slice(2)], [1, 257, ...args.slice(2)],
    ['1', ...args.slice(1)], [1.5, ...args.slice(1)], [1, Number.MAX_SAFE_INTEGER + 1, ...args.slice(2)],
    [1, 1, ZeroHash, args[3], ZeroHash], [1, 1, args[2], 'invalid', ZeroHash],
    [1, 1, args[2], args[3], 'invalid'], [...args, 'extra'],
  ]) assert.throws(() => validateOperation({kind: 'audit_batch', arguments: invalid}));
  assert.throws(() => validateOperation({kind: 'audit_batch', arguments: args, to: 'arbitrary-address'}));
  assert.throws(() => validateOperation({kind: 'transfer', arguments: args}));
  assert.equal(validateOperation({kind: 'audit', arguments: [hash('event'), ZeroHash]}), 'anchorAudit');
  assert.equal(validateOperation({kind: 'grant', arguments: [hash('grant'), hash('subject'), hash('resource'), 1001]}, 1000), 'recordGrant');
  assert.throws(() => validateOperation({kind: 'grant', arguments: [hash('grant'), hash('subject'), hash('resource'), 1000]}, 1000));
  assert.equal(validateOperation({kind: 'revoke', arguments: [hash('grant')]}), 'revokeGrant');
});
