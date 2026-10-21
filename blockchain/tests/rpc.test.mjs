import assert from 'node:assert/strict';
import http from 'node:http';
import {after, before, test} from 'node:test';
import {FetchRequest, Wallet, keccak256, encodeRlp} from 'ethers';
import {createQbftProvider, QBFT_RPC_URLS, QBFT_REQUEST_TIMEOUT_MS, requireFreshQbftQuorum} from '../scripts/qbft-provider.mjs';

const originalTransport = FetchRequest.createGetUrlFunc();
let fixture;
let states;
const seen = [];
const fresh = () => Math.floor(Date.now() / 1000);
const block = state => ({
  number: '0x20', timestamp: `0x${(fresh() + (state.age ?? 0)).toString(16)}`, hash: `0x${(state.hash ?? 'aa').repeat(32)}`,
  parentHash: '0x'+'bb'.repeat(32), nonce: '0x'+'00'.repeat(8), difficulty: '0x1',
  gasLimit: '0x1c9c380', gasUsed: '0x0', baseFeePerGas: '0x0', miner: state.miner ?? '0x'+'11'.repeat(20), transactions: [],
  extraData: encodeRlp(['0x'+'00'.repeat(32), [], [], '0x', ['0x'+(state.seal ?? 'cc').repeat(65)]]), size: state.size ?? '0x100',
});

before(async () => {
  fixture = http.createServer(async (request, response) => {
    const index = Number(request.url.slice(1));
    const state = states[index];
    let body = '';
    for await (const part of request) body += part;
    const packet = JSON.parse(body);
    seen.push({index, method: packet.method, params: packet.params});
    if (state.down) {response.destroy(); return;}
    if (state.hang) return;
    let result;
    switch (packet.method) {
      case 'eth_chainId': result = state.chain ?? '0x7a69'; break;
      case 'eth_blockNumber': result = '0x20'; break;
      case 'eth_getBlockByNumber': result = block(state); break;
      case 'eth_getCode': result = state.code ?? '0x6000'; break;
      case 'eth_getTransactionCount': result = '0x0'; break;
      case 'eth_sendRawTransaction': result = keccak256(packet.params[0]); break;
      default: response.writeHead(200, {'content-type': 'application/json'}); response.end(JSON.stringify({id: packet.id, jsonrpc: '2.0', error: {code: -32601, message: 'Fixture method unavailable'}})); return;
    }
    response.writeHead(200, {'content-type': 'application/json'});
    response.end(JSON.stringify({jsonrpc: '2.0', id: packet.id, result}));
  });
  await new Promise(resolve => fixture.listen(0, '127.0.0.1', resolve));
  // Production code still addresses only fixed qbft1..4 endpoints. The test
  // transport maps those exact aliases onto real ephemeral loopback HTTP RPCs.
  FetchRequest.registerGetUrl(async (request, signal) => {
    const index = QBFT_RPC_URLS.indexOf(request.url);
    assert.notEqual(index, -1, 'No unexpected network destination');
    const mapped = request.clone();
    mapped.url = `http://127.0.0.1:${fixture.address().port}/${index}`;
    return originalTransport(mapped, signal);
  });
});

after(async () => {
  FetchRequest.registerGetUrl(originalTransport);
  fixture.closeAllConnections();
  await new Promise(resolve => fixture.close(resolve));
});

async function network(run) {
  states = Array.from({length: 4}, () => ({}));
  seen.length = 0;
  const provider = createQbftProvider();
  try {await run(provider);} finally {await provider.destroy();}
}

test('provider fixes four private endpoints, bounded transport and equal three-read quorum', async () => network(async provider => {
  assert.equal(provider.quorum, 3);
  assert.deepEqual(provider.providerConfigs.map(config => config.weight), [1, 1, 1, 1]);
  for (const [index, {provider: child}] of provider.providerConfigs.entries()) {
    const request = child._getConnection();
    assert.equal(request.url, QBFT_RPC_URLS[index]);
    assert.equal(request.timeout, QBFT_REQUEST_TIMEOUT_MS);
    const escaped = request.clone();
    escaped.url = 'http://127.0.0.1:8545';
    await assert.rejects(() => request.preflightFunc(escaped), /Only fixed private/);
  }
  assert.deepEqual(await requireFreshQbftQuorum(provider), {responsive_validators: 4, common_block: 32});
  assert.equal(await provider.getCode('0x'+'11'.repeat(20)), '0x6000');
}));

test('quorum reads continue after validator 1 stops', async () => network(async provider => {
  await requireFreshQbftQuorum(provider);
  assert.equal(await provider.getCode('0x'+'11'.repeat(20)), '0x6000');
  states[0].down = true;
  assert.equal((await requireFreshQbftQuorum(provider)).responsive_validators, 3);
  assert.equal(await provider.getCode('0x'+'22'.repeat(20)), '0x6000');
}));

test('preflight denies two lost validators before any transaction submission', async () => network(async provider => {
  states[0].down = states[1].down = true;
  await assert.rejects(() => requireFreshQbftQuorum(provider), /Fewer than three fresh/);
  assert.equal(seen.filter(request => request.method === 'eth_sendRawTransaction').length, 0);
}));

test('responding wrong-chain validator rejects signing preflight', async () => network(async provider => {
  states[1].chain = '0x1';
  await assert.rejects(() => requireFreshQbftQuorum(provider), /not research chain 31337/);
}));

test('stale and future-dated agreeing heads cannot authorize signing', async () => network(async provider => {
  for (const age of [-30, 30]) {
    states.forEach(state => {state.age = age;});
    await assert.rejects(() => requireFreshQbftQuorum(provider), /Fewer than three fresh/);
  }
}));

test('two-versus-two common block disagreement denies signing', async () => network(async provider => {
  states[2].hash = states[3].hash = 'bb';
  await assert.rejects(() => requireFreshQbftQuorum(provider), /disagree on a fresh common block/);
}));

test('two-versus-two differing registry code cannot satisfy ethers read quorum', async () => network(async provider => {
  states[2].code = states[3].code = '0x6001';
  await assert.rejects(() => provider.getCode('0x'+'11'.repeat(20)), /quorum not met/);
}));

test('QBFT block agreement tolerates different commit seals while preserving returned raw header', async () => network(async provider => {
  for (const [index, state] of states.entries()) {
    state.seal = ['11', '22', '33', '44'][index];
    state.size = `0x${(256+index).toString(16)}`;
  }
  const confirmed = await provider.getBlock('latest');
  assert.equal(confirmed.hash, '0x'+'aa'.repeat(32));
  assert.ok(states.some(state => block(state).extraData === confirmed.extraData));
}));

test('QBFT block normalization still rejects disagreement in other header fields', async () => network(async provider => {
  states[2].miner = states[3].miner = '0x'+'22'.repeat(20);
  await assert.rejects(() => provider.getBlock('latest'), /disagree on QBFT block data/);
}));

test('one hung validator times out while three fresh peers remain usable', async () => network(async provider => {
  states[0].hang = true;
  const started = performance.now();
  assert.equal((await requireFreshQbftQuorum(provider)).responsive_validators, 3);
  assert.ok(performance.now() - started < 6000, 'Hung peer must not use the ethers five-minute default timeout');
}));

test('same signed research transaction broadcasts through remaining peers after validator 1 outage', async () => network(async provider => {
  // Random, unfunded test key; only loopback fixtures receive its signed bytes.
  const signed = await Wallet.createRandom().signTransaction({chainId: 31337, nonce: 0, to: '0x'+'11'.repeat(20), value: 0, gasLimit: 21000, gasPrice: 0, type: 0});
  await requireFreshQbftQuorum(provider);
  assert.ok(await provider.getBlockNumber() >= 32); // ethers tolerates one-block drift.
  states[0].down = true;
  await requireFreshQbftQuorum(provider);
  const submitted = await provider.broadcastTransaction(signed);
  assert.equal(submitted.hash, keccak256(signed));
  assert.ok(seen.some(request => request.index !== 0 && request.method === 'eth_sendRawTransaction'));
  const transmissions = seen.filter(request => request.method === 'eth_sendRawTransaction');
  assert.ok(transmissions.every(request => request.params[0] === signed), 'Failover repeats the same signed bytes rather than authorizing a new transaction');
}));
