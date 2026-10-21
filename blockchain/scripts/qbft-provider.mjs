import {FallbackProvider, FetchRequest, JsonRpcProvider, decodeRlp, encodeRlp} from 'ethers';

export const QBFT_CHAIN_ID = 31337;
export const QBFT_RPC_URLS = Object.freeze([1, 2, 3, 4].map(index => `http://qbft${index}:8545`));
export const QBFT_REQUEST_TIMEOUT_MS = 1500;
const hashPattern = /^0x[0-9a-fA-F]{64}$/;
const quantityPattern = /^0x[0-9a-fA-F]+$/;

function privateEndpoint(url) {
  if (!QBFT_RPC_URLS.includes(url)) throw new Error('Only fixed private QBFT validator endpoints are allowed');
}

class QbftFallbackProvider extends FallbackProvider {
  async _perform(request) {
    // ethers 6.17's fuzzy block-number path attempts to parse transport errors
    // as numbers when a previously healthy peer disappears. Use our stricter
    // common finalized-height guard for this operation, retaining ethers'
    // three-response quorum for code, contract calls, nonces and receipts.
    if (request.method === 'getBlockNumber') return (await requireFreshQbftQuorum(this)).common_block;
    if (request.method === 'getBlock') return quorumBlock(this, request);
    return super._perform(request);
  }
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}

async function quorumBlock(provider, request) {
  const {common_block: height} = await requireFreshQbftQuorum(provider);
  const query = request.blockTag === 'latest' ? {...request, blockTag: `0x${height.toString(16)}`} : request;
  const responses = await Promise.allSettled(provider.providerConfigs.map(async ({provider: node}) => {
    const block = await node._perform(query);
    if (!block || !hashPattern.test(block.hash ?? '')) throw new Error('Missing QBFT block');
    const extra = decodeRlp(block.extraData);
    if (!Array.isArray(extra) || extra.length !== 5 || !Array.isArray(extra[4])) throw new Error('Unexpected QBFT header');
    // QBFT nodes can retain different valid commit-seal sets/order for the
    // same finalized hash. Compare all remaining RPC data and the extra-data
    // prefix, while returning an original block with its seals intact.
    const normalized = {...block, extraData: encodeRlp([...extra.slice(0, 4), []])};
    delete normalized.size; // Encoded size also varies with the commit seals.
    return {block, key: JSON.stringify(canonical(normalized))};
  }));
  const groups = new Map();
  for (const result of responses) {
    if (result.status !== 'fulfilled') continue;
    const group = groups.get(result.value.key) ?? [];
    group.push(result.value.block);
    groups.set(result.value.key, group);
  }
  const agreed = [...groups.values()].find(group => group.length >= 3);
  if (!agreed) throw new Error('Private validators disagree on QBFT block data');
  return agreed[0];
}

/** No environment override, arbitrary RPC, fallback public chain or unlocked account. */
export function createQbftProvider() {
  const children = QBFT_RPC_URLS.map(url => {
    const request = new FetchRequest(url);
    request.timeout = QBFT_REQUEST_TIMEOUT_MS;
    request.preflightFunc = async packet => {privateEndpoint(packet.url); return packet;};
    request.retryFunc = async () => false;
    request.setThrottleParams({maxAttempts: 1});
    const provider = new JsonRpcProvider(request, QBFT_CHAIN_ID, {
      staticNetwork: false, pollingInterval: 150, cacheTimeout: -1, batchMaxCount: 1,
    });
    // Auto-detection transport errors are handled by callers and the quorum guard.
    provider.on('error', () => {});
    return {provider, priority: 1, weight: 1, stallTimeout: 250};
  });
  return new QbftFallbackProvider(children, QBFT_CHAIN_ID, {quorum: 3, pollingInterval: 150, cacheTimeout: -1});
}

function freshBlock(block, at) {
  if (!block || !quantityPattern.test(block.number ?? '') || !quantityPattern.test(block.timestamp ?? '') || !hashPattern.test(block.hash ?? '')) return false;
  const age = at - Number(BigInt(block.timestamp));
  return Number.isSafeInteger(Number(BigInt(block.number))) && age >= -2 && age <= 8;
}

/**
 * Read three fresh, agreeing nodes before signing. FallbackProvider supplies
 * read/receipt agreement; this extra guard rejects stale but agreeing heads.
 * It supplements Besu consensus rather than verifying validator signatures.
 */
export async function requireFreshQbftQuorum(provider) {
  const checks = await Promise.allSettled(provider.providerConfigs.map(async ({provider: node}) => {
    const chain = await node.send('eth_chainId', []);
    if (chain !== '0x7a69') throw new Error('Foreign chain');
    const block = await node.send('eth_getBlockByNumber', ['latest', false]);
    if (!freshBlock(block, Date.now() / 1000)) return null;
    return {node, height: Number(BigInt(block.number))};
  }));
  // A responding, wrongly configured validator must never receive a signature.
  if (checks.some(result => result.status === 'rejected' && result.reason?.message === 'Foreign chain')) throw new Error('QBFT validator is not research chain 31337');
  const live = checks.flatMap(result => result.status === 'fulfilled' && result.value ? [result.value] : []);
  if (live.length < 3) throw new Error('Fewer than three fresh private validators');
  const height = Math.min(...live.map(node => node.height));
  const common = await Promise.allSettled(live.map(async ({node}) => {
    const block = await node.send('eth_getBlockByNumber', [`0x${height.toString(16)}`, false]);
    return freshBlock(block, Date.now() / 1000) && Number(BigInt(block.number)) === height ? block.hash.toLowerCase() : null;
  }));
  const hashes = common.flatMap(result => result.status === 'fulfilled' && result.value ? [result.value] : []);
  const agreement = hashes.reduce((counts, value) => counts.set(value, (counts.get(value) ?? 0) + 1), new Map());
  if (![...agreement.values()].some(count => count >= 3)) throw new Error('Private validators disagree on a fresh common block');
  return {responsive_validators: live.length, common_block: height};
}
