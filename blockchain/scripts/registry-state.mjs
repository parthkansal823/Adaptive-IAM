import fs from 'node:fs/promises';

const address = value => typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value);

/** Missing metadata after a confirmed/pending deployment is a recovery failure. */
export async function requireUnusedRegistryWriter(provider, writerAddress) {
  const counts = await Promise.all(['latest', 'pending'].map(tag => provider.getTransactionCount(writerAddress, tag)));
  if (!counts.every(count => count === 0)) throw new Error('Registry metadata is missing for a previously used writer; refuse redeployment. Restore matching retained metadata.');
}

/** A broken retained identity is never permission to deploy another registry. */
export async function readRetainedDeployment(filename) {
  let handle;
  let inspected = false;
  try {
    const stat = await fs.lstat(filename);
    inspected = true;
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0 || stat.size > 65536) throw new Error('Invalid metadata file');
    handle = await fs.open(filename, 'r');
    const metadata = JSON.parse(await handle.readFile('utf8'));
    if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata) || metadata.chain_id !== 31337 || !address(metadata.contract_address) || !address(metadata.writer_address)) throw new Error('Invalid registry identity');
    return metadata;
  } catch (error) {
    if (error.code === 'ENOENT' && !inspected) return null;
    throw new Error('Cannot validate retained registry metadata; existing state preserved. Restore matching metadata before retrying.');
  } finally {
    await handle?.close();
  }
}
