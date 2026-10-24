import fs from 'node:fs/promises';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {Wallet, SigningKey, encodeRlp} from 'ethers';

// A one-shot initializer owns separate volumes; validator services receive only
// their own key. Registry writer material is never mounted into IAM/API.
export async function initializeQbft({rootDirectory = '/', log = console.log} = {}) {
  const file = name => path.join(rootDirectory, name);
  const publicDir = file('network');
  const managed = ['network/genesis.json', 'network/static-nodes.json', 'network/permissions_config.toml', 'network/operators.json', 'validator1/key', 'validator2/key', 'validator3/key', 'validator4/key', 'signer/writer.json', 'signer/password', 'auth/token'];
  const present = await Promise.all(managed.map(async name => {
    try {
      const stat = await fs.lstat(file(name));
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0) throw new Error('Invalid retained QBFT state');
      return true;
    } catch (error) {
      if (error.code === 'ENOENT') return false;
      throw new Error('Cannot safely inspect retained QBFT state; existing identity preserved');
    }
  }));
  if (present.some(Boolean)) {
    if (!present.every(Boolean)) throw new Error('Incomplete QBFT state; refuse to replace existing identity');
    log('Existing private network identities preserved.');
    return;
  }
  const keys = Array.from({length: 4}, () => Wallet.createRandom());
  const writer = Wallet.createRandom();
  const password = randomBytes(32).toString('hex');
  const auth = randomBytes(32).toString('hex');
  const addresses = keys.map(key => key.address.toLowerCase()).sort();
  const extraData = encodeRlp(['0x' + '00'.repeat(32), addresses, [], '0x', []]);
  const genesis = {
    config: {chainId: 31337, homesteadBlock: 0, eip150Block: 0, eip155Block: 0, eip158Block: 0, byzantiumBlock: 0,
      constantinopleBlock: 0, petersburgBlock: 0, istanbulBlock: 0, berlinBlock: 0, londonBlock: 0,
      zeroBaseFee: true, qbft: {blockperiodseconds: 1, epochlength: 30000, requesttimeoutseconds: 4}},
    nonce: '0x0', timestamp: '0x0', extraData, gasLimit: '0x1c9c380', difficulty: '0x1',
    mixHash: '0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365',
    coinbase: '0x' + '00'.repeat(20), alloc: {[writer.address.toLowerCase().slice(2)]: {balance: '0x0'}}
  };
  const enodes = keys.map((key, i) => `enode://${SigningKey.computePublicKey(key.privateKey, false).slice(4)}@qbft${i + 1}:30303`);
  await fs.mkdir(publicDir, {recursive: true});
  for (let i = 0; i < keys.length; i++) {
    await fs.writeFile(file(`validator${i + 1}/key`), keys[i].privateKey.slice(2), {mode: 0o600, flag: 'wx'});
  }
  await fs.writeFile(file('signer/writer.json'), await writer.encrypt(password), {mode: 0o600, flag: 'wx'});
  await fs.writeFile(file('signer/password'), password, {mode: 0o600, flag: 'wx'});
  await fs.writeFile(file('auth/token'), auth, {mode: 0o600, flag: 'wx'});
  await fs.writeFile(`${publicDir}/static-nodes.json`, JSON.stringify(enodes), {mode: 0o644, flag: 'wx'});
  await fs.writeFile(`${publicDir}/permissions_config.toml`, `nodes-allowlist=[${enodes.map(value => JSON.stringify(value)).join(',')}]\n`, {mode: 0o644, flag: 'wx'});
  await fs.writeFile(`${publicDir}/operators.json`, JSON.stringify({chain_id: 31337, validators: keys.map((key, i) => ({alias: `qbft${i + 1}`, address: key.address, enode: enodes[i]})), writer_address: writer.address}, null, 2), {mode: 0o644, flag: 'wx'});
  // Write the identity-commit marker last. Never log key material or auth tokens.
  await fs.writeFile(`${publicDir}/genesis.json`, JSON.stringify(genesis, null, 2), {mode: 0o644, flag: 'wx'});
  log('Initialized four distinct validator identities and encrypted isolated writer.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await initializeQbft();
