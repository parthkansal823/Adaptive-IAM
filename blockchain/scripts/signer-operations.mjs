// Fixed registry operations only; this module never opens a wallet or network.
const hash = value => typeof value === 'string' && /^0x[a-fA-F0-9]{64}$/.test(value) && value !== '0x' + '00'.repeat(32);
const optionalHash = value => typeof value === 'string' && /^0x[a-fA-F0-9]{64}$/.test(value);

export function validateOperation(packet, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!packet || typeof packet !== 'object' || Array.isArray(packet) || Object.keys(packet).sort().join(',') !== 'arguments,kind' || !Array.isArray(packet.arguments)) throw new Error('Unsupported operation');
  const args = packet.arguments;
  if (packet.kind === 'audit' && args.length === 2 && hash(args[0]) && optionalHash(args[1])) return 'anchorAudit';
  if (packet.kind === 'audit_batch' && args.length === 5 && Number.isSafeInteger(args[0]) && Number.isSafeInteger(args[1]) && args[0] >= 1 && args[1] >= args[0] && args[1] - args[0] < 256 && hash(args[2]) && hash(args[3]) && optionalHash(args[4])) return 'anchorAuditBatch';
  if (packet.kind === 'grant' && args.length === 4 && args.slice(0, 3).every(hash) && Number.isSafeInteger(args[3]) && args[3] > nowSeconds && args[3] <= nowSeconds + 72 * 3600) return 'recordGrant';
  if (packet.kind === 'revoke' && args.length === 1 && hash(args[0])) return 'revokeGrant';
  throw new Error('Invalid fixed registry operation');
}
