const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), 2000);
try {
  const response = await fetch('http://127.0.0.1:8545', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: []}), signal: controller.signal});
  const payload = await response.json();
  if (!response.ok || payload.result !== '0x7a69') throw new Error('Local chain is not ready');
} catch {
  process.exitCode = 1;
} finally {
  clearTimeout(timer);
}
