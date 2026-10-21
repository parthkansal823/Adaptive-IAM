import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ganache from 'ganache'
import { ContractFactory, JsonRpcProvider } from 'ethers'
import { compile } from './compile.mjs'

// Always create an ephemeral loopback chain; never connect to configured RPC or
// reuse the application's database, wallet, contract, or deployment metadata.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const pythonPath = path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const python = existsSync(pythonPath) ? pythonPath : process.platform === 'win32' ? 'python' : 'python3'
const chain = ganache.server({ chain: { chainId: 31337, hardfork: 'shanghai' }, wallet: { deterministic: true, totalAccounts: 2 }, logging: { quiet: true } })
let directory, provider, child, listening = false
let interrupted = false
const stop = () => { interrupted = true; if (child?.exitCode === null) child.kill('SIGTERM') }
process.on('SIGINT', stop)
process.on('SIGTERM', stop)
try {
  directory = await mkdtemp(path.join(tmpdir(), 'adaptive-iam-web3-'))
  await chain.listen(0, '127.0.0.1')
  listening = true
  const rpc = `http://127.0.0.1:${chain.address().port}`
  provider = new JsonRpcProvider(rpc, 31337, { staticNetwork: true })
  const artifact = compile()
  const writer = await provider.getSigner(0)
  const contract = await new ContractFactory(artifact.abi, artifact.bytecode, writer).deploy()
  await contract.waitForDeployment()
  const metadataPath = path.join(directory, 'deployment.json')
  await writeFile(metadataPath, JSON.stringify({ chain_id: 31337, contract_address: await contract.getAddress(), writer_address: await writer.getAddress() }), { mode: 0o600 })
  if (interrupted) throw new Error('Verification interrupted before tests started.')
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('IAM_')))
  env.IAM_TEST_WEB3_RPC_URL = rpc
  env.IAM_TEST_WEB3_DEPLOYMENT_FILE = metadataPath
  console.log('Running API security tests against a new isolated Ganache chain (no workspace state).')
  const result = await new Promise((resolve, reject) => {
    child = spawn(python, ['scripts/run_tests.py', '-s', 'backend/tests', '-p', 'test_blockchain.py'], { cwd: root, env, stdio: 'inherit', windowsHide: true })
    const timer = setTimeout(() => { child.kill('SIGTERM'); reject(new Error('Live API verification exceeded three minutes.')) }, 180_000)
    child.once('error', () => { clearTimeout(timer); reject(new Error('Could not start Python; install backend test dependencies and retry.')) })
    child.once('exit', (code, signal) => { clearTimeout(timer); resolve(signal ? 1 : code ?? 1) })
  })
  process.exitCode = result
  if (result === 0) console.log('Isolated live-chain API verification passed.')
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
} finally {
  process.removeListener('SIGINT', stop)
  process.removeListener('SIGTERM', stop)
  if (child?.exitCode === null) child.kill('SIGTERM')
  provider?.destroy()
  if (listening) await chain.close()
  if (directory) {
    const target = path.resolve(directory)
    if (!target.startsWith(path.resolve(tmpdir()) + path.sep) || !path.basename(target).startsWith('adaptive-iam-web3-')) throw new Error('Refusing cleanup outside verification temporary state.')
    await rm(target, { recursive: true, force: true, maxRetries: 4, retryDelay: 100 })
  }
}
