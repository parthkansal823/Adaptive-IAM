import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const localPython = path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const python = existsSync(localPython) ? localPython : process.platform === 'win32' ? 'python' : 'python3'
const args = process.argv.slice(2)
const tasks = { '--doctor': 'scripts/doctor.py', '--uncertainty': 'experiments/uncertainty_study.py' }
const selected = tasks[args[0]]
const child = spawn(python, [selected || 'scripts/verify.py', ...(selected ? args.slice(1) : args)], { cwd: root, stdio: 'inherit' })
child.on('error', () => {
  console.error('Could not start Python. Install Python 3.13 and create .venv as described in README.md.')
  process.exitCode = 1
})
child.on('exit', (code, signal) => { process.exitCode = signal ? 1 : code ?? 1 })
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal))
