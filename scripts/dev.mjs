import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const python = path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
const vite = path.join(root, 'frontend/node_modules/vite/bin/vite.js')
if (!existsSync(python) || !existsSync(vite)) {
  console.error('Run npm run setup first to install the project dependencies.')
  process.exit(1)
}
console.log('Aegis: http://127.0.0.1:5173 | API: http://127.0.0.1:8000/docs | Ctrl+C stops both servers.')
const children = [
  spawn(python, ['-m', 'uvicorn', 'backend.app.main:app', '--host', '127.0.0.1', '--port', '8000'], { cwd: root, stdio: 'inherit' }),
  spawn(process.execPath, [vite, '--host', '127.0.0.1', '--port', '5173', '--strictPort'], { cwd: path.join(root, 'frontend'), stdio: 'inherit' }),
]
let stopping = false
function stop(code = 0) {
  if (stopping) return
  stopping = true
  process.exitCode = code
  for (const child of children) if (child.exitCode === null) child.kill('SIGTERM')
}
for (const child of children) {
  child.on('error', error => { console.error(error.message); stop(1) })
  child.on('exit', code => { if (!stopping) stop(code || 0) })
}
process.on('SIGINT', () => stop())
process.on('SIGTERM', () => stop())
