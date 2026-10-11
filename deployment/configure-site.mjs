import fs from 'node:fs'

if (process.env.IAM_DOCKER_SITE !== '1') throw new Error('This provisioner is only for the isolated public demo')
const target = '/var/lib/site/client.json'
const request = async (path, token, body, method = body ? 'POST' : 'GET') => {
  const response = await fetch(`http://api:8000${path}`, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined, redirect: 'error', signal: AbortSignal.timeout(10000) })
  if (!response.ok) throw new Error('Demo website provisioning failed')
  return response.json()
}
let login = await request('/api/auth/login', null, { user_id: 'kavya', password: 'Demo@123!', context: {} })
if (login.status === 'mfa_required') login = await request('/api/auth/verify', null, { challenge_id: login.challenge_id, code: login.demo_code })
if (!login.token) throw new Error('Synthetic reviewer could not authenticate')
try {
  const apps = await request('/api/apps', login.token)
  if (fs.existsSync(target)) {
    const current = JSON.parse(fs.readFileSync(target, 'utf8'))
    if (apps.items.some(app => app.client_id === current.client_id && app.active !== false && app.disabled_at == null)) {
      console.log('Existing private demo website registration reused.')
      process.exitCode = 0
    } else fs.renameSync(target, `${target}.previous`)
  }
  if (!fs.existsSync(target)) {
    const app = await request('/api/apps', login.token, { name: 'Orbit Workspace', client_type: 'confidential', redirect_uris: ['http://127.0.0.1:3001/callback'], scopes: ['openid', 'profile', 'iam:permissions'], resource_ids: ['research-vault'] })
    fs.writeFileSync(`${target}.tmp`, JSON.stringify({ client_id: app.client_id, client_secret: app.client_secret }), { mode: 0o600 })
    fs.renameSync(`${target}.tmp`, target)
    console.log('Private demo website registered. Credentials remain in its dedicated volume.')
  }
} finally {
  await request('/api/auth/logout', login.token, {}).catch(() => {})
}
