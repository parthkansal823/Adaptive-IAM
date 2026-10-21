import fs from 'node:fs'
import { randomBytes } from 'node:crypto'
import { pathToFileURL } from 'node:url'

const API = 'http://api:8000'
const TARGET = '/var/lib/site/client.json'
const RECOVERY = 'Restore the current confidential credentials in website_config/client.json, or follow the demo website recovery steps in deployment/README.md. The existing file was preserved.'

function validConfig(value) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === 2
    && typeof value.client_id === 'string' && /^app_[A-Za-z0-9_-]{24}$/.test(value.client_id)
    && typeof value.client_secret === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value.client_secret)
}

function readConfig(target) {
  let descriptor
  try {
    descriptor = fs.openSync(target, 'r')
    const stat = fs.fstatSync(descriptor)
    if (!stat.isFile() || stat.size > 4096) throw new Error('invalid configuration')
    const config = JSON.parse(fs.readFileSync(descriptor, 'utf8'))
    if (!validConfig(config)) throw new Error('invalid configuration')
    return config
  } catch (error) {
    if (descriptor === undefined && error.code === 'ENOENT') return null
    throw new Error(`Cannot safely read the stored demo website configuration. ${RECOVERY}`)
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}

function saveConfig(target, config) {
  const temporary = `${target}.${randomBytes(12).toString('hex')}.tmp`
  try {
    fs.writeFileSync(temporary, JSON.stringify(config), { mode: 0o600, flag: 'wx' })
    // Publish a complete file atomically, without replacing another provisioner's file.
    fs.linkSync(temporary, target)
  } catch {
    throw new Error('Cannot safely save demo website credentials. Existing configuration was preserved; inspect the dedicated website_config volume permissions.')
  } finally {
    try { fs.unlinkSync(temporary) } catch { /* Never remove the existing configuration. */ }
  }
}

/** Public loopback-demo provisioning only; injectable transport keeps tests isolated. */
export async function provisionDemoSite({ target = TARGET, fetchImpl = globalThis.fetch, log = console.log } = {}) {
  const current = readConfig(target)
  const fetchApi = async (path, options) => {
    try {
      return await fetchImpl(`${API}${path}`, { ...options, redirect: 'error', signal: AbortSignal.timeout(10000) })
    } catch {
      throw new Error('Demo website provisioning could not reach the provider. Stored configuration was preserved; check the API service and retry.')
    }
  }
  if (current) {
    const response = await fetchApi('/oauth/revoke', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      // Issued tokens are 43 URL-safe characters. This probe can never match one.
      body: new URLSearchParams({ ...current, token: 'demo-configuration-check', token_type_hint: 'access_token' }).toString(),
    })
    if (response.status === 401) throw new Error(`The provider rejected the stored demo website credentials. ${RECOVERY}`)
    if (response.status !== 200) throw new Error('The provider could not validate demo website credentials. Stored configuration was preserved; check the API service and retry.')
    log('Existing private demo website registration authenticated and reused.')
    return { reused: true }
  }

  const request = async (path, token, body, method = body ? 'POST' : 'GET') => {
    const response = await fetchApi(path, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined })
    if (!response.ok) throw new Error('Demo website provisioning failed. Automatic registration requires the public demo and an unenrolled demo setup identity; use the Developer portal for private accounts.')
    try {
      const value = await response.json()
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid response')
      return value
    }
    catch { throw new Error('Demo website provisioning received an invalid provider response.') }
  }
  let login = await request('/api/auth/login', null, { user_id: 'kavya', password: 'Demo@123!', context: {} })
  if (login.status === 'mfa_required' && typeof login.demo_code === 'string') login = await request('/api/auth/verify', null, { challenge_id: login.challenge_id, code: login.demo_code })
  if (typeof login.token !== 'string' || !login.token) throw new Error('The demo setup identity requires its enrolled factor. Register the website through the Developer portal; no configuration was written.')
  try {
    const app = await request('/api/apps', login.token, { name: 'Orbit Workspace', client_type: 'confidential', redirect_uris: ['http://127.0.0.1:3001/callback'], scopes: ['openid', 'profile', 'iam:permissions'], resource_ids: ['research-vault'] })
    const config = { client_id: app.client_id, client_secret: app.client_secret }
    try {
      if (!validConfig(config)) throw new Error('The provider returned invalid demo website credentials; no configuration was written.')
      saveConfig(target, config)
    } catch (error) {
      // Remove authority only from the app created by this attempt. A failed
      // publication must never disable a concurrently published registration.
      if (typeof app.client_id === 'string' && /^app_[A-Za-z0-9_-]{24}$/.test(app.client_id)) {
        await request(`/api/apps/${app.client_id}`, login.token, undefined, 'DELETE').catch(() => {
          log('The unsaved registration could not be disabled. Review the latest Orbit Workspace application in the Developer portal before retrying.')
        })
      }
      throw error
    }
    log('Private demo website registered. Credentials remain in its dedicated volume.')
    return { reused: false }
  } finally {
    await request('/api/auth/logout', login.token, {}).catch(() => {})
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.env.IAM_DOCKER_SITE !== '1') throw new Error('This provisioner is only for the isolated public demo')
  try { await provisionDemoSite() }
  catch (error) { console.error(error.message); process.exitCode = 1 }
}
