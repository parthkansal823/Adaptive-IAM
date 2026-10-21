import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { provisionDemoSite } from '../../../deployment/configure-site.mjs'

const credentials = { client_id: 'app_' + 'c'.repeat(24), client_secret: 's'.repeat(43) }
const response = (value = {}, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })

function fixture(t, stored) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'iam-provisioning-'))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const target = path.join(directory, 'client.json')
  if (stored !== undefined) fs.writeFileSync(target, typeof stored === 'string' ? stored : JSON.stringify(stored))
  const messages = []
  return { target, directory, messages, options: { target, log: value => messages.push(value) } }
}

test('existing credentials authenticate without demo password login or changing configuration', async t => {
  const f = fixture(t, credentials); const before = fs.readFileSync(f.target)
  let calls = 0
  const result = await provisionDemoSite({ ...f.options, fetchImpl: async (url, options) => {
    calls++
    assert.equal(url, 'http://api:8000/oauth/revoke')
    assert.equal(options.method, 'POST'); assert.equal(options.redirect, 'error')
    assert.equal(options.headers['Content-Type'], 'application/x-www-form-urlencoded')
    assert.ok(options.signal instanceof AbortSignal)
    const form = new URLSearchParams(options.body)
    assert.equal(form.get('client_id'), credentials.client_id)
    assert.equal(form.get('client_secret'), credentials.client_secret)
    assert.equal(form.get('token'), 'demo-configuration-check')
    assert.notEqual(form.get('token').length, 43)
    return response()
  } })
  assert.deepEqual(result, { reused: true }); assert.equal(calls, 1)
  assert.deepEqual(fs.readFileSync(f.target), before)
  assert.doesNotMatch(f.messages.join('\n'), new RegExp(credentials.client_secret))
})

test('rotated secrets and disabled clients fail with recovery guidance and preserve the file', async t => {
  const f = fixture(t, credentials); let calls = 0
  await assert.rejects(provisionDemoSite({ ...f.options, fetchImpl: async () => { calls++; return response({ error: 'invalid_client' }, 401) } }), /rejected.*deployment\/README\.md.*preserved/)
  assert.equal(calls, 1); assert.deepEqual(JSON.parse(fs.readFileSync(f.target, 'utf8')), credentials)
  assert.deepEqual(fs.readdirSync(f.directory), ['client.json'])
})

test('provider outages never replace configuration or fall back to demo registration', async t => {
  for (const fetchImpl of [async () => response({}, 503), async () => { throw new Error('transport secret detail') }]) {
    const f = fixture(t, credentials)
    await assert.rejects(provisionDemoSite({ ...f.options, fetchImpl }), error => /preserved/.test(error.message) && !error.message.includes('transport secret detail'))
    assert.deepEqual(JSON.parse(fs.readFileSync(f.target, 'utf8')), credentials)
    assert.equal(f.messages.length, 0)
  }
})

test('malformed, oversized and incomplete stored configurations fail before network access', async t => {
  for (const stored of ['{', '[]', 'x'.repeat(4097), {}, { ...credentials, client_secret: '' }, { ...credentials, extra: true }, { ...credentials, client_id: ' app_wrong' }]) {
    const f = fixture(t, stored); const before = fs.readFileSync(f.target)
    await assert.rejects(provisionDemoSite({ ...f.options, fetchImpl: async () => assert.fail('No network call expected') }), /Cannot safely read/)
    assert.deepEqual(fs.readFileSync(f.target), before)
  }
})

test('an unreadable configuration target is preserved without network access', async t => {
  const f = fixture(t); fs.mkdirSync(f.target)
  await assert.rejects(provisionDemoSite({ ...f.options, fetchImpl: async () => assert.fail('No network call expected') }), /Cannot safely read/)
  assert.ok(fs.statSync(f.target).isDirectory())
})

test('first-run registration saves complete private credentials and logs out its setup session', async t => {
  const f = fixture(t); const paths = []
  const result = await provisionDemoSite({ ...f.options, fetchImpl: async (url, options) => {
    paths.push(new URL(url).pathname)
    if (url.endsWith('/api/auth/login')) return response({ token: 'fixture-setup-token' })
    if (url.endsWith('/api/apps')) {
      assert.equal(options.headers.Authorization, 'Bearer fixture-setup-token')
      const body = JSON.parse(options.body)
      assert.equal(body.client_type, 'confidential')
      assert.deepEqual(body.redirect_uris, ['http://127.0.0.1:3001/callback'])
      return response(credentials, 201)
    }
    assert.ok(url.endsWith('/api/auth/logout')); return response()
  } })
  assert.deepEqual(result, { reused: false })
  assert.deepEqual(paths, ['/api/auth/login', '/api/apps', '/api/auth/logout'])
  assert.deepEqual(JSON.parse(fs.readFileSync(f.target, 'utf8')), credentials)
  assert.deepEqual(fs.readdirSync(f.directory), ['client.json'])
  if (process.platform !== 'win32') assert.equal(fs.statSync(f.target).mode & 0o777, 0o600)
  assert.doesNotMatch(f.messages.join('\n'), /fixture-setup-token|s{43}/)
})

test('public demo challenge is supported but an enrolled factor is never bypassed', async t => {
  const f = fixture(t); const calls = []
  await provisionDemoSite({ ...f.options, fetchImpl: async (url, options) => {
    calls.push(new URL(url).pathname)
    if (url.endsWith('/api/auth/login')) return response({ status: 'mfa_required', challenge_id: 'fixture-challenge', demo_code: '123456' })
    if (url.endsWith('/api/auth/verify')) {
      assert.deepEqual(JSON.parse(options.body), { challenge_id: 'fixture-challenge', code: '123456' })
      return response({ token: 'fixture-setup-token' })
    }
    return url.endsWith('/api/apps') ? response(credentials, 201) : response()
  } })
  assert.deepEqual(calls, ['/api/auth/login', '/api/auth/verify', '/api/apps', '/api/auth/logout'])
  const enrolled = fixture(t); let count = 0
  await assert.rejects(provisionDemoSite({ ...enrolled.options, fetchImpl: async () => { count++; return response({ status: 'mfa_required', methods: ['totp'] }) } }), /enrolled factor/)
  assert.equal(count, 1); assert.equal(fs.existsSync(enrolled.target), false)
})

test('invalid returned credentials are never saved and setup authority is logged out', async t => {
  const f = fixture(t); let loggedOut = false; let disabled = false
  await assert.rejects(provisionDemoSite({ ...f.options, fetchImpl: async (url, options) => {
    if (url.endsWith('/api/auth/login')) return response({ token: 'fixture-setup-token' })
    if (url.endsWith('/api/apps')) return response({ ...credentials, client_secret: 'invalid' }, 201)
    if (url.endsWith('/api/apps/' + credentials.client_id)) {
      assert.equal(options.method, 'DELETE'); disabled = true; return response()
    }
    assert.ok(url.endsWith('/api/auth/logout'))
    loggedOut = true; return response()
  } }), /invalid demo website credentials/)
  assert.equal(disabled, true); assert.equal(loggedOut, true); assert.equal(fs.existsSync(f.target), false)
})

test('a concurrently created configuration is never overwritten', async t => {
  const f = fixture(t); const cleanup = []
  await assert.rejects(provisionDemoSite({ ...f.options, fetchImpl: async (url, options) => {
    if (url.endsWith('/api/auth/login')) return response({ token: 'fixture-setup-token' })
    if (url.endsWith('/api/apps')) {
      fs.writeFileSync(f.target, 'existing private configuration')
      return response(credentials, 201)
    }
    cleanup.push([new URL(url).pathname, options.method])
    return response()
  } }), /Existing configuration was preserved/)
  assert.equal(fs.readFileSync(f.target, 'utf8'), 'existing private configuration')
  assert.deepEqual(fs.readdirSync(f.directory), ['client.json'])
  assert.deepEqual(cleanup, [['/api/apps/' + credentials.client_id, 'DELETE'], ['/api/auth/logout', 'POST']])
})

test('failed remote cleanup preserves the publication error and still logs out', async t => {
  const f = fixture(t); let loggedOut = false
  await assert.rejects(provisionDemoSite({ ...f.options, fetchImpl: async (url, options) => {
    if (url.endsWith('/api/auth/login')) return response({ token: 'fixture-setup-token' })
    if (url.endsWith('/api/apps')) {
      fs.mkdirSync(f.target)
      return response(credentials, 201)
    }
    if (options.method === 'DELETE') return response({}, 503)
    assert.ok(url.endsWith('/api/auth/logout')); loggedOut = true; return response()
  } }), /Cannot safely save/)
  assert.equal(loggedOut, true); assert.ok(fs.statSync(f.target).isDirectory())
  assert.equal(f.messages.length, 1)
  assert.match(f.messages[0], /could not be disabled/)
  assert.doesNotMatch(f.messages[0], /fixture-setup-token|s{43}/)
})
