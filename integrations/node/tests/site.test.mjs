import assert from 'node:assert/strict'
import { once } from 'node:events'
import { test } from 'node:test'
import { createSiteServer } from '../../examples/node-site.mjs'
import { IamError } from '../adaptive-iam.mjs'
import { MemorySessionStore } from '../session-store.mjs'

const ISSUER = 'http://127.0.0.1:8000'
const ORIGIN = 'http://127.0.0.1:3001'
const cookieFrom = (response, name) => response.headers.getSetCookie().find(value => value.startsWith(name + '='))?.split(';')[0]

async function fixture(t) {
  const state = { time: Date.now(), grant: false, outage: false, revoked: false, mismatch: false, exchanges: 0, permissionCalls: 0, invalidExpiry: false, grantLifetime: 120_000, sessionReads: 0, sessionReadDelay: 0 }
  const identity = { sub: 'aisha', name: 'Aisha <script>alert(1)</script>' }
  const provider = {
    issuer: ISSUER,
    async authorizationUrl(flow) { state.flow = flow; return ISSUER + '/oauth/authorize?state=' + flow.state },
    async exchangeCode({ verifier, nonce }) {
      assert.equal(verifier, state.flow.verifier); assert.equal(nonce, state.flow.nonce)
      state.exchanges++
      return { identity, accessToken: 'fixture-server-token', expiresAt: state.invalidExpiry ? NaN : state.time + 600_000 }
    },
    async discover() { return { userinfo_endpoint: ISSUER + '/oauth/userinfo' } },
    async request() {
      if (state.revoked) throw new IamError('revoked', 401)
      if (state.outage) throw new IamError('unavailable', 503)
      return state.mismatch ? { sub: 'another-user' } : identity
    },
    async permission() {
      state.permissionCalls++
      if (state.revoked) throw new IamError('revoked', 401)
      if (state.outage) throw new IamError('unavailable', 503)
      if (!state.grant) throw new IamError('access_denied', 403)
      return { identity, resourceId: 'research-vault', scope: 'read', expiresAt: Object.hasOwn(state, 'grantExpiry') ? state.grantExpiry : new Date(state.time + state.grantLifetime).toISOString() }
    },
    async revoke() { state.revoked = true },
  }
  const sessionStore = new MemorySessionStore({ clock: () => state.time })
  const getSession = sessionStore.getSession.bind(sessionStore)
  sessionStore.getSession = id => {
    const session = getSession(id)
    if (++state.sessionReads === 2) state.time += state.sessionReadDelay
    return session
  }
  const server = createSiteServer({ siteOrigin: ORIGIN, client: provider, consoleOrigin: 'http://127.0.0.1:5173', clock: () => state.time, sessionStore })
  server.listen(0, '127.0.0.1'); await once(server, 'listening')
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections() }))
  const base = 'http://127.0.0.1:' + server.address().port
  const request = (path, cookie, options = {}) => fetch(base + path, { redirect: 'manual', ...options, headers: { ...(cookie ? { Cookie: cookie } : {}), ...options.headers } })
  async function begin() { const response = await request('/login'); assert.equal(response.status, 303); return cookieFrom(response, 'iam_login') }
  const callback = (changes = {}) => '/callback?' + new URLSearchParams({ state: state.flow.state, iss: ISSUER, code: 'fixture-code', ...changes })
  async function login() {
    const cookie = await begin()
    const response = await request(callback(), cookie)
    assert.equal(response.status, 303)
    assert.equal(response.headers.get('location'), '/dashboard')
    return cookieFrom(response, 'iam_site_session')
  }
  return { state, request, begin, callback, login }
}

test('public product/plans/assets work; private pages require authentication', async t => {
  const f = await fixture(t)
  for (const path of ['/', '/pricing', '/assets/orbit.css', '/assets/orbit.js']) assert.equal((await f.request(path)).status, 200)
  for (const path of ['/dashboard', '/projects', '/reports', '/settings', '/api/session', '/protected']) assert.equal((await f.request(path)).status, 401)
})

test('callback verifies cookie state, issuer and single use before creating a session', async t => {
  const f = await fixture(t)
  let cookie = await f.begin()
  assert.equal((await f.request(f.callback({ state: 'wrong-state' }), cookie)).status, 401)
  assert.equal(f.state.exchanges, 0)
  assert.equal((await f.request(f.callback(), cookie)).status, 401)
  cookie = await f.begin()
  assert.equal((await f.request(f.callback({ iss: 'https://other.example' }), cookie)).status, 401)
  assert.equal(f.state.exchanges, 0)
  cookie = await f.begin()
  assert.equal((await f.request(f.callback(), cookie)).status, 303)
  assert.equal((await f.request(f.callback(), cookie)).status, 401)
  assert.equal(f.state.exchanges, 1)
})

test('duplicate OAuth callback fields and denied consent fail before exchange', async t => {
  const f = await fixture(t)
  for (const key of ['state', 'iss', 'code', 'error']) {
    const cookie = await f.begin()
    const path = f.callback(key === 'error' ? { error: 'access_denied' } : {}) + '&' + key + '=second'
    assert.equal((await f.request(path, cookie)).status, 401)
  }
  const cookie = await f.begin()
  assert.equal((await f.request(f.callback({ error: 'access_denied' }), cookie)).status, 401)
  assert.equal(f.state.exchanges, 0)
})

test('expired login flow and invalid exchanged expiry cannot create website authority', async t => {
  const f = await fixture(t)
  let cookie = await f.begin()
  f.state.time += 300_001
  assert.equal((await f.request(f.callback(), cookie)).status, 401)
  f.state.invalidExpiry = true
  cookie = await f.begin()
  const result = await f.request(f.callback(), cookie)
  assert.equal(result.status, 401)
  assert.equal(cookieFrom(result, 'iam_site_session'), undefined)
})

test('dashboard identity is separate from a report grant; every report visit is checked', async t => {
  const f = await fixture(t); const cookie = await f.login()
  const dashboard = await f.request('/dashboard', cookie)
  assert.equal(dashboard.status, 200)
  assert.match(await dashboard.text(), /Sample workspace/)
  assert.equal((await f.request('/reports', cookie)).status, 403)
  assert.equal((await f.request('/protected', cookie)).status, 403)
  f.state.grant = true
  const html = await f.request('/reports', cookie)
  assert.equal(html.status, 200); assert.match(await html.text(), /protected-report/)
  const json = await f.request('/protected', cookie)
  assert.equal(json.status, 200); assert.equal((await json.json()).resource, 'research-vault')
  const observed = f.state.permissionCalls
  f.state.grant = false
  assert.equal((await f.request('/reports', cookie)).status, 403)
  assert.equal((await f.request('/protected', cookie)).status, 403)
  assert.equal(f.state.permissionCalls, observed + 2)
})

test('protected HTML/JSON and reports deny grants expiring during the final session read', async t => {
  const f = await fixture(t); const cookie = await f.login()
  f.state.grant = true; f.state.grantLifetime = 1000
  for (const delay of [1000, 3000]) {
    f.state.sessionReadDelay = delay
    for (const [path, headers] of [['/protected', {}], ['/protected', { Accept: 'text/html' }], ['/reports', {}]]) {
      f.state.sessionReads = 0
      const started = f.state.time; const calls = f.state.permissionCalls
      const response = await f.request(path, cookie, { headers })
      assert.equal(response.status, 403, `${path}, final read delay ${delay}`)
      assert.equal(f.state.permissionCalls, calls + 1)
      assert.equal(f.state.sessionReads, 2)
      assert.equal(f.state.time, started + delay)
      assert.doesNotMatch(await response.text(), /class="protected-report"|Your site returned this protected record/)
    }
  }
})

test('private workspace and session API remove allowed report state after the final session read', async t => {
  const f = await fixture(t); const cookie = await f.login()
  f.state.grant = true; f.state.grantLifetime = 1000
  for (const delay of [1000, 3000]) {
    f.state.sessionReadDelay = delay
    for (const path of ['/dashboard', '/projects', '/settings', '/api/session']) {
      f.state.sessionReads = 0
      const started = f.state.time; const calls = f.state.permissionCalls
      const response = await f.request(path, cookie)
      assert.equal(response.status, 200, `${path}, final read delay ${delay}`)
      assert.equal(f.state.permissionCalls, calls + 1)
      assert.equal(f.state.sessionReads, 2)
      assert.equal(f.state.time, started + delay)
      if (path === '/api/session') assert.deepEqual((await response.json()).reports, { state: 'locked' })
      else assert.doesNotMatch(await response.text(), /Report access is active|class="protected-report"/)
    }
  }
})

test('missing, non-string and invalid grant expiry cannot return protected content or allowed status', async t => {
  const f = await fixture(t); const cookie = await f.login()
  f.state.grant = true
  for (const expiry of [undefined, null, f.state.time + 60_000, '', 'not-a-date', new Date(f.state.time).toISOString()]) {
    f.state.grantExpiry = expiry
    for (const path of ['/protected', '/reports', '/api/session', '/dashboard']) {
      const response = await f.request(path, cookie)
      assert.equal(response.status, ['/protected', '/reports'].includes(path) ? 403 : 200)
      if (path === '/api/session') assert.deepEqual((await response.json()).reports, { state: 'locked' })
      else assert.doesNotMatch(await response.text(), /Report access is active|class="protected-report"|Your site returned this protected record/)
    }
  }
})

test('provider revocation and identity mismatch remove private dashboard access', async t => {
  const f = await fixture(t); const cookie = await f.login()
  assert.equal((await f.request('/dashboard', cookie)).status, 200)
  f.state.mismatch = true
  assert.equal((await f.request('/dashboard', cookie)).status, 401)
  f.state.mismatch = false; f.state.revoked = true
  for (const path of ['/dashboard', '/api/session', '/protected']) assert.equal((await f.request(path, cookie)).status, 401)
})

test('website session expiry is enforced before provider requests', async t => {
  const f = await fixture(t); const cookie = await f.login()
  f.state.time += 600_001
  assert.equal((await f.request('/dashboard', cookie)).status, 401)
  assert.equal((await f.request('/protected', cookie)).status, 401)
  assert.equal(f.state.permissionCalls, 0)
})

test('provider outage never returns protected content', async t => {
  const f = await fixture(t); const cookie = await f.login()
  f.state.grant = true; f.state.outage = true
  for (const path of ['/dashboard', '/reports', '/protected']) {
    const response = await f.request(path, cookie)
    assert.equal(response.status, 503)
    assert.doesNotMatch(await response.text(), /class="protected-report"/)
  }
})

test('cookies/CSP and HTML/API keep tokens server-side and escape identity text', async t => {
  const f = await fixture(t)
  const loginCookie = await f.begin(); const response = await f.request(f.callback(), loginCookie)
  const setCookie = response.headers.getSetCookie().find(value => value.startsWith('iam_site_session='))
  assert.match(setCookie, /HttpOnly/); assert.match(setCookie, /SameSite=Lax/)
  assert.doesNotMatch(setCookie, /fixture-server-token/)
  const cookie = cookieFrom(response, 'iam_site_session')
  const dashboard = await f.request('/dashboard', cookie)
  assert.equal(dashboard.headers.get('cache-control'), 'no-store')
  assert.match(dashboard.headers.get('content-security-policy'), /frame-ancestors 'none'/)
  const html = await dashboard.text()
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>|fixture-server-token/)
  assert.match(html, /&lt;script&gt;/)
  assert.doesNotMatch(await (await f.request('/api/session', cookie)).text(), /fixture-server-token/)
})

test('logout rejects cross-origin requests and clears local and provider authority', async t => {
  const f = await fixture(t); const cookie = await f.login()
  assert.equal((await f.request('/logout', cookie, { method: 'POST', headers: { Origin: 'https://attacker.example' } })).status, 403)
  assert.equal((await f.request('/dashboard', cookie)).status, 200)
  const response = await f.request('/logout', cookie, { method: 'POST', headers: { Origin: ORIGIN } })
  assert.equal(response.status, 303); assert.equal(f.state.revoked, true)
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/)
  assert.equal((await f.request('/dashboard', cookie)).status, 401)
})
