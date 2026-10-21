import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { access, readFile, mkdtemp, rm } from 'node:fs/promises'
import { basename, dirname, join, extname, resolve, sep } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'

// Uses only Node APIs and the production bundle, with a separate local API fixture.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const candidates = process.env.IAM_TEST_BROWSER || process.env.CHROME_BIN
  ? [process.env.IAM_TEST_BROWSER || process.env.CHROME_BIN]
  : process.platform === 'win32'
    ? [join(process.env['ProgramFiles(x86)'] || 'C:/Program Files (x86)', 'Microsoft/Edge/Application/msedge.exe'), join(process.env.ProgramFiles || 'C:/Program Files', 'Google/Chrome/Application/chrome.exe')]
    : process.platform === 'darwin'
      ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge']
      : ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/opt/google/chrome/chrome']
let browser
for (const candidate of candidates) { try { await access(candidate); browser = candidate; break } catch { /* Try the next installed browser. */ } }
assert(browser, 'No Chromium browser found. Set IAM_TEST_BROWSER or CHROME_BIN to the full path of Chrome, Edge, or Chromium, then retry.')
await access(join(root, 'frontend/dist/index.html')).catch(() => { throw new Error('The production frontend bundle is missing. Run npm run build in frontend, then retry this check.') })
const risk = { score: .1, tier: 'low', action: 'allow', signals: [], components: {}, latency_ms: 1 }
const users = [{ id: 'a', name: 'Alice Fixture', role: 'security_reviewer', department: 'Research', password: 'fixture-password' }, { id: 'b', name: 'Bob Fixture', role: 'security_reviewer', department: 'Research', password: 'fixture-password' }]
const resources = [{ id: 'vault', name: 'Fixture vault', description: 'Synthetic browser fixture', sensitivity: 'restricted', owner_id: 'a', max_duration_hours: 4 }, { id: 'logs', name: 'Fixture logs', description: 'Synthetic browser fixture', sensitivity: 'internal', owner_id: 'a', max_duration_hours: 4 }]
const summary = { stats: { pending_requests: 0, active_grants: 0, audit_events: 0, review_queue: 0, authentication_events: 0 }, risk_distribution: { low: 0, medium: 0, high: 0 }, recent_events: [], recent_requests: [], model: { name: 'fixture', version: '1', synthetic: true }, capabilities: {} }
let accessRequests = [], accessGrants = []
let holdResource = false, resourceChecks = 0, inspectionLifetime = null
let uncertaintyFail = false, uncertaintyReads = 0
let lanlFail = false, lanlEligible = false, lanlReads = 0
const aggregate = mean => ({ mean, sample_std: 0, minimum: mean, maximum: mean })
const studyPolicy = (detection, friction, coverage) => ({ suspicious_detection_rate: aggregate(detection), legitimate_friction_rate: aggregate(friction), suspicious_direct_allow_rate: aggregate(1 - detection), ...(coverage === undefined ? {} : { coverage: aggregate(coverage), suspicious_coverage: aggregate(coverage - .05), both_labels_rate: aggregate(.2), mean_set_size: aggregate(1.2) }) })
const uncertaintyStudy = { schema_version: 'uncertainty-study-v1', synthetic: true, alpha: .1, seeds: [0, 1, 2, 3, 4], protocol: { source: 'Isolated synthetic browser fixture' }, limitations: ['Synthetic fixture values exercise the interface; they are not study measurements.'], summary: { iid: { baseline: studyPolicy(.12, .05), marginal_gate: studyPolicy(.9, .1, .91), class_conditional_gate: studyPolicy(.96, .2, .95), always_challenge: studyPolicy(1, 1) }, telemetry_masking: { baseline: studyPolicy(.04, .06), marginal_gate: studyPolicy(.6, .12, .74), class_conditional_gate: studyPolicy(.8, .25, .85), always_challenge: studyPolicy(1, 1) } } }
const lanlStudy = () => {
  const split = (first, last, exercise = 0) => ({ events: 100, unlabeled_events: 100 - exercise, matched_auth_rows: exercise, known_redteam_unique_tuples: exercise, first_second: first, last_second: last })
  const method = { threshold: { validation_alert_fraction: .05 }, test_alerts: 10, test_alert_fraction: .1, unlabeled_alerts: lanlEligible ? 8 : 10, alert_fraction_over_unlabeled: lanlEligible ? 8 / 96 : .1, known_redteam_alerted_auth_rows: lanlEligible ? 2 : 0, known_redteam_recalled_unique_tuples: lanlEligible ? 2 : 0, known_redteam_tuple_recall: lanlEligible ? .5 : null }
  return { schema_version: 'lanl-study-v1', evidence_type: 'real_enterprise_authentication_with_exercise_redteam', synthetic: false, source_real_enterprise: true, source: { kind: 'Isolated browser fixture; not downloaded evidence', bounded_auth_prefix: true, landing_page: 'https://csr.lanl.gov/data/cyber1/' }, scan: { source_rows: 500, selected_rows: 300, source_first_second: 1, source_last_second: 300 }, partitions: { warmup: split(1, 100), validation: split(101, 200), test: split(201, 300, lanlEligible ? 4 : 0) }, labels: { detection_metrics_eligible: lanlEligible, eligibility_reason: lanlEligible ? 'Four recorded exercise tuples in this interface fixture.' : 'No exercise tuples match this interface fixture.', unique_redteam_tuples_in_reference: 12 }, methods: { new_user_source: method, new_user_destination: method, edge_surprise: method }, limitations: ['Fixture values exercise the interface only; they are not LANL measurements.'] }
}
const fixtureRequest = (id, overrides = {}) => ({ id, requester_id: 'b', requester_name: users[1].name, resource_id: 'vault', resource_name: resources[0].name, justification: 'Review the synthetic fixture records for the research task.', duration_hours: 1, status: 'pending', created_at: '2026-01-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z', risk, nlp: { label: 'legitimate', confidence: .9, explanation: 'Synthetic fixture' }, reviewers: [{ id: 'a', name: users[0].name, weight: 1.5, is_owner: true }], votes: [], consensus: { approval_weight: 0, total_weight: 1.5, cast_weight: 0, quorum_required: 1, quorum_reached: false }, reviewer_selection: { reason: 'Fixture reviewer' }, can_vote: true, ...overrides })
const fixtureGrant = (id, overrides = {}) => ({ id, request_id: 'approved-fixture', user_id: 'a', user_name: users[0].name, resource_id: 'vault', resource_name: resources[0].name, scope: 'read', created_at: '2026-01-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z', status: 'active', can_revoke: true, ...overrides })
let held = null
let catalogFail = false
let catalogReads = 0
let callbackChecks = 0
let appRegistrations = 0
let loginCounter = 0
const send = (res, body, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)) }
const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url, 'http://localhost').pathname
    if (!path.startsWith('/api/')) {
      const asset = path.startsWith('/assets/') ? path : '/index.html'
      res.writeHead(200, { 'content-type': extname(asset) === '.js' ? 'application/javascript' : extname(asset) === '.css' ? 'text/css' : 'text/html' })
      res.end(await readFile(join(root, 'frontend/dist', asset)))
      return
    }
    const identity = users.find(user => req.headers.authorization?.includes(`token-${user.id}`)) || users[0]
    const session = { expires_at: '2099-01-01T00:00:00Z', step_up_required: false, enrollment_required: false }
    if (path === '/api/bootstrap') return send(res, { demo_mode: true, users, resources, risk_thresholds: { low: .3, high: .7 }, reviewer_weights: {}, capabilities: {} })
    if (path === '/api/evaluation') return send(res, { dataset: {}, baseline: {}, improved: {} })
    if (path === '/api/research/uncertainty') { uncertaintyReads++; return uncertaintyFail ? send(res, { detail: 'Fixture study unavailable' }, 503) : send(res, uncertaintyStudy) }
    if (path === '/api/research/lanl') { lanlReads++; return lanlFail ? send(res, { detail: 'Fixture real-data study unavailable' }, 503) : send(res, lanlStudy()) }
    if (path === '/api/auth/me') return send(res, { user: identity, risk, session })
    if (path === '/api/overview') return send(res, { ...summary, stats: { ...summary.stats, active_grants: accessGrants.filter(grant => grant.status === 'active').length, pending_requests: accessRequests.filter(request => request.status === 'pending').length, review_queue: accessRequests.filter(request => request.can_vote).length }, recent_requests: accessRequests.slice(0, 5) })
    if (path === '/api/requests') return send(res, { items: accessRequests })
    if (path === '/api/grants') return send(res, { items: accessGrants })
    if (['/api/audit', '/api/lab/runs'].includes(path)) return send(res, { items: [] })
    if (/^\/api\/resources\/[^/]+\/access$/.test(path)) {
      resourceChecks++
      if (holdResource) { held = { path, res }; return }
      const resource = resources.find(resource => path === `/api/resources/${resource.id}/access`)
      return send(res, { allowed: true, resource_id: resource.id, resource_name: resource.name, scope: 'read', expires_at: inspectionLifetime ? new Date(Date.now() + inspectionLifetime).toISOString() : '2099-01-01T00:00:00Z', reason: 'Server allowed this fixture check.', content: { title: resource.name, records: [`protected-${resource.id}-fixture`] } })
    }
    if (path === '/api/auth/login') {
      let body = ''; for await (const chunk of req) body += chunk
      const user = users.find(user => user.id === JSON.parse(body).user_id)
      return send(res, { status: 'authenticated', token: `token-${user.id}-${++loginCounter}`, user, risk })
    }
    if (path === '/api/auth/logout' || path === '/api/audit/verify' || path === '/api/auth/sessions/current/revoke') { held = { path, res }; return }
    if (path === '/api/auth/security') return send(res, { passkeys_available: false, totp_enabled: false, passkeys: [], recovery_codes_remaining: 0, fresh_verification: false, enrollment_ready: true, step_up_required: false, session, rp_id: 'localhost', origin, demo_mode: true })
    if (path === '/api/auth/sessions') return send(res, { items: [{ id: 'current', created_at: '2026-01-01T00:00:00Z', expires_at: session.expires_at, last_seen_at: '2026-01-01T00:00:00Z', verification_method: 'password', step_up_required: false, current: true }] })
    if (path === '/api/blockchain/status') return send(res, { enabled: false, ready: false, limitation: 'Fixture' })
    if (path === '/api/lab/catalog') {
      catalogReads++
      if (catalogFail) return send(res, { detail: 'Fixture catalog unavailable' }, 503)
      return send(res, { items: [{ id: 'fixture', name: 'Fixture scenario', description: 'Synthetic browser fixture', category: 'Research' }], notice: 'Fixture only' })
    }
    if (path === '/api/developer/workspace') return send(res, { organizations: [{ id: 'org', name: 'Fixture org', role: 'admin', can_manage: true, members: [], resource_ids: [] }], apps: [], available_users: [], capabilities: { can_create_organization: true, recent_verification_required: true } })
    if (path === '/api/apps' && req.method === 'GET') return send(res, { items: [], issuer: 'http://localhost', authorization_endpoint: 'http://localhost/authorize' })
    if (path === '/api/apps') { appRegistrations++; return send(res, { detail: 'Unexpected final registration' }, 400) }
    if (path === '/api/developer/callback-check') { callbackChecks++; return send(res, { valid: true, registered: null, origin: 'https://fixture.example', development_only: false, checks: [] }) }
    send(res, { detail: `Missing browser fixture: ${path}` }, 404)
  } catch (error) { console.error(error); send(res, { detail: 'Fixture error' }, 500) }
})
let origin, profile, browserProcess, browserClient
let cdpPort
const pages = []
const request = (url, options = {}) => fetch(url, { ...options, signal: AbortSignal.timeout(8_000) })
async function connect(url) {
  const socket = new WebSocket(url)
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { socket.close(); reject(new Error('The browser debugging connection timed out.')) }, 8_000)
    socket.addEventListener('open', () => { clearTimeout(timeout); resolve() }, { once: true })
    socket.addEventListener('error', () => { clearTimeout(timeout); reject(new Error('The browser debugging connection failed.')) }, { once: true })
  })
  const pending = new Map()
  let sequence = 0
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data)
    const promise = pending.get(message.id)
    if (!promise) return
    clearTimeout(promise.timeout); pending.delete(message.id)
    if (message.error) promise.reject(new Error(JSON.stringify(message.error))); else promise.resolve(message.result)
  })
  socket.addEventListener('close', () => { for (const promise of pending.values()) { clearTimeout(promise.timeout); promise.reject(new Error('The browser debugging connection closed.')) } pending.clear() })
  const command = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`Browser command timed out: ${method}`)) }, 8_000)
    pending.set(id, { resolve, reject, timeout }); socket.send(JSON.stringify({ id, method, params }))
  })
  return { socket, command }
}
async function page(route) {
  const target = await (await request(`http://127.0.0.1:${cdpPort}/json/new?${encodeURIComponent(origin + route)}`, { method: 'PUT' })).json()
  const { socket, command } = await connect(target.webSocketDebuggerUrl)
  const evaluate = async expression => {
    const response = await command('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
    if (response.exceptionDetails) throw new Error(JSON.stringify(response.exceptionDetails))
    return response.result.value
  }
  const wait = async (expression, message) => {
    for (let attempt = 0; attempt < 100; attempt++) { if (await evaluate(expression)) return; await sleep(40) }
    throw new Error(`${message}: ${await evaluate('document.body.innerText')}`)
  }
  const click = selector => evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`)
  const button = text => evaluate(`Array.from(document.querySelectorAll('button')).find(button => button.textContent.trim() === ${JSON.stringify(text)}).click()`)
  const field = (label, value) => evaluate(`(() => { const el = Array.from(document.querySelectorAll('label')).find(label => label.querySelector('span')?.textContent === ${JSON.stringify(label)}).querySelector('input, select, textarea'); const prototype = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(prototype, 'value').set.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input', { bubbles: true })); })()`)
  await command('Page.enable')
  await command('Runtime.enable')
  await command('Page.addScriptToEvaluateOnNewDocument', { source: "sessionStorage.setItem('adaptive-iam-session', 'token-a-initial')" })
  await command('Page.reload')
  await wait("document.querySelector('.user-button')?.textContent.includes('Alice Fixture')", 'Alice did not load')
  const signInBob = async () => {
    await click('.user-button')
    await wait("!!document.querySelector('.auth-dialog select')", 'Identity selector missing')
    await field('Demo identity', 'b')
    await click('.auth-dialog button[type="submit"]')
    await wait("document.querySelector('.user-button')?.textContent.includes('Bob Fixture') && !document.querySelector('.auth-dialog')", 'Bob did not sign in')
    return evaluate("sessionStorage.getItem('adaptive-iam-session')")
  }
  const result = { command, evaluate, wait, click, button, field, signInBob, socket, target }
  pages.push(result)
  return result
}
async function waitHeld(path) {
  for (let attempt = 0; attempt < 100; attempt++) { if (held?.path === path) return; await sleep(40) }
  throw new Error(`Missing held request ${path}`)
}

try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
  origin = `http://127.0.0.1:${server.address().port}`
  profile = await mkdtemp(join(tmpdir(), 'adaptive-iam-console-'))
  browserProcess = spawn(browser, ['--headless=new', '--disable-gpu', '--no-first-run', '--disable-background-networking', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], { windowsHide: true, stdio: 'ignore' })
  let launchError
  browserProcess.once('error', error => { launchError = error })
  let browserPath
  for (let attempt = 0; attempt < 100; attempt++) {
    if (launchError) throw new Error(`The browser could not start: ${launchError.message}`)
    if (browserProcess.exitCode !== null) throw new Error(`The browser exited before exposing its debugging port (code ${browserProcess.exitCode}).`)
    try { const portFile = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).trim().split('\n'); cdpPort = Number(portFile[0]); browserPath = portFile[1]; break } catch { await sleep(100) }
  }
  assert(cdpPort, 'The browser did not expose its debugging port within ten seconds.')
  browserClient = await connect(`ws://127.0.0.1:${cdpPort}${browserPath}`)
  {
    const p = await page('/overview')
    await p.click('[aria-label="Sign out and revoke session"]')
    await waitHeld('/api/auth/logout')
    const token = await p.signInBob()
    send(held.res, { status: 'logged_out' }); held = null
    await sleep(250)
    assert.equal(await p.evaluate("sessionStorage.getItem('adaptive-iam-session')"), token)
    assert.equal(await p.evaluate("document.querySelector('.user-button')?.textContent.includes('Bob Fixture')"), true)
    console.log('PASS delayed logout preserves the replacement identity')
  }
  for (const status of [401, 200]) {
    const p = await page('/audit')
    await p.button('Verify history')
    await waitHeld('/api/audit/verify')
    const token = await p.signInBob()
    send(held.res, status === 401 ? { detail: 'Old identity session expired' } : { valid: false, checked_events: 47, head_hash: 'old-identity', ledger_type: 'local', limitation: 'Stale fixture' }, status); held = null
    await sleep(250)
    assert.equal(await p.evaluate("sessionStorage.getItem('adaptive-iam-session')"), token)
    assert.equal(await p.evaluate("!!document.querySelector('.verification-result')"), false)
    assert.equal(await p.evaluate("document.body.innerText.includes('Old identity session expired')"), false)
    console.log(`PASS delayed audit ${status} preserves replacement session and clears old verification`)
  }
  {
    const p = await page('/security')
    await p.wait("!!Array.from(document.querySelectorAll('button')).find(button => button.textContent.startsWith('Active sessions'))", 'Security sessions tab missing')
    await p.evaluate("Array.from(document.querySelectorAll('button')).find(button => button.textContent.startsWith('Active sessions')).click()")
    await p.button('Revoke and sign out')
    await waitHeld('/api/auth/sessions/current/revoke')
    const token = await p.signInBob()
    send(held.res, { status: 'revoked' }); held = null
    await sleep(250)
    assert.equal(await p.evaluate("sessionStorage.getItem('adaptive-iam-session')"), token)
    assert.equal(await p.evaluate("document.querySelector('.user-button')?.textContent.includes('Bob Fixture')"), true)
    console.log('PASS delayed Security session-revoked callback preserves replacement identity')
  }
  {
    catalogFail = true
    const p = await page('/attack')
    await p.wait("document.body.innerText.includes('Fixture catalog unavailable')", 'Initial catalog failure not displayed')
    assert.equal(await p.evaluate("document.querySelector('.attack-case-panel select').disabled"), true)
    const before = catalogReads
    catalogFail = false
    await p.button('Refresh scenarios')
    await p.wait("!document.querySelector('.attack-case-panel select').disabled && document.querySelector('.attack-case-panel select').value === 'fixture'", 'Local refresh did not recover scenarios')
    assert(catalogReads > before)
    assert.equal(await p.evaluate("document.body.innerText.includes('Fixture catalog unavailable')"), false)
    console.log('PASS local attack catalog retry recovers after initial failure')
  }
  {
    const p = await page('/apps')
    await p.wait("document.body.innerText.includes('No applications registered yet.')", 'Developer workspace not loaded')
    await p.button('Register application')
    await p.field('Application name', 'Fixture website')
    await p.button('Continue to callbacks')
    await p.field('Exact callback URLs · one per line', Array.from({ length: 9 }, (_, index) => `https://fixture.example/callback/${index}`).join('\n'))
    const checkedBefore = callbackChecks
    await p.button('Check callbacks and continue')
    await p.wait("document.body.innerText.includes('Enter between one and eight callback URLs')", 'Nine callbacks were accepted')
    assert.equal(callbackChecks, checkedBefore)
    await p.field('Exact callback URLs · one per line', 'https://fixture.example/callback\nhttps://fixture.example/callback')
    await p.button('Check callbacks and continue')
    await p.wait("document.body.innerText.includes('Each callback URL must be unique')", 'Duplicate callbacks were accepted')
    assert.equal(callbackChecks, checkedBefore)
    await p.field('Exact callback URLs · one per line', Array.from({ length: 8 }, (_, index) => `https://fixture.example/callback/${index}`).join('\n'))
    await p.button('Check callbacks and continue')
    await p.wait("!!document.querySelector('.wizard-summary')", 'Eight unique callbacks did not advance')
    assert.equal(callbackChecks - checkedBefore, 8)
    assert.equal(appRegistrations, 0)
    await p.command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true })
    assert.equal(await p.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true)
    console.log('PASS callback wizard rejects excess/duplicates and accepts eight unique URLs; narrow view has no overflow')
  }
  {
    const p = await page('/access')
    await p.button('Open resource')
    holdResource = true
    await p.click('.resource-check-form button[type="submit"]')
    await waitHeld('/api/resources/vault/access')
    await p.field('Resource to open', 'logs')
    send(held.res, { allowed: true, resource_id: 'vault', resource_name: 'Fixture vault', scope: 'read', expires_at: '2099-01-01T00:00:00Z', reason: 'Stale fixture', content: { title: 'Stale vault result', records: ['stale-protected-fixture'] } }); held = null; holdResource = false
    await p.wait("document.querySelector('.resource-check-form button').textContent.trim() === 'Open resource'", 'Resource check did not complete')
    assert.equal(await p.evaluate("document.querySelector('.resource-check-form select').value"), 'logs')
    assert.equal(await p.evaluate("!!document.querySelector('.resource-access-result')"), false)
    assert.equal(await p.evaluate("document.body.innerText.includes('stale-protected-fixture')"), false)
    await p.click('.resource-check-form button[type="submit"]')
    await p.wait("document.querySelector('.protected-content')?.textContent.includes('protected-logs-fixture')", 'Selected resource did not open after the stale response')
    console.log('PASS changing resource during a delayed check discards its stale protected result')
  }
  {
    accessRequests = [fixtureRequest('expiring-request', { expires_at: new Date(Date.now() + 2500).toISOString() })]
    const p = await page('/access')
    await p.wait("!!document.querySelector('.request-card .badge-pending')", 'Pending request fixture did not load')
    await p.click('.request-card summary')
    assert.equal(await p.evaluate("!!document.querySelector('.vote-form')"), true)
    await p.wait("!!document.querySelector('.request-card .badge-expired')", 'Pending request did not expire without refresh')
    assert.equal(await p.evaluate("!!document.querySelector('.vote-form')"), false)
    assert.equal(await p.evaluate("document.querySelector('[aria-label=\"Filter requests\"] button:nth-child(3) span').textContent"), '0')
    await p.button('Pending')
    assert.equal(await p.evaluate("document.querySelectorAll('.request-card').length"), 0)
    await p.button('Expired')
    assert.equal(await p.evaluate("document.querySelectorAll('.request-card').length"), 1)
    accessRequests = []
    console.log('PASS pending expiry removes voting and updates status filters and review counts without refresh')
  }
  {
    accessGrants = [fixtureGrant('expiring-grant', { expires_at: new Date(Date.now() + 2500).toISOString() })]
    const p = await page('/access')
    await p.button('Grants')
    await p.wait("!!document.querySelector('.grant-revoke-button')", 'Active grant fixture did not load')
    await p.button('Active')
    await p.wait("document.querySelectorAll('.grant-panel tbody tr').length === 0", 'Expired grant remained in Active filter')
    await p.button('Expired')
    assert.equal(await p.evaluate("!!document.querySelector('.grant-panel .badge-expired')"), true)
    assert.equal(await p.evaluate("!!document.querySelector('.grant-revoke-button')"), false)
    accessGrants = []
    console.log('PASS elapsed grant moves from Active to Expired and removes revoke control without refresh')
  }
  {
    inspectionLifetime = 2500
    const p = await page('/access')
    await p.button('Open resource')
    await p.click('.resource-check-form button[type="submit"]')
    await p.wait("!!document.querySelector('.protected-content')", 'Protected snapshot fixture did not load')
    const checkedBefore = resourceChecks
    await p.wait("document.querySelector('.resource-access-result')?.textContent.includes('Grant expired')", 'Protected snapshot did not expire')
    assert.equal(await p.evaluate("!!document.querySelector('.protected-content')"), false)
    assert.equal(await p.evaluate("document.body.innerText.includes('protected-vault-fixture')"), false)
    assert.equal(resourceChecks, checkedBefore)
    await p.click('.resource-check-form button[type="submit"]')
    await p.wait("!!document.querySelector('.protected-content')", 'Explicit server recheck did not restore authorized content')
    assert.equal(resourceChecks, checkedBefore + 1)
    inspectionLifetime = null
    console.log('PASS protected snapshot disappears at expiry and requires an explicit server recheck')
  }
  {
    accessRequests = [fixtureRequest('review-vault'), fixtureRequest('denied-logs', { requester_id: 'a', requester_name: users[0].name, resource_id: 'logs', resource_name: resources[1].name, status: 'denied', expires_at: '2000-01-01T00:00:00Z', can_vote: false })]
    accessGrants = [fixtureGrant('active-vault'), fixtureGrant('revoked-logs', { user_id: 'b', user_name: users[1].name, resource_id: 'logs', resource_name: resources[1].name, status: 'revoked', expires_at: '2000-01-01T00:00:00Z' })]
    const p = await page('/access')
    await p.wait("document.querySelectorAll('.request-card').length === 2", 'Search request fixtures did not load')
    await p.field('Search requests', '  DENIED-LOGS ')
    assert.equal(await p.evaluate("document.querySelectorAll('.request-card').length"), 1)
    assert.equal(await p.evaluate("!!document.querySelector('.request-card .badge-denied')"), true)
    await p.button('Pending')
    assert.equal(await p.evaluate("document.querySelectorAll('.request-card').length"), 0)
    await p.button('Clear request filters')
    await p.button('By you')
    assert.equal(await p.evaluate("document.querySelector('.request-card summary strong').textContent"), 'Fixture logs')
    await p.button('Grants')
    await p.field('Search grants', '  REVOKED-LOGS ')
    assert.equal(await p.evaluate("document.querySelectorAll('.grant-panel tbody tr').length"), 1)
    assert.equal(await p.evaluate("!!document.querySelector('.grant-panel .badge-revoked')"), true)
    await p.button('Active')
    assert.equal(await p.evaluate("document.querySelectorAll('.grant-panel tbody tr').length"), 0)
    await p.button('Clear grant filters')
    await p.button('Granted to you')
    assert.equal(await p.evaluate("document.querySelector('.grant-panel tbody strong').textContent"), 'Fixture vault')
    await p.command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true })
    assert.equal(await p.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true)
    await p.button('Requests')
    assert.equal(await p.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true)
    await p.click('[aria-label="Switch to dark mode"]')
    assert.equal(await p.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true)
    accessRequests = []; accessGrants = []
    console.log('PASS request/grant searches combine with identity/status filters and clear correctly in both mobile themes')
  }
  {
    const expiresAt = new Date(Date.now() + 2500).toISOString()
    accessRequests = [fixtureRequest('overview-expiring-request', { expires_at: expiresAt })]
    accessGrants = [fixtureGrant('overview-expiring-grant', { expires_at: expiresAt })]
    const p = await page('/overview')
    const activeCount = "Array.from(document.querySelectorAll('.metric')).find(metric => metric.textContent.includes('Active grants'))?.querySelector('strong').textContent"
    await p.wait(`${activeCount} === '1'`, 'Overview active grant fixture did not load')
    await p.wait(`${activeCount} === '0' && !!document.querySelector('.resource-panel .badge-expired')`, 'Overview expiry did not update grant count and request status')
    assert.equal(await p.evaluate("document.querySelectorAll('.overview-columns .panel:last-child .policy-range').length"), 0)
    accessRequests = []; accessGrants = []
    console.log('PASS overview removes elapsed grants and updates recent request expiry without refresh')
  }
  {
    uncertaintyFail = true
    const p = await page('/research')
    await p.wait("document.querySelector('.uncertainty-study')?.textContent.includes('Fixture study unavailable')", 'Failed uncertainty study did not show its retry state')
    assert.equal(await p.evaluate("document.querySelector('.uncertainty-study button').disabled"), false)
    const readsBefore = uncertaintyReads
    uncertaintyFail = false
    await p.button('Retry study')
    await p.wait("!!document.querySelector('.uncertainty-study select')", 'Uncertainty study retry did not recover')
    assert.equal(uncertaintyReads, readsBefore + 1)
    assert.equal(await p.evaluate("document.querySelector('.uncertainty-study').textContent.includes('5 fresh training seeds')"), true)
    assert.equal(await p.evaluate("document.querySelector('.uncertainty-study tbody tr td:nth-child(2)').textContent.startsWith('12.0%')"), true)
    await p.field('Held-out condition', 'telemetry_masking')
    assert.equal(await p.evaluate("document.querySelector('.uncertainty-study tbody tr td:nth-child(2)').textContent.startsWith('4.0%')"), true)
    assert.equal(await p.evaluate("document.querySelectorAll('.uncertainty-study table')[1].querySelector('tbody tr td:nth-child(2)').textContent.startsWith('74.0%')"), true)
    assert.equal(await p.evaluate("Array.from(document.querySelectorAll('.uncertainty-study button')).find(button => button.textContent.trim() === 'Export uncertainty study')?.disabled"), false)
    await p.command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true })
    for (const theme of ['light', 'dark']) {
      if (await p.evaluate('document.documentElement.dataset.theme') !== theme) await p.click('.theme-button')
      await p.wait(`document.documentElement.dataset.theme === '${theme}'`, 'Research theme did not change')
      assert.equal(await p.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true)
    }
    console.log('PASS uncertainty study retries, switches condition metrics, enables export, and fits both mobile themes')
  }
  {
    lanlFail = true
    const p = await page('/research')
    await p.wait("document.querySelector('.real-data-study')?.textContent.includes('Fixture real-data study unavailable')", 'Failed real-data study did not show an actionable retry')
    assert.equal(await p.evaluate("!!document.querySelector('.uncertainty-study select')"), true)
    const readsBefore = lanlReads
    lanlFail = false
    await p.button('Retry real-data study')
    await p.wait("document.querySelector('.real-data-eligibility')?.textContent.includes('not estimable')", 'Real-data study retry did not recover the sparse-label report')
    assert.equal(lanlReads, readsBefore + 1)
    assert.equal(await p.evaluate("Array.from(document.querySelectorAll('.real-data-methods tbody tr td:last-child')).every(cell => cell.textContent.includes('Not estimable') && !cell.textContent.includes('0.0%'))"), true)
    assert.equal(await p.evaluate("Array.from(document.querySelectorAll('.real-data-study .protocol-list dd')).some(cell => cell.textContent === '500')"), true)
    await p.evaluate("window.__originalCreateUrl = URL.createObjectURL; URL.createObjectURL = blob => { window.__lanlExport = blob; return window.__originalCreateUrl(blob) }")
    await p.button('Export real-data study')
    const exported = await p.evaluate("window.__lanlExport.text().then(JSON.parse)")
    assert.deepEqual(exported, lanlStudy())
    console.log('PASS real-data study recovers after 503, separates sparse-label recall from zero, and exports the full report')
  }
  {
    lanlEligible = true
    const p = await page('/research')
    await p.wait("document.querySelector('.real-data-eligibility')?.textContent.includes('recall is eligible')", 'Eligible real-data fixture did not load')
    const cells = await p.evaluate("Array.from(document.querySelectorAll('.real-data-methods tbody tr td:last-child')).map(cell => cell.textContent)")
    assert.equal(cells.length, 3)
    assert(cells.every(cell => cell.includes('50.0%') && cell.includes('2 / 4 known test exercise tuples')))
    assert.equal(await p.evaluate("document.querySelector('.real-data-study').textContent.includes('8 / 96 unlabeled events')"), true)
    await p.command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true })
    for (const theme of ['light', 'dark']) {
      if (await p.evaluate('document.documentElement.dataset.theme') !== theme) await p.click('.theme-button')
      await p.wait(`document.documentElement.dataset.theme === '${theme}'`, 'Real-data theme did not change')
      assert.equal(await p.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true)
    }
    console.log('PASS real-data evidence shows exercise recall and unlabeled alert denominators and fits both mobile themes')
  }
  console.log('Frontend regression checks: 15 passed (isolated API fixtures, no real account mutations).')
} finally {
  if (held) held.res.destroy()
  for (const p of pages) p.socket.close()
  if (browserClient) { await browserClient.command('Browser.close').catch(() => {}); browserClient.socket.close() }
  if (browserProcess && browserProcess.exitCode === null) {
    for (let attempt = 0; attempt < 20 && browserProcess.exitCode === null; attempt++) await sleep(50)
    if (browserProcess.exitCode === null) browserProcess.kill()
  }
  server.closeAllConnections()
  if (server.listening) await new Promise(resolve => server.close(resolve))
  if (profile) {
    const tempRoot = resolve(tmpdir()) + sep
    assert(resolve(profile).startsWith(tempRoot) && basename(profile).startsWith('adaptive-iam-console-'), 'Refusing cleanup outside the test temporary directory.')
    await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(error => { console.warn(`The browser profile could not be removed: ${error.message}`) })
  }
}
