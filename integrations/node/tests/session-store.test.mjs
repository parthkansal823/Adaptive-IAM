import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHash, randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { Worker } from 'node:worker_threads'
import { test } from 'node:test'
import { DatabaseSync } from 'node:sqlite'
import { SqliteSessionStore, MemorySessionStore } from '../session-store.mjs'
import { loginTransaction } from '../adaptive-iam.mjs'
import { createSiteServer } from '../../examples/node-site.mjs'

const id = () => randomBytes(32).toString('base64url')
const failure = error => error.code === 'session_store_unavailable' && error.status === 503 && error.message === 'session_store_unavailable'
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'iam-site-store-'))
  const filename = path.join(directory, 'sessions.sqlite'); const opened = []
  const state = { now: Date.now() }
  const open = (extra = {}) => {
    const store = new SqliteSessionStore({ filename, namespace: 'https://site.example|https://iam.example|fixture-client', clock: () => state.now, ...extra })
    opened.push(store); return store
  }
  const close = store => { store.close(); opened.splice(opened.indexOf(store), 1) }
  t.after(() => { for (const store of opened) store.close(); fs.rmSync(directory, { recursive: true, force: true }) })
  return { directory, filename, state, open, close, flow: () => ({ ...loginTransaction(), expiresAt: state.now + 300_000 }), session: () => ({ accessToken: 'fixture-server-token-private', identity: { sub: 'aisha', name: 'Aisha' }, expiresAt: state.now + 600_000 }) }
}

test('memory default isolates workers and expires authority at the exact boundary', () => {
  let now = Date.now(); const first = new MemorySessionStore({ clock: () => now }); const other = new MemorySessionStore({ clock: () => now })
  const token = id(); const flow = { ...loginTransaction(), expiresAt: now + 300_000 }
  first.putFlow(token, flow)
  assert.equal(other.consumeFlow(token), undefined)
  assert.deepEqual(first.consumeFlow(token), flow); assert.equal(first.consumeFlow(token), undefined)
  first.putFlow(token, flow); now = flow.expiresAt
  assert.equal(first.consumeFlow(token), undefined)
})

test('flows and sessions survive restart; encrypted payloads and hashed cookies stay off disk', t => {
  const f = fixture(t); let store = f.open(); const flowId = id(); const sessionId = id(); const flow = f.flow(); const session = f.session()
  store.putFlow(flowId, flow); store.putSession(sessionId, session); f.close(store)
  const disk = fs.readFileSync(f.filename)
  for (const secret of [session.accessToken, session.identity.sub, flow.state, flow.nonce, flow.verifier, flowId, sessionId]) assert.equal(disk.includes(Buffer.from(secret)), false)
  assert.equal(fs.statSync(f.filename + '.key').size, 32)
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(f.filename + '.key').mode & 0o777, 0o600)
    assert.equal(fs.statSync(f.filename).mode & 0o777, 0o600)
  }
  store = f.open()
  assert.deepEqual(store.consumeFlow(flowId), flow); assert.equal(store.consumeFlow(flowId), undefined)
  assert.deepEqual(store.getSession(sessionId), session)
})

test('independent workers share revocation, namespace boundaries and strict expiry', t => {
  const f = fixture(t); const first = f.open(); const second = f.open(); const otherSite = f.open({ namespace: 'another-site' }); const sessionId = id(); const flowId = id()
  first.putSession(sessionId, f.session()); first.putFlow(flowId, f.flow())
  assert.equal(otherSite.getSession(sessionId), undefined); assert.equal(otherSite.consumeFlow(flowId), undefined)
  assert.deepEqual(second.deleteSession(sessionId), f.session()); assert.equal(first.getSession(sessionId), undefined)
  first.putSession(sessionId, f.session()); f.state.now += 300_000
  assert.equal(second.consumeFlow(flowId), undefined)
  f.state.now += 300_000
  assert.equal(second.getSession(sessionId), undefined)
})

test('persisted sessions reject excessive remaining lifetime after a clock rollback', t => {
  const f = fixture(t); const writer = f.open(); const sessionId = id(); const session = f.session()
  writer.putSession(sessionId, session); f.close(writer)
  // A reader clock rollback makes this expiry exceed the maximum remaining
  // lifetime. It must fail closed without deleting the stored session.
  f.state.now--
  const reader = f.open()
  assert.throws(() => reader.getSession(sessionId), failure)
  f.state.now++
  assert.deepEqual(reader.getSession(sessionId), session)
  f.state.now = session.expiresAt
  assert.equal(reader.getSession(sessionId), undefined)
})

test('cleanup removes a bounded batch and expired rows never regain authority', t => {
  const f = fixture(t); const store = f.open()
  for (let n = 0; n < 200; n++) store.putFlow(id(), f.flow())
  f.state.now += 300_000
  store.cleanup()
  const inspect = new DatabaseSync(f.filename)
  try { assert.equal(inspect.prepare('SELECT count(*) AS total FROM site_sessions').get().total, 72) }
  finally { inspect.close() }
  store.cleanup()
  const next = id(); store.putFlow(next, f.flow()); assert.ok(store.consumeFlow(next))
})

test('capacity is shared across handles and invalid expiry cannot enter the store', t => {
  const f = fixture(t); const first = f.open(); const second = f.open()
  for (let n = 0; n < 256; n++) (n % 2 ? first : second).putFlow(id(), f.flow())
  assert.throws(() => second.putFlow(id(), f.flow()), error => error.code === 'login_capacity_reached' && error.status === 429)
  for (const expiresAt of [NaN, Infinity, f.state.now, f.state.now + 600_001]) assert.throws(() => first.putSession(id(), { ...f.session(), expiresAt }), error => error.status === 401)
})

test('ciphertext, expiry and cookie binding tampering fail closed without secret diagnostics', t => {
  const f = fixture(t); const store = f.open(); const sessionId = id(); store.putSession(sessionId, f.session())
  const edit = new DatabaseSync(f.filename)
  try {
    const original = edit.prepare("SELECT * FROM site_sessions WHERE kind='session'").get()
    edit.prepare("UPDATE site_sessions SET expires=expires+1 WHERE kind='session'").run()
    assert.throws(() => store.getSession(sessionId), failure)
    edit.prepare("UPDATE site_sessions SET expires=?,body=? WHERE kind='session'").run(original.expires, original.body.slice(0, -3) + 'AAA')
    assert.throws(() => store.getSession(sessionId), failure)
    const replacement = id()
    edit.prepare("UPDATE site_sessions SET body=?,id=? WHERE kind='session'").run(original.body, createHash('sha256').update(replacement).digest('hex'))
    assert.equal(store.getSession(sessionId), undefined)
    // A valid encrypted row copied under a different cookie digest still cannot authenticate.
    assert.throws(() => store.getSession(replacement), failure)
    edit.prepare("UPDATE site_sessions SET id=? WHERE kind='session'").run(original.id)
    assert.deepEqual(store.getSession(sessionId), f.session())
  } finally { edit.close() }
})

test('wrong, malformed or missing keys never reset an existing store', t => {
  const f = fixture(t); const key = randomBytes(32).toString('base64url'); const store = f.open({ encryptionKey: key }); const sessionId = id(); store.putSession(sessionId, f.session()); f.close(store)
  assert.equal(fs.existsSync(f.filename + '.key'), false)
  assert.throws(() => f.open({ encryptionKey: randomBytes(32).toString('base64url') }), failure)
  assert.throws(() => f.open({ encryptionKey: 'invalid-key' }), failure)
  assert.throws(() => f.open(), failure)
  assert.equal(fs.existsSync(f.filename + '.key'), false)
  assert.deepEqual(f.open({ encryptionKey: key }).getSession(sessionId), f.session())
})

test('a lost or truncated managed key fails closed without regenerating authority', t => {
  const f = fixture(t); const store = f.open(); store.putSession(id(), f.session()); f.close(store)
  const keyFile = f.filename + '.key'; const original = fs.readFileSync(keyFile)
  fs.writeFileSync(keyFile, Buffer.from('short'))
  assert.throws(() => f.open(), failure); assert.equal(fs.readFileSync(keyFile, 'utf8'), 'short')
  fs.rmSync(keyFile)
  assert.throws(() => f.open(), failure); assert.equal(fs.existsSync(keyFile), false)
  fs.writeFileSync(keyFile, original)
  assert.ok(f.open())
})

test('corrupt databases and unsupported schemas are preserved and rejected', t => {
  const f = fixture(t)
  fs.writeFileSync(f.filename, 'fixture-invalid-sqlite-private-marker')
  assert.throws(() => f.open({ encryptionKey: randomBytes(32).toString('base64url') }), failure)
  assert.equal(fs.readFileSync(f.filename, 'utf8'), 'fixture-invalid-sqlite-private-marker')
  fs.rmSync(f.filename)
  const store = f.open(); f.close(store)
  const edit = new DatabaseSync(f.filename); edit.exec('PRAGMA user_version=999'); edit.close()
  assert.throws(() => f.open(), failure)
})

test('atomic callback consumption across simultaneous Node workers allows one winner', async t => {
  const f = fixture(t); const store = f.open(); const flowId = id(); store.putFlow(flowId, f.flow()); f.close(store)
  const workers = Array.from({ length: 4 }, () => new Worker(`
    const { parentPort, workerData } = require('node:worker_threads');
    import(workerData.module).then(({ SqliteSessionStore }) => {
      const store = new SqliteSessionStore(workerData.options);
      parentPort.postMessage('ready');
      parentPort.once('message', () => {
        try { parentPort.postMessage(Boolean(store.consumeFlow(workerData.id))); }
        finally { store.close(); }
      });
    }).catch(() => { parentPort.postMessage('failed'); process.exitCode = 1; });
  `, { eval: true, workerData: { module: new URL('../session-store.mjs', import.meta.url).href, id: flowId, options: { filename: f.filename, namespace: 'https://site.example|https://iam.example|fixture-client' } } }))
  t.after(async () => { await Promise.all(workers.map(worker => worker.terminate())) })
  const ready = await Promise.all(workers.map(worker => once(worker, 'message').then(([value]) => value)))
  assert.deepEqual(ready, ['ready', 'ready', 'ready', 'ready'])
  const results = workers.map(worker => once(worker, 'message').then(([value]) => value))
  for (const worker of workers) worker.postMessage('consume')
  assert.equal((await Promise.all(results)).filter(Boolean).length, 1)
  assert.equal(f.open().consumeFlow(flowId), undefined)
})

test('simultaneous first-start workers publish one complete encryption key', async t => {
  const f = fixture(t)
  const ids = [id(), id(), id(), id()]
  const session = f.session()
  const workers = ids.map(sessionId => new Worker(`
    const { parentPort, workerData } = require('node:worker_threads');
    import(workerData.module).then(({ SqliteSessionStore }) => {
      parentPort.postMessage('ready');
      parentPort.once('message', () => {
        let store;
        try {
          store = new SqliteSessionStore({ ...workerData.options, clock: () => workerData.now });
          store.putSession(workerData.id, workerData.session);
          parentPort.postMessage('saved');
        } catch {
          parentPort.postMessage('failed'); process.exitCode = 1;
        } finally { store?.close(); }
      });
    }).catch(() => { parentPort.postMessage('failed'); process.exitCode = 1; });
  `, { eval: true, workerData: { module: new URL('../session-store.mjs', import.meta.url).href, id: sessionId, session, now: f.state.now, options: { filename: f.filename, namespace: 'https://site.example|https://iam.example|fixture-client' } } }))
  t.after(async () => { await Promise.all(workers.map(worker => worker.terminate())) })
  assert.deepEqual(await Promise.all(workers.map(worker => once(worker, 'message').then(([value]) => value))), ['ready', 'ready', 'ready', 'ready'])
  const saved = workers.map(worker => once(worker, 'message').then(([value]) => value))
  // Imported workers cross this barrier together; the fixed fixture clock is
  // shared by their writes and the later reader, independently of ACL latency.
  for (const worker of workers) worker.postMessage('start')
  assert.deepEqual(await Promise.all(saved), ['saved', 'saved', 'saved', 'saved'])
  assert.equal(fs.statSync(f.filename + '.key').size, 32)
  const store = f.open()
  const inspect = new DatabaseSync(f.filename)
  try {
    assert.deepEqual(inspect.prepare('SELECT expires FROM site_sessions').all().map(row => row.expires), ids.map(() => session.expiresAt))
  } finally { inspect.close() }
  for (const sessionId of ids) assert.deepEqual(store.getSession(sessionId), session)
  assert.equal(fs.readdirSync(f.directory).some(name => name.endsWith('.tmp')), false)
})

test('HTTP login survives worker restart, logout reaches other workers and delayed responses lose authority', async t => {
  const f = fixture(t); const issuer = 'http://127.0.0.1:8000'; const site = 'http://127.0.0.1:3001'
  let flow; let exchanges = 0; let permissionStarted; let releasePermission; let revokeCalls = 0
  const provider = {
    issuer, async authorizationUrl(value) { flow = value; return issuer + '/oauth/authorize' },
    async exchangeCode({ verifier, nonce }) { assert.equal(verifier, flow.verifier); assert.equal(nonce, flow.nonce); exchanges++; return f.session() },
    async permission() {
      if (permissionStarted) { permissionStarted(); await new Promise(resolve => { releasePermission = resolve }) }
      return { identity: { sub: 'aisha' }, resourceId: 'research-vault', scope: 'read', expiresAt: new Date(f.state.now + 120_000).toISOString() }
    }, async revoke() { revokeCalls++ },
  }
  const servers = []
  async function listen(store) {
    const server = createSiteServer({ siteOrigin: site, client: provider, consoleOrigin: issuer, sessionStore: store, clock: () => f.state.now })
    server.listen(0, '127.0.0.1'); await once(server, 'listening'); servers.push(server)
    return (url, cookie, options = {}) => fetch('http://127.0.0.1:' + server.address().port + url, { redirect: 'manual', ...options, headers: { ...(cookie ? { Cookie: cookie } : {}), ...options.headers } })
  }
  t.after(async () => { await Promise.all(servers.map(server => new Promise(resolve => { server.close(resolve); server.closeAllConnections() }))) })
  const firstStore = f.open(); const first = await listen(firstStore)
  const begun = await first('/login'); const loginCookie = begun.headers.getSetCookie()[0].split(';')[0]
  await new Promise(resolve => { servers[0].close(resolve); servers[0].closeAllConnections() }); f.close(firstStore)
  const next = await listen(f.open()); const other = await listen(f.open())
  const callback = '/callback?' + new URLSearchParams({ state: flow.state, iss: issuer, code: 'fixture-code' })
  const loggedIn = await next(callback, loginCookie); assert.equal(loggedIn.status, 303)
  assert.equal((await other(callback, loginCookie)).status, 401); assert.equal(exchanges, 1)
  const sessionCookie = loggedIn.headers.getSetCookie().find(value => value.startsWith('iam_site_session=')).split(';')[0]
  assert.equal((await other('/protected', sessionCookie)).status, 200)
  const waiting = new Promise(resolve => { permissionStarted = resolve })
  const pending = next('/protected', sessionCookie); await waiting
  assert.equal((await other('/logout', sessionCookie, { method: 'POST', headers: { Origin: site } })).status, 303)
  assert.equal(revokeCalls, 1); releasePermission()
  const refused = await pending; assert.equal(refused.status, 401); assert.doesNotMatch(await refused.text(), /protected record/)
  assert.equal((await next('/protected', sessionCookie)).status, 401)
})
