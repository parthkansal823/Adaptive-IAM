import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { IamError } from './adaptive-iam.mjs'

const require = createRequire(import.meta.url)
const limits = { flow: 256, session: 1024 }
const lifetimes = { flow: 300_000, session: 600_000 }
const idPattern = /^[A-Za-z0-9_-]{43}$/
const unavailable = () => new IamError('session_store_unavailable', 503)
const valid = (kind, value, now) => value && Number.isSafeInteger(value.expiresAt) && value.expiresAt > now && value.expiresAt <= now + lifetimes[kind] && (kind === 'flow'
  ? ['state', 'nonce', 'verifier'].every(key => typeof value[key] === 'string' && idPattern.test(value[key]))
  : typeof value.accessToken === 'string' && value.accessToken.length > 0 && typeof value.identity?.sub === 'string' && value.identity.sub.length > 0)
const capacity = kind => new IamError(kind === 'flow' ? 'login_capacity_reached' : 'session_capacity_reached', 429)

/** Default for isolated examples/fixtures. No process-global or browser token storage. */
export class MemorySessionStore {
  constructor({ clock = Date.now } = {}) { this.clock = clock; this.records = { flow: new Map(), session: new Map() } }
  cleanup() {
    for (const records of Object.values(this.records)) for (const [id, value] of records) if (value.expiresAt <= this.clock()) records.delete(id)
  }
  put(kind, id, value) {
    this.cleanup()
    if (!idPattern.test(id) || !valid(kind, value, this.clock())) throw new IamError('invalid_website_session', 401)
    if (this.records[kind].size >= limits[kind]) throw capacity(kind)
    if (this.records[kind].has(id)) throw unavailable()
    this.records[kind].set(id, structuredClone(value))
  }
  read(kind, id, consume = false) {
    const value = this.records[kind].get(id)
    if (consume) this.records[kind].delete(id)
    return valid(kind, value, this.clock()) ? structuredClone(value) : undefined
  }
  putFlow(id, value) { this.put('flow', id, value) }
  consumeFlow(id) { return this.read('flow', id, true) }
  putSession(id, value) { this.put('session', id, value) }
  getSession(id) { return this.read('session', id) }
  deleteSession(id) { return this.read('session', id, true) }
  close() { for (const records of Object.values(this.records)) records.clear() }
}

// chmod does not restrict Windows ACLs. Apply one protected DACL containing
// only the running account and SYSTEM, without an intermediate permissive ACL.
// The constant script receives the filename through the child environment.
function restrictFile(filename) {
  if (process.platform === 'win32') {
    const script = `$ErrorActionPreference='Stop'; $acl=New-Object System.Security.AccessControl.FileSecurity; $acl.SetAccessRuleProtection($true,$false); $owner=[System.Security.Principal.WindowsIdentity]::GetCurrent().User; $system=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18'); foreach($identity in @($owner,$system)) { $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($identity,'FullControl','Allow'); $acl.AddAccessRule($rule) }; [System.IO.File]::SetAccessControl($env:IAM_PRIVATE_SESSION_FILE,$acl)`
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
      stdio: 'ignore', windowsHide: true, env: { ...process.env, IAM_PRIVATE_SESSION_FILE: filename },
    })
  } else fs.chmodSync(filename, 0o600)
}
function regularFile(filename) {
  const stat = fs.lstatSync(filename)
  if (!stat.isFile() || stat.isSymbolicLink()) throw unavailable()
  return stat
}
function ensureDatabase(filename) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 })
  try { fs.closeSync(fs.openSync(filename, 'wx', 0o600)) } catch (error) { if (error.code !== 'EEXIST') throw error }
  const stat = regularFile(filename)
  restrictFile(filename)
  return stat.size > 0
}
function loadKey(filename, allowCreate) {
  if (!fs.existsSync(filename) && allowCreate) {
    fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 })
    const temporary = filename + '.' + randomBytes(16).toString('hex') + '.tmp'
    let descriptor
    try {
      descriptor = fs.openSync(temporary, 'wx', 0o600)
      restrictFile(temporary)
      fs.writeFileSync(descriptor, randomBytes(32)); fs.fsyncSync(descriptor)
      fs.closeSync(descriptor); descriptor = undefined
      // Publish a complete key once. Competing workers load the same winner.
      try { fs.linkSync(temporary, filename) } catch (error) { if (error.code !== 'EEXIST') throw error }
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor)
      fs.rmSync(temporary, { force: true })
    }
  }
  if (regularFile(filename).size !== 32) throw unavailable()
  restrictFile(filename)
  const key = fs.readFileSync(filename)
  if (key.length !== 32) throw unavailable()
  return key
}
function providedKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw unavailable()
  const key = Buffer.from(value, 'base64url')
  if (key.length !== 32 || key.toString('base64url') !== value) throw unavailable()
  return key
}

/** Same-host, bounded SQLite store. Every operation uses SQLite authority, never a worker cache. */
export class SqliteSessionStore {
  constructor({ filename, keyFile, encryptionKey, namespace, clock = Date.now }) {
    this.clock = clock
    try {
      if (typeof filename !== 'string' || !filename || filename === ':memory:' || typeof namespace !== 'string' || !namespace || (keyFile && encryptionKey)) throw unavailable()
      this.filename = path.resolve(filename)
      const existed = ensureDatabase(this.filename)
      const resolvedKey = path.resolve(keyFile || this.filename + '.key')
      if (resolvedKey === this.filename) throw unavailable()
      this.key = encryptionKey ? providedKey(encryptionKey) : loadKey(resolvedKey, !existed)
      this.scope = createHash('sha256').update(namespace).digest('hex')
      const { DatabaseSync } = require('node:sqlite')
      this.db = new DatabaseSync(this.filename, { timeout: 3000, allowExtension: false })
      this.db.exec('PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON')
      this.transaction(() => {
        const version = this.db.prepare('PRAGMA user_version').get().user_version
        const tables = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all()
        if (version === 0 && tables.length === 0) {
          this.db.exec(`CREATE TABLE store_meta (id INTEGER PRIMARY KEY CHECK(id=1), marker TEXT NOT NULL) STRICT;
            CREATE TABLE site_sessions (scope TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('flow','session')), id TEXT NOT NULL, expires INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(scope,kind,id)) STRICT;
            CREATE INDEX session_expiry ON site_sessions(expires); PRAGMA user_version=1`)
          this.db.prepare('INSERT INTO store_meta VALUES (1, ?)').run(this.seal('adaptive-iam-site-store-v1', 'store-key-check'))
        } else if (version !== 1 || tables.length !== 2 || !tables.some(table => table.name === 'store_meta') || !tables.some(table => table.name === 'site_sessions')) throw unavailable()
        const marker = this.db.prepare('SELECT marker FROM store_meta WHERE id=1').get()?.marker
        if (this.open(marker, 'store-key-check') !== 'adaptive-iam-site-store-v1') throw unavailable()
      })
      this.cleanup()
    } catch {
      try { this.db?.close() } catch { /* Fail closed without leaking transport/filesystem details. */ }
      throw unavailable()
    }
  }
  transaction(action) {
    this.db.exec('BEGIN IMMEDIATE')
    try { const result = action(); this.db.exec('COMMIT'); return result }
    catch (error) { try { this.db.exec('ROLLBACK') } catch { /* Preserve the failure. */ } throw error }
  }
  seal(value, aad) {
    const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', this.key, iv)
    cipher.setAAD(Buffer.from(aad))
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()])
    return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url')
  }
  open(value, aad) {
    if (typeof value !== 'string' || value.length > 65536 || !/^[A-Za-z0-9_-]+$/.test(value)) throw unavailable()
    const packed = Buffer.from(value, 'base64url')
    if (packed.length < 29) throw unavailable()
    const cipher = createDecipheriv('aes-256-gcm', this.key, packed.subarray(0, 12))
    cipher.setAuthTag(packed.subarray(12, 28)); cipher.setAAD(Buffer.from(aad))
    return JSON.parse(Buffer.concat([cipher.update(packed.subarray(28)), cipher.final()]).toString('utf8'))
  }
  hash(id) { return createHash('sha256').update(id).digest('hex') }
  aad(kind, id, expires) { return JSON.stringify([1, this.scope, kind, id, expires]) }
  cleanup() {
    try { this.db.prepare('DELETE FROM site_sessions WHERE rowid IN (SELECT rowid FROM site_sessions WHERE expires<=? LIMIT 128)').run(this.clock()) }
    catch { throw unavailable() }
  }
  put(kind, id, value) {
    if (typeof id !== 'string' || !idPattern.test(id) || !valid(kind, value, this.clock())) throw new IamError('invalid_website_session', 401)
    const plain = JSON.stringify(value)
    if (Buffer.byteLength(plain) > 32768) throw new IamError('invalid_website_session', 401)
    try {
      this.transaction(() => {
        this.cleanup()
        if (this.db.prepare('SELECT COUNT(*) AS total FROM site_sessions WHERE kind=?').get(kind).total >= limits[kind]) throw capacity(kind)
        const hashed = this.hash(id)
        this.db.prepare('INSERT INTO site_sessions VALUES (?,?,?,?,?)').run(this.scope, kind, hashed, value.expiresAt, this.seal(value, this.aad(kind, hashed, value.expiresAt)))
      })
    } catch (error) { if (error instanceof IamError) throw error; throw unavailable() }
  }
  read(kind, id, consume = false) {
    if (typeof id !== 'string' || !idPattern.test(id)) return undefined
    try {
      const hashed = this.hash(id)
      // DELETE RETURNING is atomic across processes; only one callback can exchange a code.
      const row = this.db.prepare(consume
        ? 'DELETE FROM site_sessions WHERE scope=? AND kind=? AND id=? RETURNING expires,body'
        : 'SELECT expires,body FROM site_sessions WHERE scope=? AND kind=? AND id=?').get(this.scope, kind, hashed)
      if (!row || row.expires <= this.clock()) return undefined
      const value = this.open(row.body, this.aad(kind, hashed, row.expires))
      if (!valid(kind, value, this.clock()) || value.expiresAt !== row.expires) throw unavailable()
      return value
    } catch { throw unavailable() }
  }
  putFlow(id, value) { this.put('flow', id, value) }
  consumeFlow(id) { return this.read('flow', id, true) }
  putSession(id, value) { this.put('session', id, value) }
  getSession(id) { return this.read('session', id) }
  deleteSession(id) { return this.read('session', id, true) }
  close() { this.db.close(); this.key.fill(0) }
}
