import http from 'node:http'
import fs from 'node:fs'
import { randomBytes } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { AdaptiveIamClient, IamError, loginTransaction, safeEqual, validateUrl } from '../node/adaptive-iam.mjs'
import { MemorySessionStore, SqliteSessionStore } from '../node/session-store.mjs'
import { dockerTransport } from './docker-transport.mjs'
import { homePage, pricingPage, workspacePage, errorPage } from './orbit-views.mjs'

const assets = new Map([
  ['/assets/orbit.css', { type: 'text/css; charset=utf-8', content: fs.readFileSync(new URL('./orbit.css', import.meta.url)) }],
  ['/assets/orbit.js', { type: 'text/javascript; charset=utf-8', content: fs.readFileSync(new URL('./orbit.js', import.meta.url)) }],
])
const randomId = () => randomBytes(32).toString('base64url')
const cookies = request => Object.fromEntries((request.headers.cookie || '').split(';').map(part => part.trim().split('=')).filter(pair => pair.length === 2))
const htmlAccepted = request => (request.headers.accept || '').split(',').some(value => value.trim().split(';')[0].toLowerCase() === 'text/html')
const securityHeaders = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
}
function reply(response, status, value, type = 'application/json') {
  response.writeHead(status, { ...securityHeaders, 'Content-Type': type })
  response.end(type === 'application/json' ? JSON.stringify(value) : value)
}
function redirect(response, location, setCookie) {
  response.writeHead(303, { ...securityHeaders, Location: location, 'Set-Cookie': setCookie })
  response.end()
}

/** Server-side sessions only. The injectable client is for isolated HTTP boundary tests. */
export function createSiteServer({ siteOrigin, client, consoleOrigin, clock = Date.now, sessionStore = new MemorySessionStore({ clock }) }) {
  const site = new URL(siteOrigin)
  const cookie = (name, value, age = 600) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${site.protocol === 'https:' ? '; Secure' : ''}`
  const activeSession = id => {
    const session = sessionStore.getSession(id)
    if (!session || session.expiresAt <= clock()) throw new IamError('login_required', 401)
    return session
  }
  // Store reads may block after the SDK has validated the grant's expiry.
  const currentGrant = access => {
    const expiry = typeof access?.expiresAt === 'string' ? Date.parse(access.expiresAt) : NaN
    return Number.isFinite(expiry) && expiry > clock()
  }
  async function verifyIdentity(session) {
    if (!session || !Number.isFinite(session.expiresAt) || session.expiresAt <= clock()) throw new IamError('login_required', 401)
    const metadata = await client.discover()
    const identity = await client.request(metadata.userinfo_endpoint, { token: session.accessToken })
    if (!identity || typeof identity.sub !== 'string' || identity.sub !== session.identity.sub) throw new IamError('subject_mismatch', 401)
    return identity
  }
  async function reportAccess(session) {
    try { return { state: 'allowed', result: await client.permission(session, 'research-vault') } }
    catch (error) {
      if (!(error instanceof IamError) || error.status === 401) throw error
      return { state: error.status === 403 ? 'locked' : 'unavailable' }
    }
  }
  return http.createServer(async (request, response) => {
    let html = false
    try {
      const now = clock()
      sessionStore.cleanup()
      const url = new URL(request.url, site); const jar = cookies(request)
      html = ['/','/pricing','/dashboard','/projects','/reports','/settings','/login','/callback'].includes(url.pathname) || (url.pathname === '/protected' && htmlAccepted(request))
      if (request.method === 'GET' && assets.has(url.pathname)) {
        const asset = assets.get(url.pathname)
        return reply(response, 200, asset.content, asset.type)
      }
      if (request.method === 'GET' && url.pathname === '/login') {
        const id = randomId(); const flow = { ...loginTransaction(), expiresAt: now + 300000 }
        sessionStore.putFlow(id, flow)
        return redirect(response, await client.authorizationUrl(flow), cookie('iam_login', id, 300))
      }
      if (request.method === 'GET' && url.pathname === '/callback') {
        const flow = sessionStore.consumeFlow(jar.iam_login)
        if (['state','iss','code','error'].some(key => url.searchParams.getAll(key).length > 1)) throw new IamError('invalid_callback_parameters', 401)
        if (!flow || flow.expiresAt <= now || !safeEqual(flow.state, url.searchParams.get('state'))) throw new IamError('invalid_login_state', 401)
        if (url.searchParams.get('iss') !== client.issuer) throw new IamError('callback_issuer_mismatch', 401)
        if (url.searchParams.has('error')) throw new IamError('login_not_approved', 401)
        const session = await client.exchangeCode({ code: url.searchParams.get('code'), verifier: flow.verifier, nonce: flow.nonce })
        if (!session || !Number.isFinite(session.expiresAt) || session.expiresAt <= clock() || typeof session.identity?.sub !== 'string' || !session.identity.sub) throw new IamError('invalid_website_session', 401)
        const id = randomId()
        try { sessionStore.putSession(id, session) }
        catch (error) { try { await client.revoke(session) } catch { /* No website session was created. */ } throw error }
        return redirect(response, '/dashboard', [cookie('iam_site_session', id, Math.max(1, Math.floor((session.expiresAt - clock()) / 1000))), cookie('iam_login', '', 0)])
      }
      const session = sessionStore.getSession(jar.iam_site_session)
      if (request.method === 'GET' && url.pathname === '/protected') {
        if (!session) throw new IamError('login_required', 401)
        const access = await client.permission(session, 'research-vault')
        activeSession(jar.iam_site_session)
        if (!currentGrant(access)) throw new IamError('grant_expired_or_invalid', 403)
        if (html) return reply(response, 200, workspacePage({ view: 'reports', identity: access.identity, session, access: { state: 'allowed', result: access }, consoleOrigin }), 'text/html; charset=utf-8')
        return reply(response, 200, { message: 'Your site returned this protected record after an IAM permission check.', user: access.identity.sub, resource: access.resourceId })
      }
      if (request.method === 'POST' && url.pathname === '/logout') {
        if (request.headers.origin !== site.origin) throw new IamError('invalid_origin', 403)
        const removed = sessionStore.deleteSession(jar.iam_site_session)
        if (removed) { try { await client.revoke(removed) } catch { /* Local session is already removed; no protected content is served. */ } }
        return redirect(response, '/', cookie('iam_site_session', '', 0))
      }
      if (request.method === 'GET' && ['/dashboard','/projects','/reports','/settings','/api/session'].includes(url.pathname)) {
        const identity = await verifyIdentity(session)
        let access = await reportAccess(session)
        activeSession(jar.iam_site_session)
        if (access.state === 'allowed' && !currentGrant(access.result)) access = { state: 'locked' }
        if (url.pathname === '/reports' && access.state !== 'allowed') throw new IamError(access.state === 'locked' ? 'access_denied' : 'iam_unavailable', access.state === 'locked' ? 403 : 503)
        if (url.pathname === '/api/session') return reply(response, 200, { identity: { sub: identity.sub, name: identity.name || identity.sub }, expires_at: new Date(session.expiresAt).toISOString(), reports: { state: access.state, ...(access.result ? { scope: access.result.scope, expires_at: access.result.expiresAt } : {}) } })
        return reply(response, 200, workspacePage({ view: url.pathname.slice(1), identity, session, access, consoleOrigin }), 'text/html; charset=utf-8')
      }
      if (request.method === 'GET' && url.pathname === '/') return reply(response, 200, homePage({ signedIn: Boolean(session), consoleOrigin }), 'text/html; charset=utf-8')
      if (request.method === 'GET' && url.pathname === '/pricing') return reply(response, 200, pricingPage({ signedIn: Boolean(session), consoleOrigin }), 'text/html; charset=utf-8')
      reply(response, 404, { error: 'not_found' })
    } catch (error) {
      const status = error instanceof IamError ? error.status : 503
      const code = error instanceof IamError ? error.code : 'iam_unavailable'
      if (html) return reply(response, status, errorPage({ status, code, consoleOrigin }), 'text/html; charset=utf-8')
      reply(response, status, { error: code })
    }
  })
}

function start() {
  const allowLocalHttp = process.env.IAM_ALLOW_LOCAL_HTTP === '1'
  const site = validateUrl(process.env.SITE_ORIGIN || 'http://127.0.0.1:3001', allowLocalHttp)
  if (site.pathname !== '/') throw new IamError('invalid_configuration', 500)
  const container = process.env.IAM_DOCKER_SITE === '1'
  const config = container && process.env.IAM_CLIENT_CONFIG_FILE ? JSON.parse(fs.readFileSync(process.env.IAM_CLIENT_CONFIG_FILE, 'utf8')) : {}
  const issuer = process.env.IAM_ISSUER || 'http://127.0.0.1:8000'
  const consoleOrigin = validateUrl(process.env.IAM_CONSOLE_ORIGIN || 'http://127.0.0.1:5173', allowLocalHttp).origin
  const client = new AdaptiveIamClient({ issuer, clientId: config.client_id || process.env.IAM_CLIENT_ID, clientSecret: config.client_secret || process.env.IAM_CLIENT_SECRET || '', redirectUri: new URL('/callback', site).href, allowLocalHttp, ...(container ? { fetchImpl: dockerTransport(issuer) } : {}) })
  if (!process.env.IAM_SITE_SESSION_DB && (process.env.IAM_SITE_SESSION_KEY || process.env.IAM_SITE_SESSION_KEY_FILE)) throw new IamError('invalid_configuration', 500)
  const sessionStore = process.env.IAM_SITE_SESSION_DB ? new SqliteSessionStore({
    filename: process.env.IAM_SITE_SESSION_DB, keyFile: process.env.IAM_SITE_SESSION_KEY_FILE,
    encryptionKey: process.env.IAM_SITE_SESSION_KEY, namespace: JSON.stringify([site.origin, client.issuer, client.clientId]),
  }) : new MemorySessionStore()
  const server = createSiteServer({ siteOrigin: site.origin, client, consoleOrigin, sessionStore })
  server.once('close', () => sessionStore.close())
  server.listen(Number(process.env.SITE_PORT || site.port || 3001), container ? '0.0.0.0' : '127.0.0.1', () => console.log(`Orbit Workspace: ${site.origin}. Tokens and client secrets stay on its server.`))
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) start()
