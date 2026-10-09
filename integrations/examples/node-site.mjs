import http from 'node:http'
import { randomBytes } from 'node:crypto'
import { AdaptiveIamClient, IamError, loginTransaction, safeEqual, validateUrl } from '../node/adaptive-iam.mjs'

const site = validateUrl(process.env.SITE_ORIGIN || 'http://127.0.0.1:3001', process.env.IAM_ALLOW_LOCAL_HTTP === '1')
const client = new AdaptiveIamClient({ issuer: process.env.IAM_ISSUER || 'http://127.0.0.1:8000', clientId: process.env.IAM_CLIENT_ID, clientSecret: process.env.IAM_CLIENT_SECRET || '', redirectUri: new URL('/callback', site).href, allowLocalHttp: process.env.IAM_ALLOW_LOCAL_HTTP === '1' })
const flows = new Map(); const sessions = new Map()
const randomId = () => randomBytes(32).toString('base64url')
const cookie = (name, value, age = 600) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${site.protocol === 'https:' ? '; Secure' : ''}`
const cookies = request => Object.fromEntries((request.headers.cookie || '').split(';').map(part => part.trim().split('=')).filter(pair => pair.length === 2))
const escape = value => String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character])
const page = body => `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Adaptive IAM connected website</title><style>body{font:16px system-ui;background:#111;color:#fafafa;max-width:640px;margin:10vh auto;padding:24px}a,button{color:#ff8a34}h1{font-size:36px}code{color:#ddd}button{background:transparent;border:1px solid #666;padding:10px;border-radius:8px}</style><h1>Your website, connected.</h1>${body}</html>`

function reply(response, status, value, type = 'application/json') {
  response.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" })
  response.end(type === 'application/json' ? JSON.stringify(value) : value)
}
function redirect(response, location, setCookie) { response.writeHead(303, { Location: location, 'Set-Cookie': setCookie, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' }); response.end() }

const server = http.createServer(async (request, response) => {
  try {
    const now = Date.now()
    for (const [id, flow] of flows) if (flow.expiresAt <= now) flows.delete(id)
    for (const [id, session] of sessions) if (session.expiresAt <= now) sessions.delete(id)
    const url = new URL(request.url, site); const jar = cookies(request)
    if (request.method === 'GET' && url.pathname === '/login') {
      if (flows.size >= 256) return reply(response, 429, { error: 'login_capacity_reached' })
      const id = randomId(); const flow = { ...loginTransaction(), expiresAt: now + 300000 }
      flows.set(id, flow)
      return redirect(response, await client.authorizationUrl(flow), cookie('iam_login', id, 300))
    }
    if (request.method === 'GET' && url.pathname === '/callback') {
      const flow = flows.get(jar.iam_login); flows.delete(jar.iam_login)
      if (!flow || flow.expiresAt <= now || !safeEqual(flow.state, url.searchParams.get('state'))) throw new IamError('invalid_login_state', 401)
      if (url.searchParams.has('error')) throw new IamError('login_not_approved', 401)
      const session = await client.exchangeCode({ code: url.searchParams.get('code'), verifier: flow.verifier, nonce: flow.nonce })
      if (sessions.size >= 1024) throw new IamError('session_capacity_reached')
      const id = randomId(); sessions.set(id, session)
      return redirect(response, '/', [cookie('iam_site_session', id, Math.max(1, Math.floor((session.expiresAt - Date.now()) / 1000))), cookie('iam_login', '', 0)])
    }
    const session = sessions.get(jar.iam_site_session)
    if (request.method === 'GET' && url.pathname === '/protected') {
      if (!session) throw new IamError('login_required', 401)
      const access = await client.permission(session, 'research-vault')
      return reply(response, 200, { message: 'Your site returned this protected record after an IAM permission check.', user: access.identity.sub, resource: access.resourceId })
    }
    if (request.method === 'POST' && url.pathname === '/logout') {
      if (request.headers.origin !== site.origin) throw new IamError('invalid_origin', 403)
      sessions.delete(jar.iam_site_session)
      return redirect(response, '/', cookie('iam_site_session', '', 0))
    }
    if (request.method === 'GET' && url.pathname === '/') {
      const body = session ? `<p>Signed in as <strong>${escape(session.identity.name || session.identity.sub)}</strong>.</p><p><a href="/protected">Open protected research page</a></p><p>Login identifies you. A separate active resource grant is required for the protected page.</p><form method="post" action="/logout"><button>Sign out</button></form>` : '<p>Use this button like a federated sign-in provider.</p><p><a href="/login">Sign in with Adaptive IAM</a></p>'
      return reply(response, 200, page(body), 'text/html; charset=utf-8')
    }
    reply(response, 404, { error: 'not_found' })
  } catch (error) {
    reply(response, error instanceof IamError ? error.status : 503, { error: error instanceof IamError ? error.code : 'iam_unavailable' })
  }
})
server.listen(Number(site.port || (site.protocol === 'https:' ? 443 : 80)), '127.0.0.1', () => console.log(`Connected website: ${site.origin}. Tokens and client secrets stay on its server.`))
