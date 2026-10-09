import assert from 'node:assert/strict'
import { before, test } from 'node:test'
import { createHash } from 'node:crypto'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { AdaptiveIamClient, IamError, loginTransaction, safeEqual } from '../adaptive-iam.mjs'

const issuer = 'https://iam.example'; const clientId = 'website-client'
const metadata = { issuer, authorization_endpoint: `${issuer}/oauth/authorize`, token_endpoint: `${issuer}/oauth/token`, userinfo_endpoint: `${issuer}/oauth/userinfo`, jwks_uri: `${issuer}/oauth/jwks`, revocation_endpoint: `${issuer}/oauth/revoke` }
let publicKey, privateKey, jwk
before(async () => { ({ publicKey, privateKey } = await generateKeyPair('RS256')); jwk = { ...await exportJWK(publicKey), kid: 'test-key', use: 'sig', alg: 'RS256' } })
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
const session = () => ({ accessToken: 'fixture-access-token', identity: { sub: 'aisha', name: 'Aisha' }, expiresAt: Date.now()+60000 })
const permit = changes => ({ allowed: true, sub: 'aisha', client_id: clientId, resource_id: 'research-vault', scope: 'read', expires_at: new Date(Date.now()+60000).toISOString(), ...changes })
const makeClient = (fetchImpl, overrides = {}) => new AdaptiveIamClient({ issuer, clientId, clientSecret: 'fixture-client-secret', redirectUri: 'https://website.example/callback', fetchImpl, ...overrides })
async function signed({ nonce = 'nonce-fixture', aud = clientId, iss = issuer, exp = Math.floor(Date.now()/1000)+600 } = {}) {
  return new SignJWT({ nonce }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setSubject('aisha').setIssuer(iss).setAudience(aud).setIssuedAt().setExpirationTime(exp).sign(privateKey)
}
function provider(idToken, overrides = {}) {
  return async (url, options) => {
    const path = new URL(url).pathname
    if (path.includes('openid-configuration')) return json(metadata)
    if (path === '/oauth/token') { overrides.observe?.(options); return json({ access_token: 'fixture-access-token', token_type: 'Bearer', expires_in: 600, scope: 'openid profile iam:permissions', id_token: idToken, ...overrides.token }) }
    if (path === '/oauth/jwks') return json({ keys: [jwk] })
    if (path === '/oauth/userinfo') return json({ sub: 'aisha', ...overrides.identity })
    throw new Error('Unexpected endpoint')
  }
}

test('HTTPS is mandatory; loopback HTTP needs explicit opt-in', () => {
  assert.throws(() => makeClient(() => {}, { issuer: 'http://evil.example' }), IamError)
  assert.throws(() => makeClient(() => {}, { issuer: 'http://127.0.0.1:8000' }), IamError)
  assert.doesNotThrow(() => makeClient(() => {}, { issuer: 'http://127.0.0.1:8000', redirectUri: 'http://127.0.0.1:3001/callback', allowLocalHttp: true }))
})
test('login URL includes S256 PKCE, state and nonce and excludes client secret', async () => {
  const flow = loginTransaction(); const client = makeClient(async () => json(metadata))
  const url = new URL(await client.authorizationUrl(flow))
  assert.equal(url.searchParams.get('state'), flow.state); assert.equal(url.searchParams.get('nonce'), flow.nonce)
  assert.equal(url.searchParams.get('code_challenge'), createHash('sha256').update(flow.verifier).digest('base64url'))
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256'); assert.equal(url.searchParams.has('client_secret'), false)
  assert(safeEqual(flow.state, flow.state)); assert(!safeEqual(flow.state, 'wrong'))
})
test('OIDC signature, issuer/audience/nonce and userinfo subject are checked before session', async () => {
  const token = await signed(); let form
  const client = makeClient(provider(token, { observe: options => { form = new URLSearchParams(options.body); assert.equal(options.redirect, 'error') } }))
  const result = await client.exchangeCode({ code: 'fixture-code', verifier: 'v'.repeat(43), nonce: 'nonce-fixture' })
  assert.equal(result.identity.sub, 'aisha'); assert.equal(form.get('code_verifier'), 'v'.repeat(43)); assert.equal(form.get('client_secret'), 'fixture-client-secret')
  assert(result.expiresAt > Date.now())
})
test('wrong nonce, issuer, audience and expired ID tokens fail', async () => {
  for (const options of [{ nonce: 'wrong-nonce' }, { aud: 'other-client' }, { iss: 'https://wrong.example' }, { exp: Math.floor(Date.now()/1000)-1 }]) {
    const client = makeClient(provider(await signed(options)))
    await assert.rejects(client.exchangeCode({ code: 'fixture-code', verifier: 'v'.repeat(43), nonce: 'nonce-fixture' }), error => error instanceof IamError && error.status === 401)
  }
})
test('tampered signature and mismatched userinfo subject fail', async () => {
  const token = await signed(); const parts = token.split('.'); parts[2] = `${parts[2][0] === 'a' ? 'b' : 'a'}${parts[2].slice(1)}`
  await assert.rejects(makeClient(provider(parts.join('.'))).exchangeCode({ code: 'x', verifier: 'v'.repeat(43), nonce: 'nonce-fixture' }), IamError)
  await assert.rejects(makeClient(provider(token, { identity: { sub: 'other' } })).exchangeCode({ code: 'x', verifier: 'v'.repeat(43), nonce: 'nonce-fixture' }), error => error.code === 'subject_mismatch')
})
test('valid resource grant must match subject, resource, scope and expiry', async () => {
  let calls = 0
  const client = makeClient(async (_url, options) => { calls++; assert.equal(options.headers.Authorization, 'Bearer fixture-access-token'); return json(permit()) })
  assert.equal((await client.permission(session(), 'research-vault')).scope, 'read')
  assert.equal((await client.permission(session(), 'research-vault')).resourceId, 'research-vault'); assert.equal(calls, 2)
  for (const changes of [{ allowed: false }, { allowed: 'true' }, { sub: 'other' }, { client_id: 'other-client' }, { resource_id: 'other' }, { scope: 'admin' }, { expires_at: new Date(Date.now()-1000).toISOString() }]) {
    await assert.rejects(makeClient(async () => json(permit(changes))).permission(session(), 'research-vault'), IamError)
  }
})
test('expired website session and missing token are rejected locally', async () => {
  const client = makeClient(async () => { throw new Error('must not call') })
  await assert.rejects(client.permission({ ...session(), expiresAt: Date.now()-1 }, 'research-vault'), error => error.status === 401)
  await assert.rejects(client.permission({ ...session(), accessToken: '' }, 'research-vault'), error => error.status === 401)
})
test('HTTP401, malformed JSON, arrays and oversized responses never allow access', async () => {
  for (const response of [json({}, 401), new Response('{'), json([]), json({ padding: 'x'.repeat(70000) })]) {
    await assert.rejects(makeClient(async () => response).permission(session(), 'research-vault'), IamError)
  }
})
test('request timeout fails closed', async () => {
  const fetchImpl = (_url, options) => new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('fixture timeout'))))
  await assert.rejects(makeClient(fetchImpl, { timeoutMs: 10 }).permission(session(), 'research-vault'), error => error.code === 'iam_timeout')
})
test('discovery cannot move token or key requests to another origin', async () => {
  const client = makeClient(async () => json({ ...metadata, token_endpoint: 'https://attacker.example/token' }))
  await assert.rejects(client.discover(), error => error.code === 'issuer_endpoint_mismatch')
})
test('logout revocation sends site-bound token and confidential secret server-side', async () => {
  let form
  const client = makeClient(async (url, options) => {
    if (new URL(url).pathname.includes('openid-configuration')) return json(metadata)
    assert.equal(new URL(url).pathname, '/oauth/revoke'); form = new URLSearchParams(options.body)
    return json({})
  })
  await client.revoke(session())
  assert.equal(form.get('token'), 'fixture-access-token'); assert.equal(form.get('client_id'), clientId)
  assert.equal(form.get('client_secret'), 'fixture-client-secret')
})
