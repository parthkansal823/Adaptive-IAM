import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose'

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const future = (value, now) => typeof value === 'string' && Number.isFinite(Date.parse(value)) && Date.parse(value) > now
const resourcePattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$/

export class IamError extends Error {
  constructor(code, status = 503) { super(code); this.name = 'IamError'; this.code = code; this.status = status }
}

export function safeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  const a = Buffer.from(left); const b = Buffer.from(right)
  return a.length === b.length && timingSafeEqual(a, b)
}

export function loginTransaction() {
  return { state: randomBytes(32).toString('base64url'), nonce: randomBytes(32).toString('base64url'), verifier: randomBytes(32).toString('base64url') }
}

export function validateUrl(value, allowLocalHttp = false) {
  let url
  try { url = new URL(value) } catch { throw new IamError('invalid_configuration', 500) }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  if (url.username || url.password || url.hash || url.search || (url.protocol !== 'https:' && !(allowLocalHttp && loopback && url.protocol === 'http:'))) {
    throw new IamError('https_required', 500)
  }
  return url
}

export class AdaptiveIamClient {
  constructor({ issuer, clientId, clientSecret = '', redirectUri, scopes = ['openid', 'profile', 'iam:permissions'], allowLocalHttp = false, timeoutMs = 2500, fetchImpl = globalThis.fetch, clock = Date.now }) {
    const url = validateUrl(issuer, allowLocalHttp)
    if (url.pathname !== '/' || !clientId || !Array.isArray(scopes) || !scopes.includes('openid') || !Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new IamError('invalid_configuration', 500)
    this.issuer = url.origin
    this.clientId = clientId; this.clientSecret = clientSecret
    this.redirectUri = validateUrl(redirectUri, allowLocalHttp).href
    this.scopes = [...new Set(scopes)]; this.allowLocalHttp = allowLocalHttp
    this.timeoutMs = timeoutMs; this.fetch = fetchImpl; this.clock = clock; this.metadata = null
  }

  endpoint(value) {
    const url = validateUrl(value, this.allowLocalHttp)
    if (url.origin !== this.issuer) throw new IamError('issuer_endpoint_mismatch')
    return url.href
  }

  async request(url, { method = 'GET', token, form } = {}) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)
    try {
      const headers = { Accept: 'application/json' }
      if (token) {
        if (typeof token !== 'string' || token.length > 8192 || /[\s\x00-\x1f]/.test(token)) throw new IamError('invalid_session', 401)
        headers.Authorization = `Bearer ${token}`
      }
      if (form) headers['Content-Type'] = 'application/x-www-form-urlencoded'
      const response = await this.fetch(this.endpoint(url), { method, headers, body: form?.toString(), signal: controller.signal, redirect: 'error' })
      if (response.status !== 200) throw new IamError(response.status === 401 ? 'invalid_session' : response.status === 403 ? 'access_denied' : 'iam_unavailable', [401, 403].includes(response.status) ? response.status : 503)
      if (!response.body?.getReader) throw new IamError('invalid_iam_response')
      const reader = response.body.getReader(); const chunks = []; let size = 0
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        size += value.length
        if (size > 65536) { await reader.cancel(); throw new IamError('iam_response_too_large') }
        chunks.push(value)
      }
      const bytes = new Uint8Array(size); let offset = 0
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
      const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
      if (!object(body)) throw new IamError('invalid_iam_response')
      return body
    } catch (error) {
      if (error instanceof IamError) throw error
      throw new IamError(controller.signal.aborted ? 'iam_timeout' : 'invalid_iam_response')
    } finally { clearTimeout(timer) }
  }

  async discover() {
    if (this.metadata) return this.metadata
    const body = await this.request(`${this.issuer}/.well-known/openid-configuration`)
    if (body.issuer !== this.issuer) throw new IamError('issuer_mismatch')
    for (const name of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint']) this.endpoint(body[name])
    if (body.revocation_endpoint) this.endpoint(body.revocation_endpoint)
    this.metadata = body
    return body
  }

  async authorizationUrl({ state, nonce, verifier }) {
    if (![state, nonce].every(value => typeof value === 'string' && value.length >= 8) || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) throw new IamError('invalid_login_transaction', 500)
    const metadata = await this.discover()
    const url = new URL(metadata.authorization_endpoint)
    url.search = new URLSearchParams({ client_id: this.clientId, response_type: 'code', redirect_uri: this.redirectUri, scope: this.scopes.join(' '), state, nonce, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString()
    return url.href
  }

  async exchangeCode({ code, verifier, nonce }) {
    if (typeof code !== 'string' || !code || code.length > 2048 || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || typeof nonce !== 'string' || nonce.length < 8) throw new IamError('invalid_callback', 401)
    const metadata = await this.discover()
    const form = new URLSearchParams({ grant_type: 'authorization_code', code, client_id: this.clientId, redirect_uri: this.redirectUri, code_verifier: verifier })
    if (this.clientSecret) form.set('client_secret', this.clientSecret)
    const token = await this.request(metadata.token_endpoint, { method: 'POST', form })
    if (typeof token.access_token !== 'string' || !token.access_token || typeof token.id_token !== 'string' || token.id_token.length > 16384 || typeof token.token_type !== 'string' || token.token_type.toLowerCase() !== 'bearer' || !Number.isInteger(token.expires_in) || token.expires_in <= 0 || token.expires_in > 86400 || typeof token.scope !== 'string' || !this.scopes.every(scope => token.scope.split(' ').includes(scope))) throw new IamError('invalid_token_response')
    let claims
    try {
      const header = decodeProtectedHeader(token.id_token)
      if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new Error('algorithm')
      const jwks = await this.request(metadata.jwks_uri)
      const matches = Array.isArray(jwks.keys) ? jwks.keys.filter(key => object(key) && key.kid === header.kid && key.kty === 'RSA' && (!key.use || key.use === 'sig') && (!key.alg || key.alg === 'RS256')) : []
      if (matches.length !== 1) throw new Error('key')
      const key = await importJWK(matches[0], 'RS256')
      const verified = await jwtVerify(token.id_token, key, { issuer: this.issuer, audience: this.clientId, algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'nonce'], maxTokenAge: 900, currentDate: new Date(this.clock()), clockTolerance: 0 })
      claims = verified.payload
      if (typeof claims.sub !== 'string' || !claims.sub || !safeEqual(claims.nonce, nonce) || (claims.azp !== undefined && claims.azp !== this.clientId) || (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== this.clientId)) throw new Error('claims')
    } catch (error) {
      if (error instanceof IamError) throw error
      throw new IamError('invalid_id_token', 401)
    }
    const identity = await this.request(metadata.userinfo_endpoint, { token: token.access_token })
    if (identity.sub !== claims.sub) throw new IamError('subject_mismatch')
    const expiresAt = Math.min(this.clock() + token.expires_in * 1000, claims.exp * 1000)
    if (expiresAt <= this.clock()) throw new IamError('invalid_session', 401)
    return { accessToken: token.access_token, identity, expiresAt }
  }

  async permission(session, resourceId) {
    if (!resourcePattern.test(resourceId) || !object(session) || !object(session.identity) || typeof session.identity.sub !== 'string' || !session.identity.sub || typeof session.accessToken !== 'string' || !session.accessToken || !Number.isFinite(session.expiresAt) || session.expiresAt <= this.clock()) throw new IamError('invalid_session', 401)
    const result = await this.request(`${this.issuer}/oauth/permissions/${encodeURIComponent(resourceId)}`, { token: session.accessToken })
    if (result.resource_id !== resourceId || result.sub !== session.identity.sub || result.client_id !== this.clientId || typeof result.allowed !== 'boolean') throw new IamError('permission_response_mismatch')
    if (!result.allowed) throw new IamError('access_denied', 403)
    if (result.scope !== 'read' || !future(result.expires_at, this.clock()) || session.expiresAt <= this.clock()) throw new IamError('grant_expired_or_invalid', 403)
    return { identity: session.identity, resourceId, scope: result.scope, expiresAt: result.expires_at }
  }

  async revoke(session) {
    const metadata = await this.discover()
    if (!metadata.revocation_endpoint) throw new IamError('revocation_unavailable')
    const form = new URLSearchParams({ token: session.accessToken, client_id: this.clientId, token_type_hint: 'access_token' })
    if (this.clientSecret) form.set('client_secret', this.clientSecret)
    await this.request(metadata.revocation_endpoint, { method: 'POST', form })
  }
}
