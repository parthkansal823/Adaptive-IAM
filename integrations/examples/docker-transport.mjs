// Explicit private-network transport for the shipped Docker research example.
// Discovery and signed-token issuer validation still use the public issuer.
export function dockerTransport(issuer, fetchImpl = globalThis.fetch) {
  if (issuer !== 'http://127.0.0.1:8000') throw new Error('Docker example requires the configured loopback issuer')
  return (value, options) => {
    const url = new URL(value)
    if (url.origin !== issuer || url.username || url.password || url.hash || (!url.pathname.startsWith('/oauth/') && url.pathname !== '/.well-known/openid-configuration')) throw new Error('Unexpected Docker backchannel endpoint')
    return fetchImpl(new URL(url.pathname + url.search, 'http://api:8000').href, options)
  }
}
