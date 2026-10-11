import { api } from './api'
import type { AuthResult, Passkey } from './api'

type BinaryOptions = Record<string, unknown> & { challenge: string; user?: { id: string; name: string; displayName: string }; excludeCredentials?: { id: string; type: 'public-key'; transports?: AuthenticatorTransport[] }[]; allowCredentials?: { id: string; type: 'public-key'; transports?: AuthenticatorTransport[] }[] }
type Challenge = { challenge_id: string; options: BinaryOptions }

function decode(value: string): ArrayBuffer {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(binary, character => character.charCodeAt(0)).buffer
}

function encode(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value)
  let binary = ''
  bytes.forEach(byte => { binary += String.fromCharCode(byte) })
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function passkeysAvailable(): boolean {
  return window.isSecureContext && typeof window.PublicKeyCredential !== 'undefined' && !!navigator.credentials
}

function serialize(credential: Credential | null) {
  if (!(credential instanceof PublicKeyCredential)) throw new Error('The browser did not return a passkey. Retry with a supported device.')
  const response = credential.response
  const common = { id: credential.id, rawId: encode(credential.rawId), type: credential.type, clientExtensionResults: credential.getClientExtensionResults() }
  if (response instanceof AuthenticatorAttestationResponse) return { ...common, response: { clientDataJSON: encode(response.clientDataJSON), attestationObject: encode(response.attestationObject), transports: response.getTransports?.() || [] } }
  if (response instanceof AuthenticatorAssertionResponse) return { ...common, response: { clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode(response.authenticatorData), signature: encode(response.signature), userHandle: response.userHandle ? encode(response.userHandle) : null } }
  throw new Error('The browser returned an unsupported passkey response.')
}

function explain(error: unknown): never {
  if (error instanceof DOMException && error.name === 'NotAllowedError') throw new Error('The passkey operation was cancelled, timed out, or no matching passkey was available. Retry when ready.')
  if (error instanceof DOMException && error.name === 'InvalidStateError') throw new Error('This passkey is already enrolled. Use it to sign in or choose another authenticator.')
  throw error
}

export async function registerPasskey(token: string, label: string): Promise<Passkey> {
  if (!passkeysAvailable()) throw new Error('Passkeys require a supported browser on HTTPS or localhost.')
  const challenge = await api<Challenge>('/auth/passkeys/register/options', token, { label })
  const raw = challenge.options
  const options = { ...raw, challenge: decode(raw.challenge), ...(raw.user ? { user: { ...raw.user, id: decode(raw.user.id) } } : {}), ...(raw.excludeCredentials ? { excludeCredentials: raw.excludeCredentials.map(item => ({ ...item, id: decode(item.id) })) } : {}) } as PublicKeyCredentialCreationOptions
  try {
    const credential = await navigator.credentials.create({ publicKey: options })
    return await api<Passkey>('/auth/passkeys/register/verify', token, { challenge_id: challenge.challenge_id, credential: serialize(credential) })
  } catch (error) { return explain(error) }
}

export async function usePasskey(mode: 'login', token: null, userId: string): Promise<AuthResult>
export async function usePasskey(mode: 'step-up', token: string, userId?: string): Promise<{ status: string }>
export async function usePasskey(mode: 'login' | 'step-up', token: string | null, userId?: string): Promise<AuthResult | { status: string }> {
  if (!passkeysAvailable()) throw new Error('Passkeys require a supported browser on HTTPS or localhost.')
  const challenge = await api<Challenge>(`/auth/passkeys/${mode}/options`, token, mode === 'login' ? { user_id: userId } : {})
  const raw = challenge.options
  const options = { ...raw, challenge: decode(raw.challenge), ...(raw.allowCredentials ? { allowCredentials: raw.allowCredentials.map(item => ({ ...item, id: decode(item.id) })) } : {}) } as PublicKeyCredentialRequestOptions
  try {
    const credential = await navigator.credentials.get({ publicKey: options })
    return await api<AuthResult | { status: string }>(`/auth/passkeys/${mode}/verify`, token, { challenge_id: challenge.challenge_id, credential: serialize(credential) })
  } catch (error) { return explain(error) }
}
