import { useEffect, useRef, useState } from 'react'
import { api } from './api'
import type { AuthResult, Bootstrap } from './api'
import { Badge, Brand, Icon, percent, presets } from './components'
import { passkeysAvailable, usePasskey } from './webauthn'

export function AuthModal({ bootstrap, onClose, onAuthenticated }: { bootstrap: Bootstrap | null; onClose: () => void; onAuthenticated: (result: AuthResult) => void }) {
  const [identity, setIdentity] = useState(bootstrap?.users[0]?.id || '')
  const [password, setPassword] = useState(bootstrap?.demo_mode ? bootstrap.users[0]?.password || 'Demo@123!' : '')
  const [preset, setPreset] = useState('usual')
  const [result, setResult] = useState<AuthResult | null>(null)
  const [code, setCode] = useState('')
  const [verificationMethod, setVerificationMethod] = useState<'totp' | 'recovery' | 'demo'>('totp')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const dialogRef = useRef<HTMLDivElement>(null)
  const busyRef = useRef(busy)
  busyRef.current = busy
  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    dialogRef.current?.querySelector<HTMLElement>('select, input')?.focus()
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busyRef.current) onClose()
      if (event.key !== 'Tab') return
      const elements = [...(dialogRef.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), a[href]') || [])]
      if (!dialogRef.current?.contains(document.activeElement)) { event.preventDefault(); (event.shiftKey ? elements.at(-1) : elements[0])?.focus() }
      else if (event.shiftKey && document.activeElement === elements[0]) { event.preventDefault(); elements.at(-1)?.focus() }
      else if (!event.shiftKey && document.activeElement === elements.at(-1)) { event.preventDefault(); elements[0]?.focus() }
    }
    document.addEventListener('keydown', handleKey)
    return () => { document.removeEventListener('keydown', handleKey); document.body.style.overflow = previousOverflow; previousFocus?.focus() }
  }, [onClose])
  useEffect(() => {
    if (result?.status === 'mfa_required') dialogRef.current?.querySelector<HTMLInputElement>('input[autocomplete="one-time-code"]')?.focus()
    if (result?.status === 'blocked') dialogRef.current?.querySelector<HTMLElement>('#auth-heading')?.focus()
  }, [result?.status])
  const login = async () => {
    if (busyRef.current) return
    setBusy(true); setError('')
    try {
      const auth = await api<AuthResult>('/auth/login', null, { user_id: identity || bootstrap?.users[0]?.id, password, ...(bootstrap?.demo_mode ? { context: presets.find(item => item.id === preset)!.context } : {}) })
      setResult(auth)
      setVerificationMethod(auth.demo_code ? 'demo' : auth.methods?.includes('totp') ? 'totp' : 'recovery')
      if (auth.status === 'authenticated') onAuthenticated(auth)
    } catch (failure) { setError(failure instanceof Error ? failure.message : 'Sign-in failed. Retry this action.') }
    finally { setBusy(false) }
  }
  const verify = async () => {
    if (busyRef.current) return
    setBusy(true); setError('')
    try {
      const auth = await api<AuthResult>('/auth/verify', null, { challenge_id: result?.challenge_id, ...(verificationMethod === 'recovery' ? { recovery_code: code } : { code }) })
      if (auth.status === 'authenticated') onAuthenticated(auth)
      else { setResult(auth); setError('Verification did not authenticate this session.') }
    } catch (failure) { setError(failure instanceof Error ? failure.message : 'Verification failed. Retry with the correct code.') }
    finally { setBusy(false) }
  }
  const passkeyLogin = async () => {
    if (busyRef.current) return
    setBusy(true); setError('')
    try {
      const auth = await usePasskey('login', null, identity || bootstrap?.users[0]?.id || '')
      setResult(auth)
      if (auth.status === 'authenticated') onAuthenticated(auth)
    } catch (failure) { setError(failure instanceof Error ? failure.message : 'Passkey sign-in could not be completed.') }
    finally { setBusy(false) }
  }
  const codeSupported = !!result?.demo_code || !!result?.methods?.some(method => ['totp', 'recovery'].includes(method))
  return <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose() }}><div className="auth-dialog" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="auth-heading" aria-describedby="auth-description"><div className="auth-top"><Brand compact /><button className="icon-button" aria-label="Close sign-in" onClick={onClose} disabled={busy}><Icon name="close" /></button></div>
    <h2 id="auth-heading" tabIndex={-1}>{result?.status === 'mfa_required' ? 'One more identity check.' : result?.status === 'blocked' ? 'This context was blocked.' : 'Connect your identity.'}</h2><p id="auth-description" className="auth-description">{result?.status === 'mfa_required' ? 'Complete the available factor verification before a session is issued.' : result?.status === 'blocked' ? 'No session was created. Inspect the policy or retry from a trusted device.' : 'Start a session to request access, cast reviews, and inspect the ledger.'}</p>
    {bootstrap?.demo_mode && <div className="demo-note"><Icon name="research" size={19} /><div><strong>Local research demo</strong><span>Seeded identities use <code>Demo@123!</code>. Enrolled factors require a real authenticator or passkey; demo codes apply only before enrollment.</span></div></div>}
    {error && <div className="auth-error" role="alert">{error}</div>}
    {result?.status === 'mfa_required' ? <form onSubmit={event => { event.preventDefault(); if (codeSupported) void verify() }}>
      <div className="auth-risk-summary"><Badge status={result.risk.tier}>{result.risk.tier} risk</Badge><strong>{percent(result.risk.score)}</strong><span>Additional factor required</span></div>
      {result.demo_code && <div className="demo-code"><span>Demo verification code</span><strong>{result.demo_code}</strong><button className="text-button" type="button" onClick={() => setCode(result.demo_code!)}>Use code</button></div>}
      {codeSupported && <>
        {!result.demo_code && <label className="field"><span>Verification method</span><select value={verificationMethod} onChange={event => { setVerificationMethod(event.target.value as 'totp' | 'recovery'); setCode('') }}>{result.methods?.includes('totp') && <option value="totp">Authenticator code</option>}{result.methods?.includes('recovery') && <option value="recovery">Recovery code</option>}</select></label>}
        <label className="field"><span>{verificationMethod === 'recovery' ? 'Unused recovery code' : 'Six-digit verification code'}</span><input autoComplete="one-time-code" inputMode={verificationMethod === 'recovery' ? 'text' : 'numeric'} pattern={verificationMethod === 'recovery' ? undefined : '[0-9]{6}'} minLength={verificationMethod === 'recovery' ? 8 : 6} maxLength={verificationMethod === 'recovery' ? 80 : 6} value={code} onChange={event => setCode(event.target.value)} required /></label>
        <button className="button primary auth-submit" disabled={busy} type="submit">{busy ? 'Verifying…' : 'Verify and sign in'}<Icon name="arrow" size={17} /></button>
      </>}
      {result.methods?.includes('passkey') && <button className={`button ${codeSupported ? 'secondary' : 'primary'} auth-submit`} type="button" disabled={busy || !passkeysAvailable()} onClick={passkeyLogin}><Icon name="lock" size={17} />Use an enrolled passkey</button>}
      {!codeSupported && result.methods?.includes('passkey') && !passkeysAvailable() && <p className="security-note">Open this provider in a browser with WebAuthn support on HTTPS or localhost to use your passkey.</p>}
      <button className="text-button auth-back" onClick={() => { setResult(null); setCode(''); setError('') }} type="button">Return to sign-in</button>
    </form> : <form onSubmit={event => { event.preventDefault(); void login() }}>
      {result?.status === 'blocked' && <div className="auth-risk-summary"><Badge status="high">High risk</Badge><strong>{percent(result.risk.score)}</strong><span>No session issued</span></div>}
      <label className="field"><span>{bootstrap?.demo_mode ? 'Demo identity' : 'Account ID'}</span>{bootstrap?.demo_mode ? <select value={identity || bootstrap?.users[0]?.id || ''} onChange={event => setIdentity(event.target.value)} required disabled={!bootstrap}>{bootstrap?.users.map(user => <option key={user.id} value={user.id}>{user.name} · {user.role.replaceAll('_', ' ')}</option>)}</select> : <input autoComplete="username webauthn" value={identity} onChange={event => setIdentity(event.target.value)} maxLength={80} required />}</label>
      <label className="field"><span>Password</span><input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
      {bootstrap?.demo_mode && <label className="field"><span>Sign-in scenario</span><select value={preset} onChange={event => { setPreset(event.target.value); setResult(null) }}>{presets.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select><small>{presets.find(item => item.id === preset)?.description}</small></label>}
      <button className="button primary auth-submit" type="submit" disabled={busy || !bootstrap}>{busy ? 'Checking identity…' : result?.status === 'blocked' ? 'Try this context' : 'Sign in'}<Icon name="arrow" size={17} /></button>
      <button className="button secondary auth-submit" type="button" disabled={busy || !bootstrap || !passkeysAvailable()} onClick={passkeyLogin}><Icon name="lock" size={17} />Sign in with a passkey</button><p className="security-note">Passkeys use an enrolled authenticator and server-observed context.{bootstrap?.demo_mode ? ' The scenario selector applies to password sign-in.' : ''}</p>
    </form>}
    <p className="auth-session-note"><Icon name="lock" size={14} />Your session token stays in this browser tab.</p>
  </div></div>
}

