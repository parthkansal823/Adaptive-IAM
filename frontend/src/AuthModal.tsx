import { useEffect, useRef, useState } from 'react'
import { api } from './api'
import type { AuthResult, Bootstrap } from './api'
import { actionLabel, Badge, Brand, Icon, percent, presets } from './components'

export function AuthModal({ bootstrap, onClose, onAuthenticated }: { bootstrap: Bootstrap | null; onClose: () => void; onAuthenticated: (result: AuthResult) => void }) {
  const [identity, setIdentity] = useState(bootstrap?.users[0]?.id || '')
  const [password, setPassword] = useState(bootstrap?.demo_mode ? bootstrap.users[0]?.password || 'Demo@123!' : '')
  const [preset, setPreset] = useState('usual')
  const [result, setResult] = useState<AuthResult | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const dialogRef = useRef<HTMLDivElement>(null)
  const busyRef = useRef(busy)
  busyRef.current = busy
  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null
    dialogRef.current?.querySelector<HTMLElement>('select, input')?.focus()
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busyRef.current) onClose()
      if (event.key !== 'Tab') return
      const elements = [...(dialogRef.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), a[href]') || [])]
      if (event.shiftKey && document.activeElement === elements[0]) { event.preventDefault(); elements.at(-1)?.focus() }
      else if (!event.shiftKey && document.activeElement === elements.at(-1)) { event.preventDefault(); elements[0]?.focus() }
    }
    document.addEventListener('keydown', handleKey)
    return () => { document.removeEventListener('keydown', handleKey); previousFocus?.focus() }
  }, [onClose])
  const login = async () => {
    setBusy(true); setError('')
    try {
      const auth = await api<AuthResult>('/auth/login', null, { user_id: identity || bootstrap?.users[0]?.id, password, context: presets.find(item => item.id === preset)!.context })
      setResult(auth)
      if (auth.status === 'authenticated') onAuthenticated(auth)
    } catch (failure) { setError(failure instanceof Error ? failure.message : 'Sign-in failed. Retry this action.') }
    finally { setBusy(false) }
  }
  const verify = async () => {
    setBusy(true); setError('')
    try {
      const auth = await api<AuthResult>('/auth/verify', null, { challenge_id: result?.challenge_id, code })
      if (auth.status === 'authenticated') onAuthenticated(auth)
      else { setResult(auth); setError('Verification did not authenticate this session.') }
    } catch (failure) { setError(failure instanceof Error ? failure.message : 'Verification failed. Retry with the correct code.') }
    finally { setBusy(false) }
  }
  return <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose() }}><div className="auth-dialog" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="auth-heading"><div className="auth-top"><Brand compact /><button className="icon-button" aria-label="Close sign-in" onClick={onClose} disabled={busy}><Icon name="close" /></button></div>
    <h2 id="auth-heading">{result?.status === 'mfa_required' ? 'One more identity check.' : result?.status === 'blocked' ? 'This context was blocked.' : 'Connect your identity.'}</h2><p className="auth-description">{result?.status === 'mfa_required' ? 'The risk policy requires a verification code before a session is issued.' : result?.status === 'blocked' ? 'No session was created. Try a different context to inspect the adaptive policy.' : 'Start a session to request access, cast reviews, and inspect the ledger.'}</p>
    {bootstrap?.demo_mode && <div className="demo-note"><Icon name="research" size={19} /><div><strong>Local research demo</strong><span>Seeded identities use <code>Demo@123!</code>. Demo verification codes are visible here.</span></div></div>}
    {error && <div className="auth-error" role="alert">{error}</div>}
    {result?.status === 'mfa_required' ? <form onSubmit={event => { event.preventDefault(); void verify() }}><div className="auth-risk-summary"><Badge status={result.risk.tier}>{result.risk.tier} risk</Badge><strong>{percent(result.risk.score)}</strong><span>{actionLabel(result.risk.action)}</span></div>{result.demo_code && <div className="demo-code"><span>Demo verification code</span><strong>{result.demo_code}</strong><button className="text-button" type="button" onClick={() => setCode(result.demo_code!)}>Use code</button></div>}<label className="field"><span>Verification code</span><input autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" minLength={6} maxLength={6} value={code} onChange={event => setCode(event.target.value)} required /></label><button className="button primary auth-submit" disabled={busy} type="submit">{busy ? 'Verifying…' : 'Verify and sign in'}<Icon name="arrow" size={17} /></button><button className="text-button auth-back" onClick={() => { setResult(null); setCode(''); setError('') }} type="button">Choose another scenario</button></form> : <form onSubmit={event => { event.preventDefault(); void login() }}>
      {result?.status === 'blocked' && <div className="auth-risk-summary"><Badge status="high">High risk</Badge><strong>{percent(result.risk.score)}</strong><span>No session issued</span></div>}
      <label className="field"><span>Demo identity</span><select value={identity || bootstrap?.users[0]?.id || ''} onChange={event => setIdentity(event.target.value)} required disabled={!bootstrap}>{bootstrap?.users.map(user => <option key={user.id} value={user.id}>{user.name} · {user.department}</option>)}</select></label>
      <label className="field"><span>Password</span><input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
      <label className="field"><span>Sign-in scenario</span><select value={preset} onChange={event => { setPreset(event.target.value); setResult(null) }}>{presets.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select><small>{presets.find(item => item.id === preset)?.description}</small></label>
      <button className="button primary auth-submit" type="submit" disabled={busy || !bootstrap}>{busy ? 'Checking identity…' : result?.status === 'blocked' ? 'Try this context' : 'Sign in'}<Icon name="arrow" size={17} /></button>
    </form>}
    <p className="auth-session-note"><Icon name="lock" size={14} />Your session token stays in this browser tab.</p>
  </div></div>
}
