import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from './api'
import type { ActiveSession, Identity, SecurityStatus } from './api'
import { Badge, Empty, formatDate, Icon, PageTitle, PanelTitle } from './components'
import { passkeysAvailable, registerPasskey, usePasskey } from './webauthn'

type Enrollment = { enrollment_id: string; secret: string; otpauth_uri: string; expires_at: string }

export function SecurityView({ token, user, onLogin, onSessionRevoked, onChanged }: { token: string | null; user: Identity | null; onLogin: () => void; onSessionRevoked: () => void; onChanged: () => Promise<void> }) {
  const [security, setSecurity] = useState<SecurityStatus | null>(null)
  const [sessions, setSessions] = useState<ActiveSession[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const busyRef = useRef(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [password, setPassword] = useState('')
  const [proof, setProof] = useState('')
  const [proofMethod, setProofMethod] = useState<'totp' | 'recovery'>('totp')
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null)
  const [code, setCode] = useState('')
  const [label, setLabel] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([])
  const [confirmRemoval, setConfirmRemoval] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const load = useCallback(async () => {
    if (!token) return
    const [status, sessionData] = await Promise.all([api<SecurityStatus>('/auth/security', token), api<{ items: ActiveSession[] }>('/auth/sessions', token)])
    setSecurity(status); setSessions(sessionData.items)
    if (!status.totp_enabled && status.recovery_codes_remaining > 0) setProofMethod('recovery')
  }, [token])
  useEffect(() => {
    let active = true
    if (!token) { setLoading(false); return }
    setLoading(true)
    load().catch(failure => { if (active) setError(failure instanceof Error ? failure.message : 'Security settings could not be loaded.') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [load, token])
  const action = async (key: string, operation: () => Promise<string | null>) => {
    if (!token || busyRef.current) return
    busyRef.current = true; setBusy(key); setError(''); setMessage('')
    try {
      const confirmation = await operation()
      if (confirmation) {
        setMessage(confirmation)
        try { await load(); await onChanged() }
        catch (failure) { setError(`The action completed, but refreshed state could not be loaded. ${failure instanceof Error ? failure.message : 'Refresh before retrying.'}`) }
      }
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        // A wrong factor also returns 401. Keep the session unless its own lookup fails.
        try { await api('/auth/me', token) } catch (lookup) { if (lookup instanceof ApiError && lookup.status === 401) onSessionRevoked() }
      }
      setError(failure instanceof Error ? failure.message : 'This security action could not be completed.')
    } finally { busyRef.current = false; setBusy(null) }
  }
  const reauth = () => action('reauth', async () => {
    await api('/auth/reauth', token, { password, ...(proof ? proofMethod === 'recovery' ? { recovery_code: proof } : { code: proof } : {}) })
    setPassword(''); setProof(''); return 'Your identity was verified. The server now permits eligible security changes.'
  })
  const verifyPasskey = () => action('verify-passkey', async () => {
    const result = await usePasskey('step-up', token!)
    if (result.status !== 'verified') throw new Error('The server did not confirm passkey verification.')
    return 'Passkey verification completed for this session.'
  })
  const enroll = () => action('enroll', async () => {
    setEnrollment(await api<Enrollment>('/auth/totp/enroll', token, {})); setCode('')
    return 'Authenticator setup started. Add the secret to your authenticator, then confirm a current code.'
  })
  const confirm = () => action('confirm', async () => {
    if (!enrollment) return null
    const result = await api<{ status: string; recovery_codes: string[] }>('/auth/totp/confirm', token, { enrollment_id: enrollment.enrollment_id, code })
    if (result.status !== 'enabled') throw new Error('The server did not confirm authenticator enrollment.')
    setEnrollment(null); setCode(''); setRecoveryCodes(result.recovery_codes)
    return 'Your authenticator is enabled. Save the recovery codes displayed below.'
  })
  const remove = (id: string) => action(`remove-${id}`, async () => {
    await api(id === 'totp' ? '/auth/totp' : `/auth/passkeys/${encodeURIComponent(id)}`, token, undefined, 'DELETE')
    setConfirmRemoval(null); if (id === 'totp') setRecoveryCodes([])
    return id === 'totp' ? 'Your authenticator was removed. Other sessions may have been revoked by policy.' : 'The passkey was removed. Other sessions may have been revoked by policy.'
  })
  const recovery = () => action('recovery', async () => {
    const result = await api<{ recovery_codes: string[] }>('/auth/recovery/regenerate', token, {})
    setRecoveryCodes(result.recovery_codes); return 'New recovery codes were issued. Previous codes no longer work.'
  })
  const addPasskey = () => action('passkey', async () => {
    if (label.trim().length < 2) throw new Error('Use at least two characters for the passkey label.')
    await registerPasskey(token!, label.trim()); setLabel(''); return 'Your passkey was verified and enrolled by the server.'
  })
  const revoke = (session: ActiveSession) => action(`revoke-${session.id}`, async () => {
    const result = await api<{ status: string }>(`/auth/sessions/${encodeURIComponent(session.id)}/revoke`, token, {})
    if (result.status !== 'revoked') throw new Error('The server did not confirm session revocation.')
    if (session.current) { onSessionRevoked(); return null }
    return 'The selected session was revoked. It can no longer authenticate requests.'
  })
  const downloadCodes = () => {
    const file = new Blob([`Adaptive IAM recovery codes\nAccount: ${user?.name}\nEach code works once. Store securely.\n\n${recoveryCodes.join('\n')}\n`], { type: 'text/plain' })
    const url = URL.createObjectURL(file); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'adaptive-iam-recovery-codes.txt'; anchor.click(); URL.revokeObjectURL(url)
  }
  const factorReady = security?.fresh_verification === true
  const enrollmentReady = factorReady || security?.enrollment_ready === true
  const passkeyReady = passkeysAvailable() && security?.passkeys_available === true
  return <>
    <PageTitle title="Keep identity in your hands." description="Manage real authenticators, passkeys, recovery codes, and browser sessions." action={user && <button className="button secondary" disabled={!!busy || loading} onClick={() => action('refresh', async () => { await load(); return null })}><Icon name="refresh" size={16} />Refresh security</button>} />
    {!user || !token ? <section className="panel"><Empty icon="shield" title="Sign in to protect your identity." action={<button className="button primary" onClick={onLogin}>Sign in</button>}>Enroll an authenticator or a browser passkey, then inspect the sessions attached to your account.</Empty></section> : <>
      {error && <div className="feedback feedback-error" role="alert"><Icon name="signal" size={18} /><span>{error}</span></div>}{message && <div className="feedback feedback-success" role="status"><Icon name="check" size={18} /><span>{message}</span></div>}
      {loading ? <section className="panel"><Empty icon="lock" title="Loading your security settings…">Checking the server's factor and session state.</Empty></section> : !security ? <section className="panel"><Empty icon="signal" title="Security settings are unavailable." action={<button className="button secondary" onClick={() => action('refresh', async () => { await load(); return null })}>Retry</button>}>The API must return your security state before enrollment or changes are available.</Empty></section> : <>
        <section className="panel security-verification"><PanelTitle title={security.step_up_required ? 'Verify this session to continue' : 'Verification for sensitive changes'} description="Recent factor verification protects enrollment, credential rotation, and organization changes." action={<Badge status={factorReady ? 'active' : 'medium'}>{factorReady ? 'Recently verified' : enrollmentReady ? 'First enrollment ready' : 'Verification required'}</Badge>} />
          {(!security.passkeys.length || security.totp_enabled || security.recovery_codes_remaining > 0) && <form className="security-proof-form" onSubmit={event => { event.preventDefault(); void reauth() }}><label className="field"><span>Current password</span><input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required /></label>{(security.totp_enabled || security.recovery_codes_remaining > 0) && <><label className="field"><span>Verification method</span><select value={proofMethod} onChange={event => { setProofMethod(event.target.value as 'totp' | 'recovery'); setProof('') }}>{security.totp_enabled && <option value="totp">Authenticator code</option>}{security.recovery_codes_remaining > 0 && <option value="recovery">Recovery code</option>}</select></label><label className="field"><span>{proofMethod === 'totp' ? 'Current authenticator code' : 'Unused recovery code'}</span><input autoComplete="one-time-code" inputMode={proofMethod === 'totp' ? 'numeric' : 'text'} pattern={proofMethod === 'totp' ? '[0-9]{6}' : undefined} value={proof} onChange={event => setProof(event.target.value)} required /></label></>}<button className="button primary" type="submit" disabled={!!busy}>{busy === 'reauth' ? 'Verifying…' : 'Verify identity'}</button></form>}
          {security.passkeys.length > 0 && <button className="button secondary" onClick={verifyPasskey} disabled={!!busy || !passkeyReady}><Icon name="lock" size={16} />{busy === 'verify-passkey' ? 'Waiting for your passkey…' : 'Verify with a passkey'}</button>}<p className="security-note">{security.totp_enabled ? 'Use an actual authenticator or recovery code. Demo codes do not verify enrolled factors.' : security.passkeys.length ? 'Use your passkey for sensitive changes. A password alone does not replace an enrolled factor.' : 'Confirm your password to enroll your first factor. Later sensitive changes require an enrolled factor.'}</p>
        </section>
        {recoveryCodes.length > 0 && <section className="panel recovery-panel"><PanelTitle title="Save your recovery codes now" description="These codes are shown once and each works once. Keep them somewhere secure outside this browser." action={<button className="button secondary" onClick={downloadCodes}><Icon name="download" size={16} />Download codes</button>} /><div className="recovery-code-grid">{recoveryCodes.map(item => <code key={item}>{item}</code>)}</div><button className="text-button" onClick={() => setRecoveryCodes([])}>I saved my codes · dismiss</button></section>}
        <section className="panel security-methods"><PanelTitle title="Your verification methods" description="A real factor continues to be required at sign-in after enrollment." /><div className="security-method-row"><span className="security-method-icon"><Icon name="risk" size={24} /></span><div className="security-method-content"><h3>Authenticator app</h3><p>Time-based codes from your authenticator. {security.totp_enabled ? `${security.recovery_codes_remaining} recovery codes remain.` : 'Add the secret manually to a TOTP authenticator.'}</p><Badge status={security.totp_enabled ? 'active' : 'neutral'}>{security.totp_enabled ? 'Enabled' : 'Not enrolled'}</Badge></div><div className="security-method-actions">{security.totp_enabled ? <><button className="button secondary" disabled={!!busy || !factorReady} onClick={recovery}>Replace recovery codes</button><button className="text-button danger-text" disabled={!!busy || !factorReady} onClick={() => setConfirmRemoval('totp')}>Remove authenticator</button></> : <button className="button secondary" disabled={!!busy || !enrollmentReady} onClick={enroll}>{busy === 'enroll' ? 'Preparing…' : 'Set up authenticator'}</button>}</div></div>
          {enrollment && <form className="totp-setup" onSubmit={event => { event.preventDefault(); void confirm() }}><div className="setup-step"><span>01</span><div><h3>Add to your authenticator</h3><p>Choose a time-based, six-digit account and paste this secret. Setup expires {formatDate(enrollment.expires_at)}.</p><label className="field"><span>Authenticator secret · keep private</span><input value={enrollment.secret} readOnly onFocus={event => event.target.select()} /></label><details><summary>Show authenticator setup URI</summary><code className="secret-uri">{enrollment.otpauth_uri}</code></details></div></div><div className="setup-step"><span>02</span><div><h3>Confirm a current code</h3><label className="field"><span>Six-digit authenticator code</span><input autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" minLength={6} maxLength={6} value={code} onChange={event => setCode(event.target.value)} required /></label><div className="inline-actions"><button className="button primary" type="submit" disabled={!!busy}>{busy === 'confirm' ? 'Confirming…' : 'Enable authenticator'}</button><button className="button secondary" type="button" disabled={!!busy} onClick={() => { setEnrollment(null); setCode('') }}>Cancel setup</button></div></div></div></form>}
          <div className="security-method-row"><span className="security-method-icon"><Icon name="lock" size={24} /></span><div className="security-method-content"><h3>Passkeys</h3><p>Use your device's authenticator. Enrollment and sign-in are verified on the server.</p><Badge status={security.passkeys.length ? 'active' : 'neutral'}>{security.passkeys.length} enrolled</Badge></div></div>
          {security.passkeys.map(passkey => <div className="passkey-row" key={passkey.id}><Icon name="shield" size={18} /><div><strong>{passkey.label}</strong><small>Enrolled {formatDate(passkey.created_at)} · {passkey.last_used_at ? `Last used ${formatDate(passkey.last_used_at)}` : 'Not used yet'}</small></div><button className="text-button danger-text" disabled={!!busy || !factorReady} onClick={() => setConfirmRemoval(passkey.id)}>Remove</button></div>)}
          <form className="passkey-enroll-form" onSubmit={event => { event.preventDefault(); void addPasskey() }}><label className="field"><span>Passkey label</span><input placeholder="My laptop" minLength={2} maxLength={80} required value={label} onChange={event => setLabel(event.target.value)} /></label><button className="button secondary" type="submit" disabled={!!busy || !enrollmentReady || !passkeyReady}><Icon name="plus" size={16} />{busy === 'passkey' ? 'Waiting for your device…' : 'Enroll a passkey'}</button></form>{!security.passkeys_available && <p className="security-note">The server passkey verifier is unavailable. Run the configured Docker API or inspect its dependency setup.</p>}{!passkeysAvailable() && <p className="security-note">This browser cannot use passkeys here. Open HTTPS or localhost in a browser that supports WebAuthn.</p>}
          {confirmRemoval && <div className="factor-removal" role="alert"><div><strong>Remove {confirmRemoval === 'totp' ? 'the authenticator' : 'this passkey'}?</strong><p>You will no longer be able to use this factor. Removing the last factor may revoke your other sessions.</p></div><button className="button secondary" disabled={!!busy} onClick={() => setConfirmRemoval(null)}>Keep factor</button><button className="button primary" disabled={!!busy} onClick={() => remove(confirmRemoval)}>Confirm removal</button></div>}
        </section>
        <section className="panel security-sessions"><PanelTitle title="Active sessions" description="Revoke a session to immediately remove its console access." /><div className="table-wrap"><table><thead><tr><th>Session</th><th>Verification</th><th>Last seen</th><th>Expires</th><th>Action</th></tr></thead><tbody>{sessions.map(session => <tr key={session.id}><td><strong>{session.current ? 'This browser tab' : 'Another session'}</strong><small>{session.id.slice(0, 12)} · Created {formatDate(session.created_at)}</small></td><td><Badge status={session.step_up_required ? 'medium' : 'neutral'}>{session.step_up_required ? 'Step-up required' : (session.verification_method || 'unverified').replaceAll('_', ' ')}</Badge></td><td>{formatDate(session.last_seen_at)}</td><td>{formatDate(session.expires_at)}</td><td><button className="text-button danger-text" disabled={!!busy} onClick={() => revoke(session)}>{busy === `revoke-${session.id}` ? 'Revoking…' : session.current ? 'Revoke and sign out' : 'Revoke session'}</button></td></tr>)}</tbody></table></div>{!sessions.length && <Empty icon="clock" title="No active sessions returned.">Refresh security settings to confirm your latest session state.</Empty>}</section>
        <p className="security-origin"><Icon name="shield" size={15} /><span>Passkey relying party: <code>{security.rp_id}</code> · Origin: <code>{security.origin}</code></span></p>
      </>}
    </>}
  </>
}
