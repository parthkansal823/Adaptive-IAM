import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from './api'
import type { AppRegistry, Bootstrap, ConnectedApp, Identity } from './api'
import { Badge, Empty, formatDate, Icon, PageTitle, PanelTitle } from './components'
import { hasExpired, useExpiryClock } from './expiry'

export function AppsView({ token, user, bootstrap, onLogin }: { token: string | null; user: Identity | null; bootstrap: Bootstrap | null; onLogin: () => void }) {
  const [registry, setRegistry] = useState<AppRegistry | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [name, setName] = useState('')
  const [redirects, setRedirects] = useState('')
  const [clientType, setClientType] = useState<'public' | 'confidential'>('public')
  const [scopes, setScopes] = useState(['openid', 'profile', 'iam:permissions'])
  const [resourceIds, setResourceIds] = useState<string[]>([])
  const [created, setCreated] = useState<ConnectedApp | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const permitted = user?.role === 'security_reviewer'
  const load = useCallback(async () => {
    if (!token || !permitted) return
    setBusy('load'); setError('')
    try { setRegistry(await api<AppRegistry>('/apps', token)) }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'Connected apps could not be loaded.') }
    finally { setBusy(null) }
  }, [token, permitted])
  useEffect(() => { void load() }, [load])
  const register = async () => {
    const redirectUris = redirects.split(/\r?\n/).map(uri => uri.trim()).filter(Boolean)
    if (!redirectUris.length || redirectUris.length > 8) { setError('Enter between one and eight exact callback URLs, one per line.'); return }
    setBusy('create'); setError(''); setMessage('')
    try {
      const application = await api<ConnectedApp>('/apps', token, { name, redirect_uris: redirectUris, client_type: clientType, scopes, resource_ids: resourceIds })
      setCreated(application); setFormOpen(false); setName(''); setRedirects(''); setMessage(`${application.name} was registered. Use its client ID in your website.`); await load()
    } catch (failure) { setError(failure instanceof Error ? failure.message : 'The app could not be registered.') }
    finally { setBusy(null) }
  }
  const disable = async (application: ConnectedApp) => {
    setBusy(application.client_id); setError(''); setMessage('')
    try { await api(`/apps/${application.client_id}`, token, undefined, 'DELETE'); setMessage(`${application.name} was disabled and its app tokens were revoked.`); await load() }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'The app could not be disabled.') }
    finally { setBusy(null) }
  }
  const toggle = (items: string[], item: string) => items.includes(item) ? items.filter(value => value !== item) : [...items, item]
  return <>
    <PageTitle title="Applications" description="Manage websites that use Adaptive IAM for sign-in and permission checks." action={<button className="button primary" onClick={() => !user ? onLogin() : permitted && setFormOpen(!formOpen)} disabled={!!user && !permitted}><Icon name={formOpen ? 'close' : 'plus'} size={17} />{formOpen ? 'Close form' : 'Register app'}</button>} />
    {!user || !permitted ? <section className="panel"><Empty icon="shield" title={!user ? 'Sign in to manage integrations.' : 'Application registration belongs to security reviewers.'} action={<button className="button secondary" onClick={onLogin}>{user ? 'Switch demo identity' : 'Sign in'}</button>}>Use the seeded security reviewer identity to register exact callback URLs, scopes, and resource mappings for your website.</Empty></section> : <>
      {error && <div className="feedback feedback-error" role="alert"><Icon name="signal" size={18} /><span>{error}</span></div>}{message && <div className="feedback feedback-success" role="status"><Icon name="check" size={18} /><span>{message}</span></div>}
      {created && <section className="panel credentials-panel"><PanelTitle title={`${created.name} is registered`} description={created.client_secret ? 'Save the client secret now. The API only returns it when the app is created.' : 'Public clients use PKCE without a client secret.'} action={<button className="icon-button" aria-label="Dismiss newly created credentials" onClick={() => setCreated(null)}><Icon name="close" size={17} /></button>} /><div className="app-credentials"><label className="field"><span>Client ID</span><input value={created.client_id} readOnly onFocus={event => event.target.select()} /></label>{created.client_secret && <label className="field"><span>Client secret · keep on your server</span><input value={created.client_secret} readOnly onFocus={event => event.target.select()} /></label>}</div></section>}
      {formOpen && <section className="panel app-registration-panel"><PanelTitle title="Register a website" description="Use exact HTTPS callback URLs, or HTTP on localhost for development." /><form onSubmit={event => { event.preventDefault(); void register() }}><div className="request-form-top"><label className="field"><span>Application name</span><input required minLength={2} maxLength={80} placeholder="Your website name" value={name} onChange={event => setName(event.target.value)} /></label><label className="field"><span>Client type</span><select value={clientType} onChange={event => setClientType(event.target.value as 'public' | 'confidential')}><option value="public">Public · browser or mobile</option><option value="confidential">Confidential · server application</option></select></label></div><label className="field"><span>Callback URLs · one per line</span><textarea rows={3} required placeholder="http://localhost:3000/auth/callback" value={redirects} onChange={event => setRedirects(event.target.value)} /><small>Each authorization redirect must match a registered URL exactly.</small></label><fieldset className="scope-fields"><legend>Identity scopes</legend>{[{ id: 'openid', name: 'Identify the signed-in user', mandatory: true }, { id: 'profile', name: 'Read profile name and department' }, { id: 'iam:permissions', name: "Read resource permissions" }].map(scope => <label key={scope.id}><input type="checkbox" checked={scopes.includes(scope.id)} disabled={scope.mandatory} onChange={() => setScopes(previous => toggle(previous, scope.id))} /><span>{scope.name}<small>{scope.id}{scope.mandatory ? ' · required' : ''}</small></span></label>)}</fieldset><fieldset className="scope-fields"><legend>Resources this app may check</legend>{bootstrap?.resources.map(resource => <label key={resource.id}><input type="checkbox" checked={resourceIds.includes(resource.id)} onChange={() => setResourceIds(previous => toggle(previous, resource.id))} /><span>{resource.name}<small>{resource.description}</small></span></label>)}<p>Resource mappings never create grants. The signed-in user still needs an approved, unexpired access request.</p></fieldset><div className="form-footer"><span><Icon name="shield" size={15} />Registering as {user.name}</span><button className="button primary" type="submit" disabled={busy === 'create'}>{busy === 'create' ? 'Registering…' : 'Register app'}</button></div></form></section>}
      <section className="panel registered-apps"><PanelTitle title="Registered applications" description={`${registry?.items.length ?? 0} applications`} action={<button className="icon-button" aria-label="Refresh connected apps" disabled={busy === 'load'} onClick={load}><Icon name="refresh" size={17} /></button>} />{registry?.items.length ? <div className="app-list">{registry.items.map(application => <details className="registered-app" key={application.client_id}><summary><span className="request-summary-icon"><Icon name="access" size={20} /></span><div className="app-summary"><strong>{application.name}</strong><span>{application.client_type} client · {formatDate(application.created_at)}</span></div><Badge status={application.active ? 'active' : 'expired'}>{application.active ? 'Active' : 'Disabled'}</Badge><Icon name="chevron" size={17} /></summary><div className="app-details"><dl><div><dt>Client ID</dt><dd><code>{application.client_id}</code></dd></div><div><dt>Callback URLs</dt><dd>{application.redirect_uris.map(uri => <code key={uri}>{uri}</code>)}</dd></div><div><dt>Scopes</dt><dd>{application.scopes.join(', ')}</dd></div><div><dt>Mapped resources</dt><dd>{application.resource_ids.map(id => bootstrap?.resources.find(resource => resource.id === id)?.name || id).join(', ') || 'None'}</dd></div></dl>{application.active && <button className="button secondary" onClick={() => disable(application)} disabled={busy === application.client_id}><Icon name="logout" size={16} />{busy === application.client_id ? 'Disabling…' : 'Disable app and revoke tokens'}</button>}</div></details>)}</div> : <Empty icon="access" title={busy === 'load' ? 'Loading applications…' : 'Your first integration starts here.'}>Register a website to get its OAuth client ID and begin the authorization-code flow with PKCE.</Empty>}</section>
      {registry && <section className="panel provider-panel"><PanelTitle title="Provider endpoints" description="Configure these URLs in your website's OAuth or OpenID Connect client." /><dl>{Object.entries(registry).filter(([key, value]) => key !== 'items' && typeof value === 'string').map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd><code>{String(value)}</code></dd></div>)}</dl></section>}
    </>}
  </>
}

export function ConsentView({ requestId, token, user, onLogin, onSecurity }: { requestId: string | null; token: string | null; user: Identity | null; onLogin: () => void; onSecurity: () => void }) {
  const [packet, setPacket] = useState<import('./api').AuthorizationPacket | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [terminal, setTerminal] = useState(false)
  const [decision, setDecision] = useState<boolean | null>(null)
  const [verificationNeeded, setVerificationNeeded] = useState(false)
  const now = useExpiryClock([packet?.expires_at])
  const expired = !!packet && hasExpired(packet.expires_at, now)
  const displayedError = expired ? 'This authorization request expired. Start sign-in again from the website you want to connect.' : error
  useEffect(() => {
    let active = true
    if (!requestId) { setError('No authorization request was supplied. Start sign-in from the website you want to connect.'); setLoading(false); return }
    api<import('./api').AuthorizationPacket>(`/oauth/authorization/${encodeURIComponent(requestId)}`).then(value => { if (active) setPacket(value) }).catch(failure => { if (active) setError(failure instanceof Error ? failure.message : 'The authorization request could not be loaded.') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [requestId])
  const consent = async (approve: boolean) => {
    if (!packet || !token || !user || busy || terminal || hasExpired(packet.expires_at, Date.now())) return
    setBusy(true); setDecision(approve); setError('')
    try {
      const response = await api<{ redirect_to: string }>('/oauth/consent', token, { request_id: packet.request_id, approve })
      const redirect = new URL(response.redirect_to)
      if (redirect.username || redirect.password || redirect.hash || (redirect.protocol !== 'https:' && !(redirect.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(redirect.hostname)))) throw new ApiError('The API returned an invalid callback URL.', 500)
      window.location.assign(redirect.href)
    } catch (failure) {
      if (failure instanceof ApiError && ['step_up_required', 'recent_verification_required'].includes(failure.code || '')) setVerificationNeeded(true)
      if (failure instanceof ApiError && [404, 409].includes(failure.status)) setTerminal(true)
      setError(failure instanceof Error ? failure.message : 'Consent could not be recorded.'); setBusy(false)
    }
  }
  return <>
    <PageTitle title="Authorize application" description="Review the identity information this application is asking to use." />
    {displayedError && <div className="feedback feedback-error" role="alert"><Icon name="signal" size={18} /><span>{displayedError}</span>{verificationNeeded && !expired && <button className="text-button" onClick={onSecurity}>Verify in Security</button>}</div>}
    {loading ? <section className="panel"><Empty icon="access" title="Loading the authorization request…">The provider is checking the app and its requested scopes.</Empty></section> : packet ? <section className="panel consent-panel"><div className="consent-app-mark"><Icon name="access" size={31} /></div><h2>{packet.app.name} requests access</h2><p>{user ? `You are signing in as ${user.name}.` : 'Sign in to choose whether to share your identity with this website.'}</p><div className="consent-scopes"><h3>This app will be allowed to</h3>{packet.scopes.map(scope => <div key={scope}><Icon name="check" size={17} /><span>{scope === 'openid' ? 'Identify your account' : scope === 'profile' ? 'Read your profile name and department' : scope === 'iam:permissions' ? 'Check your resource permissions' : scope}<small>{scope}</small></span></div>)}</div>{packet.resources.length > 0 && <div className="consent-resources"><h3>Mapped resources</h3>{packet.resources.map(resource => <span key={resource.id} className="quiet-tag">{resource.name}</span>)}<p>Only your existing approved grants allow resource access.</p></div>}<div className="consent-expiry"><Icon name="clock" size={15} /><span>This request expires {formatDate(packet.expires_at)}.</span></div>{!user ? <button className="button primary" disabled={terminal || expired} onClick={onLogin}>Sign in to continue <Icon name="arrow" size={17} /></button> : <div className="consent-actions"><button className="button secondary" disabled={busy || terminal || expired} onClick={() => consent(false)}>{busy && decision === false ? 'Returning to app…' : 'Deny connection'}</button><button className="button primary" disabled={busy || terminal || expired} onClick={() => consent(true)}>{busy && decision === true ? 'Returning to app…' : 'Allow and continue'}<Icon name="arrow" size={17} /></button></div>}</section> : null}
  </>
}



