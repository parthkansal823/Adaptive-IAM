import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from './api'
import type { AppRegistry, Bootstrap, CallbackDiagnostic, ConnectedApp, DeveloperWorkspace, Identity, Organization } from './api'
import { Badge, Empty, formatDate, Icon, PageTitle, PanelTitle } from './components'

const availableScopes = [{ id: 'openid', name: 'Identify the account' }, { id: 'profile', name: 'Read profile name and department' }, { id: 'iam:permissions', name: 'Check approved resource permissions' }]
const toggle = (items: string[], item: string) => items.includes(item) ? items.filter(value => value !== item) : [...items, item]

export function DeveloperView({ token, user, bootstrap, onLogin, onSecurity }: { token: string | null; user: Identity | null; bootstrap: Bootstrap | null; onLogin: () => void; onSecurity: () => void }) {
  const [tab, setTab] = useState<'apps' | 'setup' | 'organizations' | 'diagnostics'>('apps')
  const [workspace, setWorkspace] = useState<DeveloperWorkspace | null>(null)
  const [registry, setRegistry] = useState<AppRegistry | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState<string | null>(null)
  const busyRef = useRef(false)
  const [error, setError] = useState('')
  const [verificationNeeded, setVerificationNeeded] = useState(false)
  const [message, setMessage] = useState('')
  const [organizationName, setOrganizationName] = useState('')
  const [organizationId, setOrganizationId] = useState('')
  const [memberId, setMemberId] = useState('')
  const [memberRole, setMemberRole] = useState('member')
  const [step, setStep] = useState(1)
  const [appName, setAppName] = useState('')
  const [clientType, setClientType] = useState<'public' | 'confidential'>('confidential')
  const [callbacks, setCallbacks] = useState('http://127.0.0.1:3001/callback')
  const [scopes, setScopes] = useState(['openid', 'profile', 'iam:permissions'])
  const [resourceIds, setResourceIds] = useState<string[]>([])
  const [credentials, setCredentials] = useState<{ client_id: string; client_secret?: string } | null>(null)
  const [diagnosticUri, setDiagnosticUri] = useState('http://127.0.0.1:3001/callback')
  const [diagnosticApp, setDiagnosticApp] = useState('')
  const [diagnostic, setDiagnostic] = useState<CallbackDiagnostic | null>(null)
  const [callbackChecks, setCallbackChecks] = useState<{ uri: string; result: CallbackDiagnostic }[]>([])
  const callbackSequence = useRef(0)
  const diagnosticSequence = useRef(0)
  const [confirmation, setConfirmation] = useState<{ kind: 'rotate' | 'disable' | 'remove'; id: string } | null>(null)
  const organization = workspace?.organizations.find(item => item.id === organizationId)
  const manageable = workspace?.organizations.filter(item => item.can_manage) || []
  const load = useCallback(async () => {
    if (!token) return
    const [next, endpoints] = await Promise.all([api<DeveloperWorkspace>('/developer/workspace', token), api<AppRegistry>('/apps', token)])
    setWorkspace(next); setRegistry(endpoints)
    setOrganizationId(previous => next.organizations.some(item => item.id === previous) ? previous : next.organizations.find(item => item.can_manage)?.id || next.organizations[0]?.id || '')
  }, [token])
  const fail = (failure: unknown) => {
    setError(failure instanceof Error ? failure.message : 'This developer action could not be completed.')
    if (failure instanceof ApiError && ['recent_verification_required', 'step_up_required'].includes(failure.code || '')) setVerificationNeeded(true)
  }
  useEffect(() => {
    let active = true
    if (!token) { setLoading(false); return }
    setLoading(true)
    load().catch(failure => { if (active) fail(failure) }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [load, token])
  const action = async (key: string, operation: () => Promise<string | null>) => {
    if (!token || busyRef.current) return
    busyRef.current = true; setBusy(key); setError(''); setMessage(''); setVerificationNeeded(false)
    try {
      const confirmation = await operation()
      if (confirmation) {
        setMessage(confirmation)
        try { await load() } catch (failure) { setError(`The action completed. Refresh failed; inspect current state before retrying. ${failure instanceof Error ? failure.message : ''}`) }
      }
    } catch (failure) { fail(failure) }
    finally { busyRef.current = false; setBusy(null) }
  }
  const createOrganization = () => action('organization', async () => {
    if (organizationName.trim().length < 2) throw new Error('Use at least two characters for the organization name.')
    const created = await api<Organization>('/developer/organizations', token, { name: organizationName.trim() })
    setOrganizationId(created.id); setOrganizationName(''); return 'Organization created. You are its administrator.'
  })
  const saveMember = () => action('member', async () => {
    await api(`/developer/organizations/${encodeURIComponent(organizationId)}/members`, token, { user_id: memberId, role: memberRole })
    return 'Organization membership updated. Membership does not create resource access.'
  })
  const checkCallbacks = () => action('callbacks', async () => {
    const sequence = ++callbackSequence.current
    const uris = callbacks.split('\n').map(value => value.trim()).filter(Boolean)
    if (!uris.length || uris.length > 8) throw new Error('Enter between one and eight callback URLs, one per line.')
    if (new Set(uris).size !== uris.length) throw new Error('Each callback URL must be unique. Remove duplicates and check again.')
    const checked = await Promise.all(uris.map(async uri => ({ uri, result: await api<CallbackDiagnostic>('/developer/callback-check', token, { redirect_uri: uri }) })))
    if (sequence !== callbackSequence.current) return null
    setCallbackChecks(checked)
    if (checked.every(item => item.result.valid)) setStep(3)
    else throw new Error('At least one callback is invalid. Review the checks below, edit the URL, and check again.')
    return null
  })
  const register = () => action('register', async () => {
    if (!organization?.can_manage) throw new Error('Select an organization where you can manage applications.')
    const application = await api<ConnectedApp>('/apps', token, { name: appName.trim(), client_type: clientType, organization_id: organizationId, redirect_uris: callbacks.split('\n').map(uri => uri.trim()).filter(Boolean), scopes, resource_ids: resourceIds })
    setCredentials({ client_id: application.client_id, ...(application.client_secret ? { client_secret: application.client_secret } : {}) })
    setStep(1); setAppName(''); setResourceIds([]); setCallbackChecks([]); setTab('apps')
    return 'Application registered. Save its credentials before leaving this page.'
  })
  const mutate = () => {
    if (!confirmation) return
    const { kind, id } = confirmation
    void action(`${kind}-${id}`, async () => {
      if (kind === 'rotate') {
        const result = await api<{ client_id: string; client_secret: string; rotated: boolean; tokens_revoked: boolean }>(`/apps/${encodeURIComponent(id)}/rotate-secret`, token, {})
        if (!result.rotated) throw new Error('The server did not confirm credential rotation.')
        setCredentials({ client_id: result.client_id, client_secret: result.client_secret })
      } else if (kind === 'disable') await api(`/apps/${encodeURIComponent(id)}`, token, undefined, 'DELETE')
      else await api(`/developer/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(id)}`, token, undefined, 'DELETE')
      setConfirmation(null)
      return kind === 'rotate' ? 'Client secret rotated. Previous secrets and app tokens were invalidated.' : kind === 'disable' ? 'Application disabled and its tokens revoked.' : 'Member removed and their organization app tokens revoked.'
    })
  }
  const inspectCallback = () => action('diagnostic', async () => {
    const sequence = ++diagnosticSequence.current
    const result = await api<CallbackDiagnostic>('/developer/callback-check', token, { redirect_uri: diagnosticUri.trim(), ...(diagnosticApp ? { client_id: diagnosticApp } : {}) })
    if (sequence === diagnosticSequence.current) setDiagnostic(result)
    return null
  })
  return <>
    <PageTitle title="Applications" description="Connect a website to Adaptive IAM for sign-in and resource permissions." action={user && tab !== 'setup' && <button className="button primary" disabled={!!busy || loading} onClick={() => setTab('setup')}><Icon name="plus" size={16} />Register application</button>} />
    {!user || !token ? <section className="panel"><Empty icon="access" title="Sign in to manage applications" action={<button className="button primary" onClick={onLogin}>Sign in</button>}>Sign in to inspect your organizations and register a website.</Empty></section> : <>
      {error && <div className="feedback feedback-error" role="alert"><Icon name="signal" size={18} /><span>{error}</span>{verificationNeeded && <button className="text-button" onClick={onSecurity}>Verify in Security</button>}</div>}{message && <div className="feedback feedback-success" role="status"><Icon name="check" size={18} /><span>{message}</span></div>}
      <p className="security-note">Changes require recent factor verification. <button className="text-button" onClick={onSecurity}>Verify in Security</button></p>
      {loading ? <section className="panel"><Empty title="Loading your developer workspace…" icon="access">Reading server-enforced organization membership and registered applications.</Empty></section> : !workspace ? <section className="panel"><Empty title="Workspace unavailable." icon="signal" action={<button className="button secondary" onClick={() => action('refresh', async () => { await load(); return null })}>Retry</button>}>Verify a gated session or reconnect to the API, then retry.</Empty></section> : <>
        <div className="page-tabs" role="group" aria-label="Application workspace">{([{ id: 'apps', label: 'Applications' }, { id: 'setup', label: 'Register' }, { id: 'organizations', label: 'Organizations' }, { id: 'diagnostics', label: 'Connection tools' }] as const).map(item => <button key={item.id} aria-pressed={tab === item.id} className={tab === item.id ? 'selected' : ''} onClick={() => setTab(item.id)}>{item.label}</button>)}</div>
        {credentials && <section className="panel credentials-panel"><PanelTitle title="Save these app credentials" description="The secret is displayed once. Keep confidential client secrets on your website's server." action={<button className="text-button" onClick={() => setCredentials(null)}>Dismiss credentials</button>} /><div className="app-credentials"><label className="field"><span>Client ID</span><input value={credentials.client_id} readOnly onFocus={event => event.target.select()} /></label>{credentials.client_secret && <label className="field"><span>Client secret · keep private</span><input value={credentials.client_secret} readOnly onFocus={event => event.target.select()} /></label>}<p className="security-note">Use authorization code with PKCE S256, state, and nonce. Public browser clients never receive a client secret.</p></div></section>}
        {tab === 'organizations' && <section className="panel organization-panel"><PanelTitle title="Organizations" description="Roles control app administration. Existing research resources remain shared prototype infrastructure." /><div className="organization-layout"><div><label className="field"><span>Selected organization</span><select value={organizationId} onChange={event => { setOrganizationId(event.target.value); setResourceIds([]); setConfirmation(null) }} disabled={!!busy || !workspace.organizations.length}>{workspace.organizations.map(item => <option key={item.id} value={item.id}>{item.name} · {item.role}</option>)}</select></label><form className="organization-create" onSubmit={event => { event.preventDefault(); void createOrganization() }}><label className="field"><span>New organization name</span><input minLength={2} maxLength={80} required value={organizationName} onChange={event => setOrganizationName(event.target.value)} placeholder="My research team" /></label><button className="button secondary" type="submit" disabled={!!busy || !workspace.capabilities.can_create_organization}><Icon name="plus" size={16} />Create organization</button></form></div><div className="organization-members">{organization ? <><div className="organization-summary"><h3>{organization.name}</h3><Badge status="neutral">Your role: {organization.role}</Badge></div><ul className="member-list">{organization.members.map(member => <li key={member.user_id}><div><strong>{member.name}</strong><small>{member.role}</small></div>{organization.role === 'admin' && <button className="text-button danger-text" disabled={!!busy} onClick={() => setConfirmation({ kind: 'remove', id: member.user_id })}>Remove member</button>}</li>)}</ul>{organization.role === 'admin' && <form className="member-form" onSubmit={event => { event.preventDefault(); void saveMember() }}><label className="field"><span>Identity</span><select value={memberId} onChange={event => setMemberId(event.target.value)} required><option value="">Choose an identity</option>{workspace.available_users.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label><label className="field"><span>Organization role</span><select value={memberRole} onChange={event => setMemberRole(event.target.value)}><option value="member">Member</option><option value="developer">Developer</option><option value="admin">Administrator</option></select></label><button className="button secondary" type="submit" disabled={!!busy}>Add or update member</button></form>}</> : <p className="security-note">Create an organization to become its administrator.</p>}</div></div></section>}
        {tab === 'setup' && <section className="panel app-registration-panel"><PanelTitle title="Register a website" description="Three setup steps, with callbacks checked by the identity provider." />{!manageable.length && <div className="feedback feedback-error"><span>Create an organization before registering an application.</span><button className="text-button" onClick={() => setTab('organizations')}>Manage organizations</button></div>}<ol className="registration-steps" aria-label="Registration steps">{['App and organization', 'Callback URLs', 'Permissions'].map((name, index) => <li key={name} className={step === index + 1 ? 'current' : step > index + 1 ? 'completed' : ''} aria-current={step === index + 1 ? 'step' : undefined}><span>{index + 1}</span>{name}</li>)}</ol><form onSubmit={event => { event.preventDefault(); if (step === 1) setStep(2); else if (step === 2) void checkCallbacks(); else void register() }}>
          {step === 1 && <div className="wizard-fields"><label className="field"><span>Application name</span><input minLength={2} maxLength={80} value={appName} onChange={event => setAppName(event.target.value)} placeholder="My website" required /></label><label className="field"><span>Organization that owns this app</span><select required value={organization?.can_manage ? organizationId : ''} onChange={event => { setOrganizationId(event.target.value); setResourceIds([]) }}><option value="">Choose a manageable organization</option>{manageable.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label className="field"><span>Client type</span><select value={clientType} onChange={event => setClientType(event.target.value as 'public' | 'confidential')}><option value="confidential">Server website · confidential</option><option value="public">Browser or mobile app · public</option></select><small>Use a confidential client when your backend can keep a client secret.</small></label></div>}
          {step === 2 && <div className="wizard-fields"><label className="field"><span>Exact callback URLs · one per line</span><textarea rows={4} required maxLength={20_480} value={callbacks} onChange={event => { ++callbackSequence.current; setCallbacks(event.target.value); setCallbackChecks([]) }} /></label><p className="security-note">Use HTTPS. Exact localhost HTTP callbacks are permitted for development. Wildcards and URL fragments are rejected.</p>{callbackChecks.map(item => <div className="callback-check-result" key={item.uri}><code>{item.uri}</code><Badge status={item.result.valid ? 'active' : 'high'}>{item.result.valid ? 'Valid URL' : 'Invalid URL'}</Badge>{item.result.checks.filter(check => check.name !== 'Exact registration' || item.result.registered !== null).map(check => <p key={check.name}>{check.name}: {check.passed ? 'Passed' : 'Failed'} · {check.message}</p>)}</div>)}</div>}
          {step === 3 && <><div className="wizard-summary"><strong>{appName}</strong><span>{organization?.name} · {clientType}</span><code>{callbacks}</code></div><fieldset className="scope-fields"><legend>Identity and permission scopes</legend>{availableScopes.map(scope => <label key={scope.id}><input type="checkbox" checked={scopes.includes(scope.id)} disabled={scope.id === 'openid'} onChange={() => setScopes(previous => toggle(previous, scope.id))} /><span>{scope.name}<small>{scope.id}</small></span></label>)}</fieldset><fieldset className="scope-fields"><legend>Resources this app may check</legend>{bootstrap?.resources.filter(resource => organization?.resource_ids.includes(resource.id)).map(resource => <label key={resource.id}><input type="checkbox" checked={resourceIds.includes(resource.id)} onChange={() => setResourceIds(previous => toggle(previous, resource.id))} /><span>{resource.name}<small>{resource.description}</small></span></label>)}{!organization?.resource_ids.length && <p>Add a resource owner to this organization to make their resource eligible for app mapping.</p>}<p>Mapping a resource lets the app check a user's approved grants. It never grants access by itself.</p></fieldset></>}
          <div className="form-footer"><span>{step > 1 ? <button className="text-button" type="button" disabled={!!busy} onClick={() => setStep(previous => previous - 1)}>Previous step</button> : 'Registering under your server-verified role'}</span><button className="button primary" type="submit" disabled={!!busy || !manageable.length}>{busy === 'callbacks' ? 'Checking callbacks…' : busy === 'register' ? 'Registering…' : step === 1 ? 'Continue to callbacks' : step === 2 ? 'Check callbacks and continue' : 'Register application'}</button></div>
        </form></section>}
        {confirmation && <section className="panel destructive-confirmation" role="alert"><div><h3>{confirmation.kind === 'rotate' ? 'Rotate this app’s client secret?' : confirmation.kind === 'disable' ? 'Disable this application?' : 'Remove this organization member?'}</h3><p>{confirmation.kind === 'rotate' ? 'Previous secrets and all tokens issued to this app will be invalidated. Update your website server with the new secret.' : confirmation.kind === 'disable' ? 'New sign-ins will stop and existing app tokens will be revoked.' : 'Their tokens for this organization’s applications will be revoked. Resource grants remain governed separately.'}</p></div><div className="inline-actions"><button className="button secondary" disabled={!!busy} onClick={() => setConfirmation(null)}>Cancel</button><button className="button primary" disabled={!!busy} onClick={mutate}>Confirm {confirmation.kind === 'rotate' ? 'rotation' : confirmation.kind === 'disable' ? 'disable' : 'removal'}</button></div></section>}
        {tab === 'apps' && <section className="panel registered-apps"><PanelTitle title="Your registered applications" description={`${workspace.apps.length} visible applications`} action={<button className="icon-button" aria-label="Refresh applications" disabled={!!busy} onClick={() => action('refresh', async () => { await load(); return null })}><Icon name="refresh" size={18} /></button>} />{workspace.apps.length ? <div className="app-list">{workspace.apps.map(application => <details className="registered-app" key={application.client_id}><summary><span className="request-summary-icon"><Icon name="access" size={20} /></span><div className="app-summary"><strong>{application.name}</strong><span>{application.client_type} · {workspace.organizations.find(item => item.id === application.organization_id)?.name || 'Legacy demo app'} · {formatDate(application.created_at)}</span></div><Badge status={application.active ? 'active' : 'expired'}>{application.active ? 'Active' : 'Disabled'}</Badge><Icon name="chevron" size={17} /></summary><div className="app-details"><dl><div><dt>Client ID</dt><dd><code>{application.client_id}</code></dd></div><div><dt>Callback URLs</dt><dd>{application.redirect_uris.map(uri => <code key={uri}>{uri}</code>)}</dd></div><div><dt>Scopes</dt><dd>{application.scopes.join(', ')}</dd></div><div><dt>Mapped resources</dt><dd>{application.resource_ids.map(id => bootstrap?.resources.find(resource => resource.id === id)?.name || id).join(', ') || 'None'}</dd></div></dl>{application.can_manage && application.active && <div className="inline-actions">{application.client_type === 'confidential' && <button className="button secondary" disabled={!!busy} onClick={() => setConfirmation({ kind: 'rotate', id: application.client_id })}>Rotate client secret</button>}<button className="text-button danger-text" disabled={!!busy} onClick={() => setConfirmation({ kind: 'disable', id: application.client_id })}>Disable app and revoke tokens</button></div>}</div></details>)}</div> : <Empty title="No applications registered yet." icon="access">Use Register to connect your first website. An organization is required to manage it.</Empty>}</section>}
        {tab === 'diagnostics' && <section className="panel callback-diagnostics"><PanelTitle title="Check a callback" description="Checks URL rules and exact active registration. This does not send a request to the website." /><form onSubmit={event => { event.preventDefault(); void inspectCallback() }}><label className="field"><span>Callback URL to inspect</span><input type="url" required value={diagnosticUri} onChange={event => { ++diagnosticSequence.current; setDiagnosticUri(event.target.value); setDiagnostic(null) }} /></label><label className="field"><span>Application to compare · optional</span><select value={diagnosticApp} onChange={event => { ++diagnosticSequence.current; setDiagnosticApp(event.target.value); setDiagnostic(null) }}><option value="">URL rules only</option>{workspace.apps.filter(item => item.can_manage).map(item => <option value={item.client_id} key={item.client_id}>{item.name}</option>)}</select></label><button className="button secondary" type="submit" disabled={!!busy}>{busy === 'diagnostic' ? 'Checking…' : 'Check callback'}</button></form>{diagnostic && <div className="diagnostic-results"><Badge status={diagnostic.valid && diagnostic.registered !== false ? 'active' : 'high'}>{diagnostic.valid ? diagnostic.registered === false ? 'Not registered' : 'URL rules passed' : 'Invalid callback'}</Badge>{diagnostic.development_only && <Badge status="medium">Development HTTP only</Badge>}{diagnostic.checks.map(check => <div key={check.name}><Icon name={check.passed ? 'check' : 'close'} size={17} /><span><strong>{check.name} · {check.name === 'Exact registration' && diagnostic.registered === null ? 'Not checked' : check.passed ? 'Passed' : 'Failed'}</strong><small>{check.message}</small></span></div>)}</div>}</section>}
        {tab === 'diagnostics' && registry && <section className="panel provider-panel"><PanelTitle title="Provider endpoints" description="Use these URLs with an OAuth/OIDC client. Permission checks still run on your server." /><dl>{Object.entries(registry).filter(([key, value]) => key !== 'items' && typeof value === 'string').map(([key, value]) => <div key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd><code>{String(value)}</code></dd></div>)}</dl></section>}
        {tab === 'organizations' && workspace.notice && <p className="security-note developer-notice">{workspace.notice}</p>}
      </>}
    </>}
  </>
}
