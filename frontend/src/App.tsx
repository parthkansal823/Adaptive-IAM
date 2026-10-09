import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from './api'
import type { AccessRequest, AuditEvent, AuthResult, Bootstrap, Context, Evaluation, Grant, Identity, Overview, ResourceAccess, Risk, Verification } from './api'
import { AccessView } from './AccessView'
import { AppsView, ConsentView } from './AppsView'
import { AuditView } from './AuditView'
import { AuthModal } from './AuthModal'
import { Badge, Brand, Icon, initials } from './components'
import type { IconName } from './components'
import { ExperimentsView } from './ExperimentsView'
import { OverviewView } from './OverviewView'
import { RiskView } from './RiskView'

type View = 'overview' | 'risk' | 'access' | 'audit' | 'research' | 'apps' | 'connect'
const navigation: { id: View; name: string; icon: IconName }[] = [{ id: 'overview', name: 'Overview', icon: 'overview' }, { id: 'risk', name: 'Risk lab', icon: 'risk' }, { id: 'access', name: 'Access requests', icon: 'access' }, { id: 'audit', name: 'Audit ledger', icon: 'audit' }, { id: 'research', name: 'Experiments', icon: 'research' }, { id: 'apps', name: 'Connected apps', icon: 'access' }]

export default function App() {
  const [view, setView] = useState<View>(() => window.location.pathname === '/connect' ? 'connect' : 'overview')
  const [requestId] = useState(() => new URLSearchParams(window.location.search).get('request_id'))
  const [theme, setTheme] = useState(() => localStorage.getItem('adaptive-iam-theme') || 'light')
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem('adaptive-iam-session'))
  const tokenRef = useRef(token)
  tokenRef.current = token
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null)
  const [user, setUser] = useState<Identity | null>(null)
  const [sessionRisk, setSessionRisk] = useState<Risk | null>(null)
  const [assessmentRisk, setAssessmentRisk] = useState<Risk | null>(null)
  const [overview, setOverview] = useState<Overview | null>(null)
  const [requests, setRequests] = useState<AccessRequest[]>([])
  const [grants, setGrants] = useState<Grant[]>([])
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [report, setReport] = useState<Evaluation | null>(null)
  const [verification, setVerification] = useState<Verification | null>(null)
  const [loginOpen, setLoginOpen] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)
  const [connection, setConnection] = useState<'connecting' | 'online' | 'offline'>('connecting')
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  useEffect(() => { document.documentElement.dataset.theme = theme; localStorage.setItem('adaptive-iam-theme', theme) }, [theme])
  const closeLogin = useCallback(() => setLoginOpen(false), [])
  const clearSession = useCallback(() => { sessionStorage.removeItem('adaptive-iam-session'); setToken(null); setUser(null); setSessionRisk(null); setOverview(null); setRequests([]); setGrants([]); setEvents([]); setVerification(null) }, [])
  const refreshProtected = useCallback(async (sessionToken: string) => {
    const [summary, requestData, grantData, auditData] = await Promise.all([
      api<Overview>('/overview', sessionToken), api<{ items: AccessRequest[] }>('/requests', sessionToken), api<{ items: Grant[] }>('/grants', sessionToken), api<{ items: AuditEvent[] }>('/audit', sessionToken),
    ])
    if (tokenRef.current !== sessionToken) return
    setOverview(summary); setRequests(requestData.items); setGrants(grantData.items); setEvents(auditData.items); setConnection('online')
  }, [])
  const loadReport = useCallback(async () => {
    setReportLoading(true)
    try { setReport(await api<Evaluation>('/evaluation')); setConnection('online') }
    catch (error) { setFeedback({ type: 'error', text: error instanceof Error ? error.message : 'The evaluation could not be loaded.' }) }
    finally { setReportLoading(false) }
  }, [])
  const loadPublic = useCallback(async () => {
    setConnection('connecting')
    try { const data = await api<Bootstrap>('/bootstrap'); setBootstrap(data); setConnection('online') }
    catch (error) { setConnection('offline'); setFeedback({ type: 'error', text: error instanceof Error ? error.message : 'The backend could not be reached.' }) }
  }, [])
  useEffect(() => { void loadPublic(); void loadReport() }, [loadPublic, loadReport])
  useEffect(() => {
    if (!token) return
    let current = true
    const load = async () => {
      try {
        const session = await api<{ user: Identity; session: { expires_at: string }; risk: Risk }>('/auth/me', token)
        if (!current) return
        setUser(session.user); setSessionRisk(session.risk); setAssessmentRisk(previous => previous || session.risk)
        await refreshProtected(token)
      } catch (error) {
        if (!current) return
        if (error instanceof ApiError && error.status === 401) { clearSession(); setFeedback({ type: 'error', text: 'Your session expired. Sign in again to continue.' }) }
        else { setConnection('offline'); setFeedback({ type: 'error', text: error instanceof Error ? error.message : 'Workspace data could not be loaded.' }) }
      }
    }
    void load()
    return () => { current = false }
  }, [token, refreshProtected, clearSession])
  const runAction = async (key: string, action: () => Promise<void>, message?: string): Promise<boolean> => {
    setBusy(key); setFeedback(null)
    try { await action(); setConnection('online'); if (message) setFeedback({ type: 'success', text: message }); return true }
    catch (error) {
      if (error instanceof ApiError && error.status === 401) clearSession()
      if (error instanceof ApiError && error.status === 0) setConnection('offline')
      setFeedback({ type: 'error', text: error instanceof Error ? error.message : 'This action could not be completed.' }); return false
    } finally { setBusy(null) }
  }
  const authenticated = (result: AuthResult) => {
    if (!result.token || !result.user) { setFeedback({ type: 'error', text: 'The API did not issue a session. Retry sign-in.' }); return }
    setOverview(null); setRequests([]); setGrants([]); setEvents([]); setVerification(null)
    tokenRef.current = result.token
    sessionStorage.setItem('adaptive-iam-session', result.token); setToken(result.token); setUser(result.user); setSessionRisk(result.risk); setAssessmentRisk(result.risk); setLoginOpen(false); setFeedback({ type: 'success', text: `Signed in as ${result.user.name}.` })
  }
  const refresh = async () => {
    setRefreshing(true); setFeedback(null)
    await loadPublic(); await loadReport()
    if (token) await runAction('refresh', () => refreshProtected(token))
    setRefreshing(false)
  }
  const assess = (context: Context) => runAction('assess', async () => { setAssessmentRisk(await api<Risk>('/risk/assess', null, { context })) }, 'Assessment complete. The result reflects the submitted context.')
  const create = (body: { resource_id: string; justification: string; duration_hours: number }) => runAction('create', async () => { await api<AccessRequest>('/requests', token, body); if (token) await refreshProtected(token) }, 'Request submitted. Reviewers and the decision are shown below.')
  const vote = (id: string, approve: boolean, comment: string) => runAction(`vote-${id}`, async () => { await api<AccessRequest>(`/requests/${id}/votes`, token, { approve, comment }); setVerification(null); if (token) await refreshProtected(token) }, 'Your vote was recorded in the ledger.')
  const verify = () => runAction('verify', async () => { setVerification(await api<Verification>('/audit/verify', token)) })
  const inspect = async (resourceId: string): Promise<ResourceAccess | null> => { let result: ResourceAccess | null = null; const success = await runAction('inspect', async () => { result = await api<ResourceAccess>(`/resources/${resourceId}/access`, token); setVerification(null); if (token) await refreshProtected(token) }); return success ? result : null }
  const logout = () => runAction('logout', async () => { await api('/auth/logout', token, {}); clearSession() }, 'Signed out. Your server session was revoked.')
  const selected = navigation.find(item => item.id === view) || { name: 'Connect an app' }
  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to workspace</a>
    <aside className="sidebar"><Brand /><div className="workspace-picker"><span className="workspace-icon"><Icon name="shield" size={17} /></span><span>Research workspace<small>Adaptive IAM</small></span><span className="workspace-dot" /></div><nav aria-label="Main navigation">{navigation.map(item => <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} aria-current={view === item.id ? 'page' : undefined} onClick={() => { setView(item.id); setFeedback(null) }}><Icon name={item.icon} size={20} /><span>{item.name}</span>{item.id === 'access' && overview?.stats.review_queue ? <span className="nav-count">{overview.stats.review_queue}</span> : null}</button>)}</nav><div className="sidebar-bottom"><div className="sidebar-research"><Icon name="research" size={19} /><span>Research edition<small>Evaluate. Inspect. Improve.</small></span></div><div className="api-status"><span className={`status-dot status-${connection}`} /><span>{connection === 'online' ? 'API connected' : connection === 'offline' ? 'API unavailable' : 'Connecting to API'}</span><button aria-label="Reconnect to API" onClick={refresh} disabled={refreshing}><Icon name="refresh" size={13} /></button></div></div></aside>
    <div className="workspace"><header className="topbar"><div className="breadcrumb"><span>Workspace</span><Icon name="chevron" size={13} /><strong>{selected.name}</strong></div><div className="topbar-actions"><span className="demo-pill">Local demo</span><button className={`icon-button refresh-button ${refreshing ? 'spinning' : ''}`} title="Refresh workspace" aria-label="Refresh workspace" onClick={refresh} disabled={refreshing}><Icon name="refresh" size={18} /></button><button className="icon-button theme-button" title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`} aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`} onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}><Icon name={theme === 'light' ? 'moon' : 'sun'} size={19} /></button><div className="topbar-divider" />{user ? <div className="session-control"><button className="user-button" onClick={() => setLoginOpen(true)} title="Sign in as another demo identity"><span className="avatar">{initials(user.name)}</span><span>{user.name}<small>{user.role.replaceAll('_', ' ')}</small></span></button><button className="icon-button" title="Sign out and revoke session" aria-label="Sign out and revoke session" onClick={logout} disabled={busy === 'logout'}><Icon name="logout" size={17} /></button></div> : <button className="button secondary sign-in-button" onClick={() => setLoginOpen(true)}><Icon name="user" size={16} />Sign in</button>}</div></header>
      <main id="main-content" tabIndex={-1}>
        {feedback && <div className={`feedback feedback-${feedback.type}`} role={feedback.type === 'error' ? 'alert' : 'status'}><Icon name={feedback.type === 'error' ? 'signal' : 'check'} size={18} /><span>{feedback.text}</span><button className="icon-button" aria-label="Dismiss message" onClick={() => setFeedback(null)}><Icon name="close" size={16} /></button></div>}
        {connection === 'offline' && <div className="offline-notice"><span>The API is unavailable. Start the backend on port 8000, then reconnect.</span><button className="text-button" onClick={refresh} disabled={refreshing}>Reconnect <Icon name="refresh" size={15} /></button></div>}
        {view === 'overview' && <OverviewView bootstrap={bootstrap} overview={overview} user={user} risk={sessionRisk} grants={grants} onRisk={() => setView('risk')} onRequests={() => setView('access')} onResearch={() => setView('research')} onLogin={() => setLoginOpen(true)} />}
        {view === 'risk' && <RiskView risk={assessmentRisk} onAssess={assess} busy={busy === 'assess'} thresholds={bootstrap?.risk_thresholds} />}
        {view === 'access' && <AccessView key={user?.id || 'signed-out'} user={user} bootstrap={bootstrap} requests={requests} grants={grants} busy={busy} onLogin={() => setLoginOpen(true)} onCreate={create} onVote={vote} onInspect={inspect} />}
        {view === 'audit' && <AuditView events={events} verification={verification} user={user} token={token} busy={busy === 'verify'} onVerify={verify} onLogin={() => setLoginOpen(true)} />}
        {view === 'research' && <ExperimentsView report={report} loading={reportLoading} onRefresh={loadReport} />}
        {view === 'apps' && <AppsView key={user?.id || 'signed-out'} token={token} user={user} bootstrap={bootstrap} onLogin={() => setLoginOpen(true)} />}
        {view === 'connect' && <ConsentView key={user?.id || 'signed-out'} requestId={requestId} token={token} user={user} onLogin={() => setLoginOpen(true)} />}
        <footer className="workspace-footer"><span>Adaptive IAM <span className="footer-separator">/</span> Adaptive identity research</span><span>{bootstrap ? <Badge status="neutral">Synthetic model · local ledger</Badge> : 'Waiting for API'}</span></footer>
      </main>
    </div>
    {loginOpen && <AuthModal bootstrap={bootstrap} onClose={closeLogin} onAuthenticated={authenticated} />}
  </div>
}

