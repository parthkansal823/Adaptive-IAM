import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from './api'
import type { AttackCase, Identity, LabRun } from './api'
import { actionLabel, Badge, Empty, formatDate, Icon, PageTitle, PanelTitle, percent } from './components'

export function AttackLabView({ token, user, onLogin, onSecurity }: { token: string | null; user: Identity | null; onLogin: () => void; onSecurity: () => void }) {
  const [cases, setCases] = useState<AttackCase[]>([])
  const [notice, setNotice] = useState('')
  const [caseId, setCaseId] = useState('')
  const [runs, setRuns] = useState<LabRun[]>([])
  const [result, setResult] = useState<LabRun | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const busyRef = useRef(false)
  const mounted = useRef(false)
  const [error, setError] = useState('')
  const [verificationNeeded, setVerificationNeeded] = useState(false)
  const selected = cases.find(item => item.id === caseId)
  const load = useCallback(async () => {
    if (!token) return
    const [catalog, history] = await Promise.all([api<{ items: AttackCase[]; notice: string }>('/lab/catalog', token), api<{ items: LabRun[] }>('/lab/runs', token)])
    if (!mounted.current) return
    setCases(catalog.items); setNotice(catalog.notice); setRuns(history.items); setCaseId(previous => catalog.items.some(item => item.id === previous) ? previous : catalog.items[0]?.id || '')
  }, [token])
  const fail = (failure: unknown) => {
    setError(failure instanceof Error ? failure.message : 'The diagnostic could not be completed.')
    setVerificationNeeded(failure instanceof ApiError && ['step_up_required', 'recent_verification_required'].includes(failure.code || ''))
  }
  useEffect(() => {
    let active = true
    mounted.current = true
    if (!token) { setLoading(false); return () => { mounted.current = false } }
    setLoading(true)
    load().catch(failure => { if (active) fail(failure) }).finally(() => { if (active) setLoading(false) })
    return () => { active = false; mounted.current = false }
  }, [load, token])
  const refresh = async () => {
    if (!token || loading || busyRef.current) return
    busyRef.current = true; setLoading(true); setError(''); setVerificationNeeded(false)
    try { await load() }
    catch (failure) { if (mounted.current) fail(failure) }
    finally { busyRef.current = false; if (mounted.current) setLoading(false) }
  }
  const run = async () => {
    if (!token || !caseId || loading || busyRef.current) return
    busyRef.current = true; setBusy(true); setError(''); setVerificationNeeded(false); setResult(null)
    try {
      const packet = await api<LabRun>('/lab/run', token, { case_id: caseId }, 'POST', 120_000)
      if (!mounted.current) return
      setResult(packet); setRuns(previous => [packet, ...previous.filter(item => item.id !== packet.id)].slice(0, 20))
    } catch (failure) { if (mounted.current) fail(failure) }
    finally { if (mounted.current) setBusy(false); busyRef.current = false }
  }
  return <>
    <PageTitle title="Attack scenarios" description="Run a research scenario and inspect the model and permission checks." action={user && token && <button className="button secondary" disabled={loading || busy} onClick={refresh}><Icon name="refresh" size={16} />{loading ? 'Loading scenarios…' : 'Refresh scenarios'}</button>} />
    {!user || !token ? <section className="panel"><Empty title="Sign in to run scenarios" icon="research" action={<button className="button primary" onClick={onLogin}>Sign in</button>}>Diagnostics observe your own server-side requests and grants. They never cast votes or create access.</Empty></section> : <>
      {error && <div className="feedback feedback-error" role="alert"><Icon name="signal" size={18} /><span>{error}</span>{verificationNeeded && <button className="text-button" onClick={onSecurity}>Verify in Security</button>}</div>}
      <section className="panel attack-case-panel"><PanelTitle title="Choose a scenario" description="Select a test case to see the running model and your current permission checks." /><form onSubmit={event => { event.preventDefault(); void run() }}><label className="field"><span>Diagnostic scenario</span><select value={caseId} disabled={loading || busy || !cases.length} required onChange={event => { setCaseId(event.target.value); setResult(null) }}>{[...new Set(cases.map(item => item.category))].map(category => <optgroup label={category} key={category}>{cases.filter(item => item.category === category).map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</optgroup>)}</select><small>{selected?.description || (loading ? 'Loading the scenario catalog…' : 'No scenarios returned. Use Refresh scenarios to retry, or verify this session in Security.')}</small></label><button className="button primary" type="submit" disabled={busy || loading || !cases.length}><Icon name="research" size={18} />{busy ? 'Running actual checks…' : 'Run scenario'}</button></form><div className="lab-boundary"><Icon name="shield" size={18} /><p>{notice || 'Diagnostic scenarios use simulated inputs. Existing grants are observed, and this run never creates votes or permissions.'}</p></div></section>
      {busy && <section className="panel"><Empty title="Reading the model and policy state…" icon="clock">Waiting for the API to confirm this diagnostic. Results appear only after the server responds.</Empty></section>}
      {result && <section className="panel attack-result"><PanelTitle title={cases.find(item => item.id === result.case_id)?.name || result.case_id} description={`Observed ${formatDate(result.created_at)}`} action={<Badge status="neutral">Read-only diagnostic</Badge>} /><div className="lab-result-summary"><div><span>Context risk</span><strong>{percent(result.risk.score)}</strong><Badge status={result.risk.tier}>{result.risk.tier} risk</Badge></div><div><span>Authentication policy</span><strong>{actionLabel(result.risk.action)}</strong><small>Simulated context; no session issued</small></div><div><span>Language adviser</span><strong>{result.nlp ? result.nlp.label.replaceAll('_', ' ') : 'Not requested'}</strong><small>{result.nlp ? `${result.nlp.engine} · classifier confidence ${percent(result.nlp.confidence)}` : 'No text in this scenario'}</small></div></div><details className="diagnostic-details"><summary>View policy checks</summary><ol className="diagnostic-journey">{result.stages.map((stage, index) => <li key={stage.name}><span className="journey-index">{index + 1}</span><div><h3>{stage.name}</h3><p>{stage.detail}</p></div><Badge status="neutral">{stage.status.replaceAll('_', ' ')}</Badge></li>)}</ol><div className="lab-observations"><h3>Server observations</h3>{result.checks.map(check => <div key={check.name}><Icon name={check.passed ? 'check' : 'signal'} size={18} /><span><strong>{check.name} · {check.passed ? 'Observed' : 'Not observed'}</strong><small>{check.detail}</small></span></div>)}</div></details><div className="lab-boundary"><Icon name="lock" size={18} /><p>{result.grant_created ? 'The API reported a created grant. Inspect the access ledger before relying on this result.' : 'No grant was created by this run.'} {result.human_approval_required ? 'Owner and peer approval remain required for new resource access.' : ''} {result.notice}</p></div></section>}
      <section className="panel lab-history"><PanelTitle title="Recent runs" description="The server retains your latest 20 runs. Reopening a result shows its recorded state, not a new live check." />{runs.length ? <div className="table-wrap"><table><thead><tr><th>Scenario</th><th>Recorded</th><th>Context risk</th><th>Language</th><th>Result</th></tr></thead><tbody>{runs.map(item => <tr key={item.id}><td><strong>{cases.find(entry => entry.id === item.case_id)?.name || item.case_id}</strong></td><td>{formatDate(item.created_at)}</td><td><Badge status={item.risk.tier}>{percent(item.risk.score)}</Badge></td><td>{item.nlp?.label.replaceAll('_', ' ') || 'No text'}</td><td><button className="text-button" disabled={busy} onClick={() => setResult(item)}>View result</button></td></tr>)}</tbody></table></div> : <Empty title={loading ? 'Loading diagnostic history…' : 'No diagnostics yet.'} icon="research">Select a scenario above to trace a real response from the running API.</Empty>}</section>
    </>}
  </>
}
