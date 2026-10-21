import { useEffect, useState } from 'react'
import { api } from './api'
import type { UncertaintyStudy } from './api'
import { Badge, Empty, Icon, PanelTitle, percent } from './components'

const title = (value: string) => value.replaceAll('_', ' ').replace(/\biid\b/gi, 'IID')

export function UncertaintyStudyView() {
  const [report, setReport] = useState<UncertaintyStudy | null>(null)
  const [condition, setCondition] = useState('iid')
  const [attempt, setAttempt] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    setLoading(true); setError('')
    api<UncertaintyStudy>('/research/uncertainty').then(value => {
      if (!active) return
      if (value.schema_version !== 'uncertainty-study-v1' || value.synthetic !== true || !value.summary || !Array.isArray(value.seeds)) throw new Error('The API returned an unsupported study report.')
      setReport(value)
      setCondition(previous => previous in value.summary ? previous : Object.keys(value.summary)[0] || '')
    }).catch(failure => { if (active) { setReport(null); setError(failure instanceof Error ? failure.message : 'The study could not be loaded.') } }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [attempt])
  const download = () => {
    if (!report) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'adaptive-iam-uncertainty-study.json'; anchor.click(); URL.revokeObjectURL(url)
  }
  const metric = (method: string, key: string) => {
    const value = report?.summary[condition]?.[method]?.[key]
    return value && Number.isFinite(value.mean) ? <>{percent(value.mean)}<small>SD {percent(value.sample_std)} · range {percent(value.minimum)}–{percent(value.maximum)}</small></> : '—'
  }
  return <section className="panel comparison-panel uncertainty-study">
    <PanelTitle title="Uncertainty under distribution shift" description="A separate synthetic stress study of conformal prediction sets and additional sign-in verification." action={<Badge status="neutral">Research only</Badge>} />
    {!report ? <Empty icon="research" title={loading ? 'Loading the uncertainty study…' : 'The uncertainty study is unavailable.'} action={<button className="button secondary" disabled={loading} onClick={() => setAttempt(value => value + 1)}>Retry study</button>}>{error || 'Reading the frozen experiment report from the API.'}</Empty> : <>
      <p className="security-note">{report.seeds.length} fresh training seeds · nominal set coverage {percent(1 - report.alpha)} under stated exchangeability assumptions. Coverage can change under distribution shift. This study changes no deployed model or access policy.</p>
      <div className="request-form-top"><label className="field"><span>Held-out condition</span><select value={condition} onChange={event => setCondition(event.target.value)}>{Object.keys(report.summary).map(key => <option key={key} value={key}>{title(key)}</option>)}</select></label><button className="button secondary" onClick={download}><Icon name="download" size={16} />Export uncertainty study</button></div>
      <div className="table-wrap"><table className="comparison-table"><caption className="sr-only">Mean rates across fixed seeds, with sample standard deviations and ranges</caption><thead><tr><th>Research policy</th><th>Suspicious challenged</th><th>Legitimate friction</th><th>Suspicious directly allowed</th></tr></thead><tbody>{Object.keys(report.summary[condition] || {}).map(method => <tr key={method}><td><strong>{title(method)}</strong></td><td>{metric(method, 'suspicious_detection_rate')}</td><td>{metric(method, 'legitimate_friction_rate')}</td><td>{metric(method, 'suspicious_direct_allow_rate')}</td></tr>)}</tbody></table></div>
      <div className="table-wrap"><table className="comparison-table"><caption>Conformal set diagnostics for the selected condition</caption><thead><tr><th>Research policy</th><th>Overall coverage</th><th>Suspicious coverage</th><th>Both labels included</th><th>Mean set size</th></tr></thead><tbody>{Object.keys(report.summary[condition] || {}).filter(method => report.summary[condition][method].coverage).map(method => <tr key={method}><td><strong>{title(method)}</strong></td><td>{metric(method, 'coverage')}</td><td>{metric(method, 'suspicious_coverage')}</td><td>{metric(method, 'both_labels_rate')}</td><td>{report.summary[condition][method].mean_set_size?.mean.toFixed(3) ?? '—'}</td></tr>)}</tbody></table></div>
      <p className="security-note">Conformal gates may add verification to the baseline. Higher detection can require more legitimate-user challenges; the always-challenge control exposes that cost. Resource access still requires server-enforced human approval.</p>
      <details className="protocol-extra"><summary>Study protocol, uncertainty and limitations</summary><pre>{JSON.stringify(report.protocol, null, 2)}</pre><ul>{report.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details>
    </>}
  </section>
}
