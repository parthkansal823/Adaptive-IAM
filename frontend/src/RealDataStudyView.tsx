import { useEffect, useState } from 'react'
import { api } from './api'
import type { LanlStudy } from './api'
import { Badge, Empty, Icon, PanelTitle, percent } from './components'

const methodNames = { new_user_source: 'New user / source', new_user_destination: 'New user / destination', edge_surprise: 'Authentication edge surprise' }
const partitions = ['warmup', 'validation', 'test'] as const
const count = (value: number) => value.toLocaleString('en-US')
const sourceLink = (value: unknown) => {
  if (typeof value !== 'string') return null
  try { const url = new URL(value); return url.protocol === 'https:' ? url.href : null } catch { return null }
}

export function RealDataStudyView() {
  const [report, setReport] = useState<LanlStudy | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    setLoading(true); setError('')
    api<LanlStudy>('/research/lanl').then(value => {
      if (!active) return
      if (value.schema_version !== 'lanl-study-v1' || value.synthetic !== false || value.source_real_enterprise !== true || value.evidence_type !== 'real_enterprise_authentication_with_exercise_redteam' || !value.source || typeof value.source.kind !== 'string' || !value.scan || !value.labels || !value.methods || !Object.keys(methodNames).every(key => key in value.methods) || !partitions.every(key => value.partitions?.[key]) || !Array.isArray(value.limitations)) throw new Error('The API returned an unsupported real-data study report.')
      setReport(value)
    }).catch(failure => { if (active) { setReport(null); setError(failure instanceof Error ? failure.message : 'The real-data study could not be loaded.') } }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [attempt])
  const download = () => {
    if (!report) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'adaptive-iam-lanl-study.json'; anchor.click(); URL.revokeObjectURL(url)
  }
  const eligible = report?.labels.detection_metrics_eligible === true && (report?.partitions.test.known_redteam_unique_tuples ?? 0) > 0
  const landingPage = sourceLink(report?.source.landing_page)
  return <section className="panel comparison-panel real-data-study">
    <PanelTitle title="Real enterprise authentication evidence" description="A separate chronological LANL study using deidentified enterprise events and exercise red-team labels." action={<Badge status="neutral">Real event data</Badge>} />
    {!report ? <Empty icon="research" title={loading ? 'Loading the real-data study…' : 'The real-data study is unavailable.'} action={<button className="button secondary" disabled={loading} onClick={() => setAttempt(value => value + 1)}>Retry real-data study</button>}>{error || 'Reading the frozen LANL study report from the API.'}</Empty> : <>
      <p className="security-note">This is a limited {report.source.bounded_auth_prefix ? 'prefix sample' : 'sample'} of observed enterprise authentication. Red-team matches identify recorded exercise activity; remaining events are unlabeled. These measurements do not establish general production detection or the safety of an access policy.</p>
      <div className="request-form-top"><button className="button secondary" onClick={download}><Icon name="download" size={16} />Export real-data study</button><button className="button secondary" disabled={loading} onClick={() => setAttempt(value => value + 1)}>{loading ? 'Loading…' : 'Refresh real-data study'}</button></div>
      <dl className="protocol-list">
        <div><dt>Source</dt><dd>{report.source.kind.replaceAll('_', ' ')}{landingPage && <> · <a href={landingPage} target="_blank" rel="noreferrer">LANL dataset and provenance</a></>}</dd></div>
        <div><dt>Source rows scanned</dt><dd>{count(report.scan.source_rows)}</dd></div>
        <div><dt>Selected authentication rows</dt><dd>{count(report.scan.selected_rows)}</dd></div>
        <div><dt>Source time span</dt><dd>Seconds {count(report.scan.source_first_second)}–{count(report.scan.source_last_second)} relative to the dataset start</dd></div>
        <div><dt>Exercise reference</dt><dd>{count(report.labels.unique_redteam_tuples_in_reference)} unique red-team tuples in the reference</dd></div>
      </dl>
      <div className="table-wrap"><table className="comparison-table"><caption>Chronological partitions; warmup precedes threshold selection and held-out testing</caption><thead><tr><th>Partition</th><th>Events</th><th>Unlabeled events</th><th>Matched exercise rows</th><th>Known exercise tuples</th><th>Dataset seconds</th></tr></thead><tbody>{partitions.map(key => { const split = report.partitions[key]; return <tr key={key}><td><strong>{key === 'warmup' ? 'Warmup' : key === 'validation' ? 'Validation' : 'Test'}</strong></td><td>{count(split.events)}</td><td>{count(split.unlabeled_events)}</td><td>{count(split.matched_auth_rows)}</td><td>{count(split.known_redteam_unique_tuples)}</td><td>{count(split.first_second)}–{count(split.last_second)}</td></tr> })}</tbody></table></div>
      <p className="security-note real-data-eligibility"><strong>{eligible ? 'Exercise recall is eligible for this sample.' : 'Exercise recall is not estimable for this sample.'}</strong> {report.labels.eligibility_reason} Known test exercise tuples: {count(report.partitions.test.known_redteam_unique_tuples)}; matched test authentication rows: {count(report.partitions.test.matched_auth_rows)}.</p>
      <div className="table-wrap"><table className="comparison-table real-data-methods"><caption>Frozen research baselines: alert burden and known exercise recall on held-out test events</caption><thead><tr><th>Research baseline</th><th>Validation alerts</th><th>Test alerts</th><th>Unlabeled alerts</th><th>Known exercise tuple recall</th></tr></thead><tbody>{(Object.keys(methodNames) as (keyof typeof methodNames)[]).map(key => { const method = report.methods[key]; return <tr key={key}><td><strong>{methodNames[key]}</strong></td><td>{percent(method.threshold.validation_alert_fraction)}<small>{method.threshold.minimum_score === null ? 'Disabled: validation tie exceeds alert budget' : 'Threshold selected on validation'}</small></td><td>{percent(method.test_alert_fraction)}<small>{count(method.test_alerts)} / {count(report.partitions.test.events)} test events</small></td><td>{report.partitions.test.unlabeled_events > 0 && method.alert_fraction_over_unlabeled !== null ? percent(method.alert_fraction_over_unlabeled) : <strong>Not estimable</strong>}<small>{count(method.unlabeled_alerts)} / {count(report.partitions.test.unlabeled_events)} unlabeled events</small></td><td>{eligible && method.known_redteam_tuple_recall !== null && method.known_redteam_recalled_unique_tuples !== null && method.known_redteam_alerted_auth_rows !== null ? <>{percent(method.known_redteam_tuple_recall)}<small>{count(method.known_redteam_recalled_unique_tuples)} / {count(report.partitions.test.known_redteam_unique_tuples)} known test exercise tuples</small><small>{count(method.known_redteam_alerted_auth_rows)} matched authentication rows alerted</small></> : <><strong>Not estimable</strong><small>Exercise labels insufficient in this sample</small></>}</td></tr> })}</tbody></table></div>
      <p className="security-note">Unlabeled alert burden is a count of alerts on events without a matching exercise label. It does not measure false positives, user friction, or accuracy. Exercise tuple recall covers only known exercise activity in this sample.</p>
      <details className="protocol-extra"><summary>Source provenance, protocol and limitations</summary><pre>{JSON.stringify(report.source, null, 2)}</pre><ul>{report.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details>
    </>}
  </section>
}
