import { useEffect, useState } from 'react'
import { api } from './api'
import type { RealAuthModelsStudy } from './api'
import { Badge, Empty, Icon, PanelTitle, percent } from './components'

const modelNames = { lifetime_user_computer: 'Lifetime frequency control', hierarchical_static: 'Smoothed static', hierarchical_decay: 'Smoothed with decay' }
const strataNames = { cold_user: 'Cold user', known_user_new_computer: 'Known user / new computer', familiar_user_computer: 'Familiar user / computer' }
const datasetNames: Record<string, string> = { lanl2015_retrospective: 'LANL 2015 · retrospective exercise sample', lanl2014_unlabeled: 'LANL 2014 · successful authentication, no attack labels' }
const modelKeys = Object.keys(modelNames) as (keyof typeof modelNames)[]
const strataKeys = Object.keys(strataNames) as (keyof typeof strataNames)[]
const partitionKeys = ['warmup', 'validation', 'test'] as const
const count = (value: number) => value.toLocaleString('en-US')
const rate = (value: number | null, denominator: number) => value !== null && Number.isFinite(value) && denominator > 0 ? `${(value * 100).toFixed(3)}%` : 'Not estimable'
const seconds = (first: number | null, last: number | null) => first !== null && last !== null ? `${count(first)}–${count(last)}` : 'No events'
function sourceLink(source: RealAuthModelsStudy['datasets'][string]['source']) {
  const value = source.source_url || source.provenance?.source_url
  if (typeof value !== 'string') return null
  try { const url = new URL(value); return url.protocol === 'https:' ? url.href : null } catch { return null }
}

export function RealAuthModelsView() {
  const [report, setReport] = useState<RealAuthModelsStudy | null>(null)
  const [selected, setSelected] = useState('lanl2015_retrospective')
  const [attempt, setAttempt] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    setLoading(true); setError('')
    api<RealAuthModelsStudy>('/research/real-auth-models').then(value => {
      if (!active) return
      if (value.schema_version !== 'real-auth-model-study-v1' || value.synthetic !== false || !value.protocol || !Array.isArray(value.limitations) || !value.datasets || !Object.keys(value.datasets).length || !Object.values(value.datasets).every(dataset => dataset.source && dataset.scan && dataset.labels && modelKeys.every(key => dataset.methods?.[key]?.threshold) && partitionKeys.every(key => dataset.partitions?.[key]) && strataKeys.every(key => dataset.test_strata?.[key] && modelKeys.every(model => dataset.test_strata[key].methods?.[model])))) throw new Error('The API returned an unsupported real-authentication model study.')
      setReport(value)
      setSelected(previous => previous in value.datasets ? previous : Object.keys(value.datasets)[0])
    }).catch(failure => { if (active) { setReport(null); setError(failure instanceof Error ? failure.message : 'The model study could not be loaded.') } }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [attempt])
  const download = () => {
    if (!report) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'adaptive-iam-real-auth-models.json'; anchor.click(); URL.revokeObjectURL(url)
  }
  const dataset = report?.datasets[selected]
  const test = dataset?.partitions.test
  const knownTuples = test?.known_redteam_unique_tuples
  const eligible = dataset?.labels.available === true && dataset.labels.detection_metrics_eligible === true && typeof knownTuples === 'number' && knownTuples > 0
  const landingPage = dataset ? sourceLink(dataset.source) : null
  return <section className="panel comparison-panel real-auth-models">
    <PanelTitle title="User–computer model comparison" description="Three fixed research models share the same user, destination computer and past timestamp history." action={<Badge status="neutral">Offline research</Badge>} />
    {!report || !dataset || !test ? <Empty icon="research" title={loading ? 'Loading the real-authentication models…' : 'The real-authentication model study is unavailable.'} action={<button className="button secondary" disabled={loading} onClick={() => setAttempt(value => value + 1)}>Retry model study</button>}>{error || 'Reading the frozen model comparison from the API.'}</Empty> : <>
      <p className="security-note">These real authentication datasets come from the same historic LANL institution. They do not establish generalization to independent organizations. All fixed models and regressions are reported; test results select no winner and change no live access policy.</p>
      <div className="request-form-top"><label className="field"><span>Model study dataset</span><select value={selected} onChange={event => setSelected(event.target.value)}>{Object.keys(report.datasets).map(key => <option key={key} value={key}>{datasetNames[key] || key.replaceAll('_', ' ')}</option>)}</select></label><button className="button secondary" onClick={download}><Icon name="download" size={16} />Export model study</button></div>
      <p className="security-note model-study-eligibility"><strong>{dataset.labels.available ? eligible ? 'Known exercise recall is eligible for this sample.' : 'Known exercise recall is not estimable for this sample.' : 'No attack labels are available. This dataset measures alert burden only.'}</strong> {dataset.labels.interpretation} {dataset.source.retrospective && 'This previously inspected prefix is a retrospective diagnostic, not untouched confirmation.'}</p>
      <dl className="protocol-list">
        <div><dt>Source</dt><dd>{dataset.source.kind}{landingPage && <> · <a href={landingPage} target="_blank" rel="noreferrer">Dataset provenance</a></>}</dd></div>
        <div><dt>Input sample</dt><dd>{dataset.source.bounded_prefix ? 'Bounded prefix' : 'Reported source sample'} · {count(dataset.scan.source_rows)} rows scanned · {count(dataset.scan.selected_rows)} selected</dd></div>
        <div><dt>Source time span</dt><dd>Seconds {seconds(dataset.scan.source_first_second, dataset.scan.source_last_second)} relative to the dataset start</dd></div>
        <div><dt>Authentication input SHA-256</dt><dd><code>{dataset.source.auth_sha256}</code></dd></div>
        <div><dt>Test cold-user events</dt><dd>{count(dataset.test_strata.cold_user.events)} / {count(test.events)} test events</dd></div>
      </dl>
      <div className="table-wrap"><table className="comparison-table"><caption>Chronological source-second partitions; thresholds use validation observables only</caption><thead><tr><th>Partition</th><th>Events</th><th>Unlabeled events</th><th>Known exercise tuples</th><th>Dataset seconds</th></tr></thead><tbody>{partitionKeys.map(key => { const part = dataset.partitions[key]; return <tr key={key}><td><strong>{key[0].toUpperCase() + key.slice(1)}</strong></td><td>{count(part.events)}</td><td>{count(part.unlabeled_events)}</td><td>{dataset.labels.available && part.known_redteam_unique_tuples !== null ? count(part.known_redteam_unique_tuples) : 'No labels'}</td><td>{seconds(part.first_second, part.last_second)}</td></tr> })}</tbody></table></div>
      <div className="table-wrap"><table className="comparison-table real-auth-model-methods"><caption>Fixed model comparison for the selected dataset; alert burden is not detection accuracy</caption><thead><tr><th>Research model</th><th>Validation alerts</th><th>Test alerts</th><th>Unlabeled alerts</th><th>Known exercise tuple recall</th></tr></thead><tbody>{modelKeys.map(key => {
        const method = dataset.methods[key]
        return <tr key={key}><td><strong>{modelNames[key]}</strong></td><td>{rate(method.threshold.validation_alert_fraction, method.threshold.validation_events)}<small>{count(method.threshold.validation_alerts)} / {count(method.threshold.validation_events)} validation events</small><small>{method.threshold.minimum_score === null ? 'Disabled: validation tie exceeds alert budget' : 'Threshold fitted before test'}</small></td><td>{rate(method.test_alert_fraction, test.events)}<small>{count(method.test_alerts)} / {count(test.events)} test events</small></td><td>{rate(method.alert_fraction_over_unlabeled, test.unlabeled_events)}<small>{count(method.unlabeled_alerts)} / {count(test.unlabeled_events)} unlabeled events</small></td><td>{eligible && method.known_redteam_tuple_recall !== null && method.known_redteam_recalled_unique_tuples !== null ? <>{percent(method.known_redteam_tuple_recall)}<small>{count(method.known_redteam_recalled_unique_tuples)} / {count(knownTuples as number)} known test exercise tuples</small></> : <><strong>Not estimable</strong><small>{dataset.labels.available ? 'No eligible test exercise tuples' : 'No attack labels in this dataset'}</small></>}</td></tr>
      })}</tbody></table></div>
      <p className="security-note">Unlabeled events have no matching exercise label; they are not established benign events. Alert burden measures workload. These novelty scores are not calibrated attack probabilities, and the older source/destination experiment below uses different observables.</p>
      <details className="protocol-extra"><summary>Cold-start and familiarity diagnostics</summary><p className="security-note">Strata use strictly prior lifetime history shared by all three models. A zero novelty score is not proof of benign behavior; smoothing or decay does not itself establish better detection.</p><div className="table-wrap"><table className="comparison-table real-auth-model-strata"><caption>Held-out test strata; zero scores and mean scores describe model behavior</caption><thead><tr><th>Test stratum</th><th>Research model</th><th>Events</th><th>Unlabeled alerts</th><th>Zero scores</th><th>Mean score</th></tr></thead><tbody>{strataKeys.flatMap(stratum => modelKeys.map(model => { const group = dataset.test_strata[stratum]; const result = group.methods[model]; return <tr key={`${stratum}-${model}`}><td>{strataNames[stratum]}</td><td>{modelNames[model]}</td><td>{count(group.events)}</td><td>{rate(result.alert_fraction_over_unlabeled, group.unlabeled_events)}<small>{count(result.unlabeled_alerts)} / {count(group.unlabeled_events)} unlabeled events</small></td><td>{count(result.zero_scores)} / {count(group.events)}</td><td>{result.mean_score === null ? 'Not estimable' : result.mean_score.toFixed(3)}</td></tr> }))}</tbody></table></div></details>
      <details className="protocol-extra"><summary>Frozen protocol, source provenance and limitations</summary><pre>{JSON.stringify({ protocol: report.protocol, protocol_sha256: report.protocol_sha256, protocol_frozen_at_utc: report.protocol_frozen_at_utc, source: dataset.source, partition_cutoffs: dataset.partition_cutoffs }, null, 2)}</pre><ul>{report.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details>
    </>}
  </section>
}
