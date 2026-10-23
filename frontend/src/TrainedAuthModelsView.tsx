import { useEffect, useState } from 'react'
import { api } from './api'
import type { RealAuthTrainingStudy } from './api'
import { Badge, Empty, Icon, PanelTitle, percent } from './components'

const names = { isolation_forest: 'Isolation Forest · fixed', isolation_forest_tuned: 'Isolation Forest · validation selected', lifetime_user_computer: 'Lifetime frequency control', hierarchical_static: 'Smoothed static', hierarchical_decay: 'Smoothed with decay' }
const methods = Object.keys(names) as (keyof typeof names)[]
const datasets: Record<string, string> = { lanl2015_retrospective: 'LANL 2015 · retrospective exercise sample', lanl2014_month00: 'LANL 2014 · first monthly slice', lanl2014_month01: 'LANL 2014 · later monthly slice' }
const partitions = ['warmup', 'validation', 'test'] as const
const count = (value: number) => value.toLocaleString('en-US')
const rate = (value: number | null, denominator: number) => value !== null && Number.isFinite(value) && denominator > 0 ? `${(value * 100).toFixed(3)}%` : 'Not estimable'

export function TrainedAuthModelsView() {
  const [report, setReport] = useState<RealAuthTrainingStudy | null>(null)
  const [selected, setSelected] = useState('lanl2015_retrospective')
  const [attempt, setAttempt] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    setLoading(true); setError('')
    api<RealAuthTrainingStudy>('/research/real-auth-training').then(value => {
      if (!active) return
      if (value.schema_version !== 'real-auth-training-v1' || value.synthetic !== false || value.status !== 'measured' || !Array.isArray(value.protocol?.features) || !Array.isArray(value.limitations) || !value.datasets || !Object.keys(value.datasets).length || !Object.values(value.datasets).every(dataset => dataset.source && dataset.scan && dataset.labels && Array.isArray(dataset.training?.tuning?.candidates) && dataset.training.tuning.selected_params && methods.every(key => dataset.methods?.[key]?.threshold) && partitions.every(key => dataset.partitions?.[key]))) throw new Error('The API returned an unsupported training study.')
      setReport(value)
      setSelected(previous => previous in value.datasets ? previous : Object.keys(value.datasets)[0])
    }).catch(failure => { if (active) { setReport(null); setError(failure instanceof Error ? failure.message : 'The training study could not be loaded.') } }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [attempt])
  const download = () => {
    if (!report) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a'); link.href = url; link.download = 'adaptive-iam-real-auth-training.json'; link.click(); URL.revokeObjectURL(url)
  }
  const dataset = report?.datasets[selected]
  const test = dataset?.partitions.test
  const training = dataset?.training
  const known = test?.known_redteam_unique_tuples
  const eligible = dataset?.labels.available === true && dataset.labels.detection_metrics_eligible === true && typeof known === 'number' && known > 0
  return <section className="panel comparison-panel real-auth-training">
    <PanelTitle title="Trained models on real authentication" description="Actual warmup fits and chronological validation search, alongside fixed count controls." action={<Badge status="neutral">Offline research</Badge>} />
    {!report || !dataset || !test || !training ? <Empty icon="research" title={loading ? 'Loading the trained-model study…' : 'The trained-model study is unavailable.'} action={<button className="button secondary" disabled={loading} onClick={() => setAttempt(value => value + 1)}>Retry training study</button>}>{error || 'Reading measured aggregate evidence from the API.'}</Empty> : <>
      <p className="security-note">These historic logs come from one institution. Forests learn unusual behavior without attack labels. Validation selects budget stability, not best attack accuracy; every test result and regression remains visible. This report changes no live access policy.</p>
      <div className="request-form-top"><label className="field"><span>Training study dataset</span><select value={selected} onChange={event => setSelected(event.target.value)}>{Object.keys(report.datasets).map(key => <option key={key} value={key}>{datasets[key] || key.replaceAll('_', ' ')}</option>)}</select></label><button className="button secondary" onClick={download}><Icon name="download" size={16} />Export training study</button></div>
      <p className="security-note training-study-eligibility"><strong>{dataset.labels.available ? eligible ? 'Known exercise recall is eligible for this sample.' : 'Known exercise recall is not estimable for this sample.' : 'No attack labels are available. This dataset measures alert burden only.'}</strong> {dataset.labels.interpretation} {dataset.source.retrospective && 'Previously inspected data: retrospective diagnostic, not untouched confirmation.'}</p>
      <dl className="protocol-list">
        <div><dt>Observed source</dt><dd>{dataset.source.release} · {count(dataset.scan.selected_rows)} usable events</dd></div>
        <div><dt>Actual fit</dt><dd>{count(training.reservoir_events)} reservoir rows from {count(training.warmup_events_seen)} warmup events · {training.fitted_feature_dimensions} features · {training.fitted_tree_count} trees per forest</dd></div>
        <div><dt>Validation-selected parameters</dt><dd>max_samples={training.tuning.selected_params.max_samples}, max_features={training.tuning.selected_params.max_features}{training.tuning.fallback_used && ' · fixed fallback used'}</dd></div>
        <div><dt>Search objective</dt><dd>{training.tuning.objective}</dd></div>
        <div><dt>Authentication input SHA-256</dt><dd><code>{dataset.source.auth_sha256}</code></dd></div>
        <div><dt>Selected fitted model SHA-256</dt><dd><code>{training.tuning.selected_model_sha256}</code></dd></div>
      </dl>
      <div className="table-wrap"><table className="comparison-table"><caption>Whole-source-second chronological partitions; only warmup supplies fitted rows</caption><thead><tr><th>Partition</th><th>Events</th><th>Unlabeled events</th><th>Known exercise tuples</th></tr></thead><tbody>{partitions.map(key => { const part = dataset.partitions[key]; return <tr key={key}><td>{key}</td><td>{count(part.events)}</td><td>{count(part.unlabeled_events)}</td><td>{dataset.labels.available && part.known_redteam_unique_tuples !== null ? count(part.known_redteam_unique_tuples) : 'No labels'}</td></tr> })}</tbody></table></div>
      <div className="table-wrap"><table className="comparison-table real-auth-training-methods"><caption>All five test methods; alert burden is not a false-positive rate</caption><thead><tr><th>Research model</th><th>Validation alerts</th><th>Test alerts</th><th>Unlabeled alerts</th><th>Known exercise tuple recall</th></tr></thead><tbody>{methods.map(key => { const method = dataset.methods[key]; return <tr key={key}><td><strong>{names[key]}</strong></td><td>{rate(method.threshold.validation_alert_fraction, method.threshold.validation_events)}<small>{count(method.threshold.validation_alerts)} / {count(method.threshold.validation_events)} validation events</small><small>{method.threshold.minimum_score === null ? 'Disabled: validation tie exceeds budget' : 'Threshold frozen before test'}</small></td><td>{rate(method.test_alert_fraction, test.events)}<small>{count(method.test_alerts)} / {count(test.events)} test events</small></td><td>{rate(method.alert_fraction_over_unlabeled, test.unlabeled_events)}<small>{count(method.unlabeled_alerts)} / {count(test.unlabeled_events)} unlabeled events</small></td><td>{eligible && method.known_redteam_tuple_recall !== null && method.known_redteam_recalled_unique_tuples !== null ? <>{percent(method.known_redteam_tuple_recall)}<small>{count(method.known_redteam_recalled_unique_tuples)} / {count(known as number)} known test exercise tuples</small></> : <><strong>Not estimable</strong><small>{dataset.labels.available ? 'No eligible test exercise tuples' : 'No attack labels in this dataset'}</small></>}</td></tr> })}</tbody></table></div>
      <p className="security-note">Unlabeled events are not confirmed benign. Both 2014 slices have higher selected-forest workload than their fixed controls; no detection benefit is established there. Test workload need not meet the validation budget.</p>
      <details className="protocol-extra"><summary>Validation candidates and learned features</summary><p>{training.tuning.tool} · {training.tuning.candidates.length} configurations. Selected candidate: {training.tuning.selected_candidate_id}. All candidates share one warmup reservoir; final threshold recalibration uses validation only.</p><div className="table-wrap"><table className="comparison-table training-candidates"><caption>Later-validation alert workload; no test-based selection</caption><thead><tr><th>Candidate</th><th>Samples / features</th><th>Selection alerts</th><th>Eligible</th></tr></thead><tbody>{training.tuning.candidates.map(candidate => <tr key={candidate.id}><td>{candidate.id}{candidate.id === training.tuning.selected_candidate_id && ' · selected'}</td><td>{candidate.params.max_samples} / {candidate.params.max_features}</td><td>{rate(candidate.selection_alert_fraction, candidate.selection_events)}</td><td>{candidate.eligible ? 'Yes' : 'No'}</td></tr>)}</tbody></table></div><ul>{report.protocol.features.map(feature => <li key={feature}>{feature.replaceAll('_', ' ')}</li>)}</ul></details>
      <details className="protocol-extra"><summary>Frozen training protocol, provenance and limitations</summary><pre>{JSON.stringify({ protocol: report.protocol, protocol_sha256: report.protocol_sha256, source: dataset.source, training, implementation: report.implementation, execution_commitment: report.execution_commitment, execution_dependency_manifest: report.execution_dependency_manifest, post_measurement_compatibility_revision: report.post_measurement_compatibility_revision }, null, 2)}</pre><ul>{report.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></details>
    </>}
  </section>
}
