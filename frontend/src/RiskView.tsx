import { useState } from 'react'
import type { CSSProperties } from 'react'
import type { Context, Risk } from './api'
import { actionLabel, Badge, defaultContext, Icon, PageTitle, PanelTitle, percent, presets, RiskWave } from './components'

export function RiskView({ risk, onAssess, busy, thresholds }: { risk: Risk | null; onAssess: (context: Context) => Promise<boolean>; busy: boolean; thresholds?: { low: number; high: number } }) {
  const [context, setContext] = useState<Context>({ ...defaultContext })
  const [preset, setPreset] = useState('usual')
  const [hasRun, setHasRun] = useState(false)
  const update = <K extends keyof Context>(key: K, value: Context[K]) => { setContext(previous => ({ ...previous, [key]: value })); setPreset('custom'); setHasRun(false) }
  const selectPreset = (id: string) => { const selected = presets.find(item => item.id === id)!; setPreset(id); setContext({ ...selected.context }); setHasRun(false) }
  const numeric: { key: keyof Pick<Context, 'hour' | 'failed_attempts' | 'login_velocity' | 'account_age_days' | 'travel_distance_km'>; label: string; hint: string; min: number; max: number; step: number }[] = [
    { key: 'hour', label: 'Local hour', hint: 'Hour of this sign-in (0–23)', min: 0, max: 23, step: 1 },
    { key: 'failed_attempts', label: 'Failed attempts', hint: 'Recent failed sign-ins', min: 0, max: 20, step: 1 },
    { key: 'login_velocity', label: 'Sign-in velocity', hint: 'Sign-ins in the recent window', min: 0, max: 30, step: 1 },
    { key: 'account_age_days', label: 'Account age', hint: 'Days since account creation', min: 0, max: 3650, step: 1 },
    { key: 'travel_distance_km', label: 'Distance traveled', hint: 'Kilometers since prior location', min: 0, max: 20000, step: 1 },
  ]
  return <>
    <PageTitle title="The context behind the decision." description="Change a sign-in scenario and inspect the model's actual response." action={<span className="quiet-tag"><Icon name="research" size={15} /> Synthetic research model</span>} />
    <div className="preset-switch" role="group" aria-label="Risk scenario presets">{presets.map(item => <button key={item.id} className={preset === item.id ? 'selected' : ''} aria-pressed={preset === item.id} onClick={() => selectPreset(item.id)}>{item.name}</button>)}</div>
    {thresholds && <p className="threshold-note">Current policy: allow below {(thresholds.low * 100).toFixed(1)}%, verify from {(thresholds.low * 100).toFixed(1)}% to {(thresholds.high * 100).toFixed(1)}%, and block at {(thresholds.high * 100).toFixed(1)}%.</p>}
    <div className="risk-layout">
      <section className="panel context-panel">
        <PanelTitle title="Sign-in context" description={presets.find(item => item.id === preset)?.description || 'A custom combination of contextual signals.'} />
        <form onSubmit={async event => { event.preventDefault(); const success = await onAssess(context); setHasRun(success) }}>
          <div className="boolean-fields">{([{ key: 'known_device', title: 'Familiar device', detail: 'Recognized by the account' }, { key: 'known_location', title: 'Familiar location', detail: 'Matches usual location' }, { key: 'vpn', title: 'VPN connection', detail: 'Connection uses a VPN' }] as const).map(item => <label className="toggle-field" key={item.key}><span><strong>{item.title}</strong><small>{item.detail}</small></span><input type="checkbox" checked={context[item.key]} onChange={event => update(item.key, event.target.checked)} /><span className="toggle-track" aria-hidden="true" /></label>)}</div>
          <div className="numeric-fields">{numeric.map(item => <label className={`field ${item.key === 'travel_distance_km' ? 'field-full' : ''}`} key={item.key}><span>{item.label}</span><input type="number" min={item.min} max={item.max} step={item.step} required value={context[item.key]} onChange={event => update(item.key, Number(event.target.value))} /><small>{item.hint}</small></label>)}</div>
          <div className="form-footer"><span>Changes take effect when you run a check.</span><button className="button primary" disabled={busy} type="submit"><Icon name="risk" size={18} />{busy ? 'Assessing…' : 'Run assessment'}</button></div>
        </form>
      </section>
      <section className="panel assessment-panel">
        <PanelTitle title="Assessment" action={risk && <Badge status={risk.tier}>{risk.tier} risk</Badge>} />
        {risk ? <>
          <div className={`assessment-score score-${risk.tier}`}><div className="score-ring" style={{ '--score': risk.score } as CSSProperties}><div><strong>{(risk.score * 100).toFixed(1)}<span>%</span></strong><small>Risk probability</small></div></div><div className="policy-result"><span className="eyebrow">Policy response</span><h3>{actionLabel(risk.action)}</h3><p>{risk.tier === 'low' ? 'Context meets the low-risk sign-in policy.' : risk.tier === 'medium' ? 'Verify identity before starting a session.' : 'Context exceeds the high-risk threshold.'}</p></div></div>
          {!hasRun && <p className="inline-note">Showing the last assessment. Run a check to evaluate these inputs.</p>}
          <div className="model-agreement"><span>Model probabilities</span><span>{risk.latency_ms.toFixed(2)} ms</span></div><RiskWave risk={risk} />
          <div className="component-values"><div><span>Logistic regression</span><strong>{percent(risk.components.logistic_regression ?? 0)}</strong></div><div><span>Random forest</span><strong>{percent(risk.components.random_forest ?? 0)}</strong></div><div><span>Calibrated ensemble</span><strong>{percent(risk.components.calibrated ?? risk.score)}</strong></div></div>
          <h3 className="subheading">Context signals</h3><div className="signal-list">{risk.signals.map((signal, index) => <div key={`${signal.label}-${index}`}><span className={`signal-dot signal-${signal.impact}`} /><span>{signal.label}</span><strong>{typeof signal.value === 'boolean' ? signal.value ? 'Yes' : 'No' : signal.value}</strong></div>)}</div>
        </> : <div className="assessment-empty"><Icon name="risk" size={38} /><h3>A decision starts with context.</h3><p>Choose a scenario, then run an assessment to see risk, model agreement, and policy response.</p><RiskWave risk={null} /></div>}
      </section>
    </div>
    <div className="research-footnote"><Icon name="research" size={18} /><p>The model is trained on generated scenarios. Its probability describes this research dataset; validate on real, consented telemetry before making operational access decisions.</p></div>
  </>
}

