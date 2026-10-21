import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { api } from './api'
import { Badge, Empty, Icon, PanelTitle } from './components'

interface Batch {
  id: number
  start_sequence: number
  end_sequence: number
  event_count: number
  root: string
  previous_root: string
  audit_end_hash: string
}
interface BatchList { items: Batch[]; checked_events: number; sealed_end: number; unsealed_events: number; batch_count: number; anchor_checked: false }
const digest = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)
const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0
const nonnegative = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
const validBatch = (batch: Batch) => batch && positive(batch.id) && positive(batch.start_sequence) && positive(batch.end_sequence) && batch.end_sequence - batch.start_sequence + 1 === batch.event_count && batch.event_count >= 1 && batch.event_count <= 256 && digest(batch.root) && digest(batch.previous_root) && digest(batch.audit_end_hash)

export function AuditProofsPanel({ token }: { token: string }) {
  const [listing, setListing] = useState<BatchList | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [revision, setRevision] = useState(0)
  const [size, setSize] = useState('256')
  const [sequence, setSequence] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const alive = useRef(true)
  const currentToken = useRef(token)
  currentToken.current = token
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const current = (captured: string) => alive.current && currentToken.current === captured

  useEffect(() => {
    let active = true
    setLoading(true); setError('')
    api<BatchList>('/audit/batches', token).then(result => {
      if (!active) return
      if (!Array.isArray(result.items) || !result.items.every(validBatch) || result.anchor_checked !== false || ![result.checked_events, result.sealed_end, result.unsealed_events, result.batch_count].every(nonnegative) || result.sealed_end + result.unsealed_events !== result.checked_events) throw new Error('The API returned an unsupported audit batch response.')
      setListing(result)
      if (result.items.length) setSequence(previous => previous || String(result.items[0].start_sequence))
    }).catch(failure => { if (active) { setListing(null); setError(failure instanceof Error ? failure.message : 'Audit batches could not be read.') } }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [token, revision])

  const seal = async () => {
    const captured = token
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await api<{ batch: Batch; anchor_checked: boolean }>('/audit/batches/seal', captured, { max_events: Number(size) })
      if (!current(captured)) return
      if (!validBatch(result.batch) || result.anchor_checked !== false) throw new Error('The seal response could not be confirmed.')
      setNotice(`Batch ${result.batch.id} sealed locally: events ${result.batch.start_sequence}–${result.batch.end_sequence}. External anchoring has not been checked.`)
      setSequence(String(result.batch.start_sequence)); setRevision(value => value + 1)
    } catch (failure) { if (current(captured)) setError(failure instanceof Error ? failure.message : 'The batch could not be sealed.') }
    finally { if (current(captured)) setBusy(false) }
  }

  const anchor = async (batch: Batch) => {
    const captured = token
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await api<{ batch: Batch; status: string; anchor_checked: boolean; chain_id: number }>(`/audit/batches/${batch.id}/anchor`, captured, {}, 'POST', 120_000)
      if (!current(captured)) return
      if (result.status !== 'anchored' || result.anchor_checked !== true || result.batch?.id !== batch.id || result.batch.root !== batch.root || result.chain_id !== 31337) throw new Error('The live anchor response could not be confirmed.')
      setNotice(`Live anchor checked for batch ${batch.id} on local chain ${result.chain_id}. This result describes the last server check.`)
    } catch (failure) { if (current(captured)) setError(failure instanceof Error ? failure.message : 'The live anchor could not be verified.') }
    finally { if (current(captured)) setBusy(false) }
  }

  const download = async (event: FormEvent) => {
    event.preventDefault()
    const requested = Number(sequence), captured = token
    if (!positive(requested)) { setError('Enter a positive, supported event sequence.'); return }
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await api<{ schema_version: string; batch: Batch; leaf: { sequence: number }; siblings: unknown[]; trust: { external_anchor_checked: boolean } }>(`/audit/proofs/${requested}`, captured)
      if (!current(captured)) return
      if (result.schema_version !== 'audit-inclusion-v1' || !validBatch(result.batch) || result.leaf?.sequence !== requested || !Array.isArray(result.siblings) || result.siblings.length > 8 || result.trust?.external_anchor_checked !== false) throw new Error('The API returned an unsupported inclusion proof.')
      const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }))
      const link = document.createElement('a'); link.href = url; link.download = `adaptive-iam-audit-proof-${requested}.json`; link.click(); URL.revokeObjectURL(url)
      setNotice(`Hash-only proof for event ${requested} exported. Verify it against a root obtained through a trusted channel.`)
    } catch (failure) { if (current(captured)) setError(failure instanceof Error ? failure.message : 'The inclusion proof could not be exported.') }
    finally { if (current(captured)) setBusy(false) }
  }

  const pending = busy || loading
  return <section className="panel audit-proofs-panel">
    <PanelTitle title="Audit inclusion proofs" description="Seal bounded audit ranges and export hash-only evidence for independent verification." action={<Badge status="neutral">Security reviewer</Badge>} />
    <p className="security-note">Sealed batches are local commitments. A portable proof alone does not establish blockchain confirmation. Live anchoring requires configured Web3 and the matching per-event prefix to be synchronized first.</p>
    {error && <div className="chain-error" role="alert">{error}</div>}{notice && <div className="chain-message" role="status">{notice}</div>}
    <div className="request-form-top"><label className="field"><span>Maximum events per batch</span><select value={size} onChange={event => setSize(event.target.value)} disabled={pending}>{[1, 16, 64, 256].map(value => <option key={value} value={value}>{value}</option>)}</select></label><div className="chain-actions"><button className="button secondary" disabled={pending} onClick={() => setRevision(value => value + 1)}>Refresh batches</button><button className="button primary" disabled={pending || !listing?.unsealed_events} onClick={seal}>{busy ? 'Confirming…' : 'Seal audit batch'}</button></div></div>
    {listing ? <><dl className="protocol-list"><div><dt>Verified local events</dt><dd>{listing.checked_events.toLocaleString()}</dd></div><div><dt>Sealed / unsealed events</dt><dd>{listing.sealed_end.toLocaleString()} / {listing.unsealed_events.toLocaleString()}</dd></div><div><dt>Root trust</dt><dd>Local SQLite; external anchor not checked by this listing</dd></div></dl>{listing.items.length ? <div className="table-wrap"><table><caption>Latest locally sealed audit batches</caption><thead><tr><th>Batch</th><th>Event range</th><th>Root</th><th>External check</th></tr></thead><tbody>{listing.items.map(batch => <tr key={batch.id}><td>{batch.id}</td><td>{batch.start_sequence}–{batch.end_sequence} ({batch.event_count})</td><td><code title={batch.root}>{batch.root.slice(0, 14)}…</code></td><td><button className="button secondary" disabled={pending} onClick={() => anchor(batch)}>Check / anchor batch {batch.id}</button></td></tr>)}</tbody></table></div> : <Empty icon="audit" title="No audit batches sealed">Seal an available event range to export inclusion proofs.</Empty>}</> : <p>{loading ? 'Verifying local batches…' : 'Refresh after resolving the reported error.'}</p>}
    <form className="request-form-top" onSubmit={download}><label className="field"><span>Audit event sequence</span><input type="number" min="1" max={Number.MAX_SAFE_INTEGER} step="1" required value={sequence} onChange={event => setSequence(event.target.value)} disabled={pending} /></label><button className="button secondary" type="submit" disabled={pending || !listing?.items.length}><Icon name="download" size={16} />Export inclusion proof</button></form>
    <details className="protocol-extra"><summary>Verify an exported proof</summary><p>Use the offline verifier with an independently obtained expected root. Merkle inclusion binds an event hash to that root; it does not prove that the original event was truthful or authorize resource access.</p><code>.venv/Scripts/python.exe scripts/verify_audit_bundle.py proof.json --expected-root ROOT</code></details>
  </section>
}
