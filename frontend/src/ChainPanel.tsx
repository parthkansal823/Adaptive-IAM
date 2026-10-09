import { useCallback, useEffect, useState } from 'react'
import { api } from './api'
import type { ChainStatus, Identity } from './api'
import { Badge, Icon, PanelTitle } from './components'

export function ChainPanel({ token, user }: { token: string | null; user: Identity }) {
  const [status, setStatus] = useState<ChainStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const load = useCallback(async () => {
    if (!token) return
    setBusy(true); setError('')
    try { setStatus(await api<ChainStatus>('/blockchain/status', token)) }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'The blockchain status could not be read.') }
    finally { setBusy(false) }
  }, [token])
  useEffect(() => { void load() }, [load])
  const sync = async () => {
    setBusy(true); setError(''); setMessage('')
    try {
      const result = await api<ChainStatus>('/blockchain/sync', token, {})
      setStatus(result)
      setMessage(`${result.synced_audit_events ?? 0} audit events and ${result.synced_grants ?? 0} grants anchored on-chain.`)
    } catch (failure) { setError(failure instanceof Error ? failure.message : 'On-chain synchronization failed.') }
    finally { setBusy(false) }
  }
  return <section className="panel chain-panel"><PanelTitle title="On-chain anchoring" description="Actual contract confirmations for event hashes and timed access grants." action={<div className="chain-actions"><button className="icon-button" onClick={load} disabled={busy} aria-label="Refresh blockchain status"><Icon name="refresh" size={17} /></button>{user.role === 'security_reviewer' && <button className="button secondary" disabled={busy || !status?.ready} onClick={sync}>{busy ? 'Connecting…' : 'Sync to chain'}</button>}</div>} />
    {error && <div className="chain-error" role="alert">{error}</div>}{message && <div className="chain-message" role="status">{message}</div>}
    {status ? <><div className="chain-status-heading"><Badge status={!status.enabled ? 'expired' : status.ready ? 'active' : 'pending'}>{!status.enabled ? 'Disabled' : status.ready ? 'Contract ready' : 'Needs connection'}</Badge>{status.chain_id && <span>Chain {status.chain_id}</span>}{status.error && <span className="text-high">{status.error}</span>}</div>{status.enabled && <><div className="chain-metrics"><div><strong>{status.audit_count}</strong><span>On-chain audit events</span></div><div><strong>{status.pending_audit_events}</strong><span>Events pending</span></div><div><strong>{status.pending_grants}</strong><span>Grants pending</span></div></div><dl className="chain-contract"><div><dt>Contract</dt><dd><code>{status.contract_address || 'Not configured'}</code></dd></div><div><dt>On-chain head</dt><dd><code>{status.head_hash || 'No events anchored'}</code></dd></div></dl></>}{status.receipts?.length ? <div className="table-wrap"><table><thead><tr><th>Confirmation</th><th>Transaction</th><th>Block</th></tr></thead><tbody>{status.receipts.map(receipt => <tr key={receipt.transaction_hash}><td>{receipt.kind.replaceAll('_', ' ')}</td><td><code title={receipt.transaction_hash}>{receipt.transaction_hash.slice(0, 14)}…</code></td><td>{receipt.block_number}</td></tr>)}</tbody></table></div> : null}{status.errors?.map((failure, index) => <p key={index} className="chain-error">{failure.kind}: {failure.message}</p>)}<p className="chain-limitation">{status.limitation}</p></> : <p className="chain-limitation">{busy ? 'Reading the configured chain…' : 'Refresh to inspect the configured chain and contract.'}</p>}
  </section>
}
