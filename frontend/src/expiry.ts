import { useEffect, useState } from 'react'
import type { AccessRequest, Grant } from './api'

export function hasExpired(expiresAt: string | null | undefined, now: number) {
  return !!expiresAt && Date.parse(expiresAt) <= now
}

export function requestStatus(request: AccessRequest, now: number): AccessRequest['status'] {
  return request.status === 'pending' && hasExpired(request.expires_at, now) ? 'expired' : request.status
}

export function grantStatus(grant: Grant, now: number): Grant['status'] {
  return grant.status === 'active' && hasExpired(grant.expires_at, now) ? 'expired' : grant.status
}

// Wake at the next server-provided deadline; no API polling or client permission decisions.
export function useExpiryClock(deadlines: (string | null | undefined)[]) {
  const [now, setNow] = useState(Date.now)
  const deadlineKey = deadlines.filter(Boolean).sort().join('|')
  useEffect(() => {
    const timestamps = deadlineKey.split('|').map(value => Date.parse(value)).filter(Number.isFinite)
    let timer: number | undefined
    const update = () => {
      window.clearTimeout(timer)
      const current = Date.now()
      setNow(previous => Math.max(previous, current))
      const next = Math.min(...timestamps.filter(timestamp => timestamp > current))
      if (Number.isFinite(next)) timer = window.setTimeout(update, Math.min(next - current + 1, 2_147_483_647))
    }
    const visible = () => { if (document.visibilityState === 'visible') update() }
    update()
    document.addEventListener('visibilitychange', visible)
    window.addEventListener('focus', update)
    return () => { window.clearTimeout(timer); document.removeEventListener('visibilitychange', visible); window.removeEventListener('focus', update) }
  }, [deadlineKey])
  return Math.max(now, Date.now())
}
