import type { ReactNode } from 'react'
import type { AuditEvent, Context, Risk } from './api'

export type IconName = 'overview' | 'risk' | 'access' | 'audit' | 'research' | 'sun' | 'moon' | 'arrow' | 'refresh' | 'check' | 'close' | 'shield' | 'logout' | 'plus' | 'chevron' | 'lock' | 'clock' | 'download' | 'user' | 'signal'

const paths: Record<IconName, ReactNode> = {
  overview: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>,
  risk: <><path d="M3 12h4l3-7 4 14 3-7h4" /><path d="M4 4v2M20 18v2" /></>,
  access: <><rect x="3" y="4" width="18" height="16" rx="3" /><circle cx="8" cy="10" r="2" /><path d="M5 16c1-3 5-3 6 0M14 9h4M14 13h4" /></>,
  audit: <><path d="M8 3h8l4 4v14H4V3h4M14 3v5h6M8 12h8M8 16h5" /></>,
  research: <><path d="M9 3h6M10 3v6L4 19c-.5 1 .5 2 1.5 2h13c1 0 2-1 1.5-2L14 9V3M7 15h10" /><path d="M10 18h.01M14 16h.01" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1 1M18 18l1 1M5 19l1-1M18 6l1-1" /></>,
  moon: <path d="M20 14A8.5 8.5 0 0 1 10 4 8.5 8.5 0 1 0 20 14Z" />,
  arrow: <path d="M5 12h14M14 7l5 5-5 5" />,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" /><path d="m8 12 3 3 5-6" /></>,
  logout: <><path d="M10 4H4v16h6M10 12h11M17 8l4 4-4 4" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  chevron: <path d="m9 5 7 7-7 7" />,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  download: <><path d="M12 3v12m-4-4 4 4 4-4M4 17v4h16v-4" /></>,
  user: <><circle cx="12" cy="8" r="4" /><path d="M4 21v-3a8 8 0 0 1 16 0v3" /></>,
  signal: <><path d="M5 17v3M10 12v8M15 8v12M20 3v17" /></>,
}

export function Icon({ name, size = 20 }: { name: IconName; size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>
}

export function Brand({ compact = false }: { compact?: boolean }) {
  return <div className="brand"><span className="brand-mark"><svg width="27" height="29" viewBox="0 0 27 29" fill="none" aria-hidden="true"><path d="m13.5 2 11 6.5v13L13.5 28l-11-6.5v-13L13.5 2Z" stroke="currentColor" strokeWidth="1.4" /><path d="m7 19 6.5-11 6.5 11M10 15h7" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></svg></span><span>Adaptive IAM{!compact && <small>Identity, in context</small>}</span></div>
}

export function Badge({ status, children }: { status: string; children?: ReactNode }) {
  return <span className={`badge badge-${status}`}><span className="badge-dot" />{children || status.replaceAll('_', ' ')}</span>
}

export function Empty({ icon = 'lock', title, children, action }: { icon?: IconName; title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="empty-state"><span className="empty-icon"><Icon name={icon} size={25} /></span><h3>{title}</h3><p>{children}</p>{action}</div>
}

export function PageTitle({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return <div className="page-heading"><div><h1>{title}</h1><p>{description}</p></div>{action && <div className="page-heading-action">{action}</div>}</div>
}

export function PanelTitle({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return <div className="panel-heading"><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{action}</div>
}

export function formatDate(value?: string | null, options?: Intl.DateTimeFormatOptions) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(undefined, options || { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export function initials(name: string) { return name.split(' ').map(part => part[0]).slice(0, 2).join('') }
export function percent(value: number) { return `${(value * 100).toFixed(1)}%` }
export function actionLabel(action: string) { return ({ allow: 'Allow sign-in', mfa: 'Verify with MFA', require_mfa: 'Verify with MFA', block: 'Block sign-in' } as Record<string, string>)[action] || action.replaceAll('_', ' ') }

export const defaultContext: Context = { known_device: true, known_location: true, vpn: false, failed_attempts: 0, hour: 10, login_velocity: 1, account_age_days: 365, travel_distance_km: 0 }
export const presets = [
  { id: 'usual', name: 'Usual sign-in', description: 'A familiar device in a familiar location.', context: defaultContext },
  { id: 'device', name: 'New device', description: 'An unfamiliar device with otherwise usual behavior.', context: { ...defaultContext, known_device: false } },
  { id: 'travel', name: 'Travel', description: 'A familiar device after a large location change.', context: { ...defaultContext, known_location: false, login_velocity: 2, travel_distance_km: 6500 } },
  { id: 'attack', name: 'Suspicious activity', description: 'New device, rapid retries, and a large location change.', context: { known_device: false, known_location: false, vpn: true, failed_attempts: 8, hour: 2, login_velocity: 20, account_age_days: 1, travel_distance_km: 12000 } },
  { id: 'location', name: 'New location', description: 'A familiar device signs in from an unfamiliar location.', context: { ...defaultContext, known_location: false, travel_distance_km: 1800 } },
  { id: 'retries', name: 'Rapid retries', description: 'Repeated failed attempts and a burst of sign-in activity.', context: { ...defaultContext, failed_attempts: 6, login_velocity: 18 } },
  { id: 'vpn', name: 'VPN connection', description: 'A familiar identity connects through a VPN.', context: { ...defaultContext, vpn: true } },
  { id: 'night', name: 'After hours', description: 'An otherwise familiar sign-in at 02:00 local time.', context: { ...defaultContext, hour: 2 } },
  { id: 'new-account', name: 'New account', description: 'An account created one day ago, with familiar device and location.', context: { ...defaultContext, account_age_days: 1 } },
]

export function RiskWave({ risk }: { risk: Risk | null }) {
  const values = [risk?.components.logistic_regression, risk?.components.random_forest, risk?.components.calibrated ?? risk?.score]
  const usable = values.every(value => typeof value === 'number')
  const points = values.map((value, i) => `${24 + i * 104},${68 - (value || 0) * 53}`).join(' ')
  return <div className="risk-wave"><svg viewBox="0 0 256 92" role="img" aria-label={usable ? `Model probabilities: logistic regression ${percent(values[0]!)}, random forest ${percent(values[1]!)}, calibrated ensemble ${percent(values[2]!)}` : 'Run an assessment to see model probabilities'}>
    <path className="wave-grid" d="M10 15h238M10 42h238M10 69h238" />
    <path className="wave-grid" d="M24 9v64M128 9v64M232 9v64" />
    {usable ? <><polyline className="wave-line" points={points} />{values.map((value, i) => <circle key={i} className="wave-point" cx={24 + i * 104} cy={68 - value! * 53} r="4" />)}</> : <path className="wave-placeholder" d="M24 55h208" />}
    <text x="24" y="88" textAnchor="middle">LR</text><text x="128" y="88" textAnchor="middle">RF</text><text x="232" y="88" textAnchor="middle">Ensemble</text>
  </svg></div>
}

export function EventRows({ events, dense = false }: { events: AuditEvent[]; dense?: boolean }) {
  return <div className={`event-list ${dense ? 'dense' : ''}`}>{events.map(event => <div className="event-row" key={event.id}><span className={`event-icon ${event.event_type.includes('den') || event.event_type.includes('block') ? 'event-alert' : ''}`}><Icon name={event.event_type.includes('auth') || event.event_type.includes('login') ? 'shield' : event.event_type.includes('vote') ? 'check' : 'access'} size={17} /></span><div className="event-copy"><strong>{event.event_type.replaceAll('_', ' ')}</strong><span>{event.actor_name || event.actor_id || 'System'}</span></div><time dateTime={event.timestamp}>{formatDate(event.timestamp)}</time></div>)}</div>
}
