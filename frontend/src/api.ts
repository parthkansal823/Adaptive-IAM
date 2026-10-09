export interface Identity {
  id: string
  name: string
  role: string
  department: string
  password?: string
}

export interface Resource {
  id: string
  name: string
  description: string
  sensitivity: string
  owner_id: string
  max_duration_hours: number
}

export interface Context {
  known_device: boolean
  known_location: boolean
  vpn: boolean
  failed_attempts: number
  hour: number
  login_velocity: number
  account_age_days: number
  travel_distance_km: number
}

export interface Risk {
  score: number
  tier: 'low' | 'medium' | 'high'
  action: string
  signals: { label: string; impact: 'positive' | 'negative' | 'neutral'; value: string | number | boolean }[]
  components: Record<string, number>
  latency_ms: number
}

export interface Bootstrap {
  demo_mode: boolean
  users: Identity[]
  resources: Resource[]
  reviewer_weights: Record<string, number>
  risk_thresholds: { low: number; high: number }
  capabilities: Record<string, unknown>
}

export interface AuthResult {
  status: 'authenticated' | 'mfa_required' | 'blocked'
  risk: Risk
  token?: string
  user?: Identity
  challenge_id?: string
  demo_code?: string
  expires_at?: string
}

export interface Vote {
  reviewer_id: string
  reviewer_name: string
  approve: boolean
  weight: number
  comment: string
  created_at: string
}

export interface AccessRequest {
  id: string
  requester_id: string
  requester_name: string
  resource_id: string
  resource_name: string
  justification: string
  duration_hours: number
  status: 'pending' | 'approved' | 'denied' | 'expired'
  created_at: string
  expires_at: string | null
  risk: Risk
  nlp: { label: string; confidence: number; engine: string; explanation: string }
  reviewers: { id: string; name: string; weight: number; is_owner: boolean }[]
  votes: Vote[]
  consensus: { approval_weight: number; total_weight: number; cast_weight: number; quorum_required: number; quorum_reached: boolean }
  reviewer_selection: { engine: string; reason: string }
  can_vote: boolean
}

export interface Grant {
  id: string
  request_id: string
  user_id: string
  user_name: string
  resource_id: string
  resource_name: string
  scope: string
  created_at: string
  expires_at: string
  status: 'active' | 'expired'
  blockchain?: { required: boolean; status: 'disabled' | 'pending' | 'confirmed' | 'failed'; transaction_hash?: string }
}

export interface ChainStatus {
  enabled: boolean
  connected: boolean
  ready: boolean
  chain_id: number | null
  contract_address: string | null
  audit_count: number
  head_hash: string
  local_audit_count: number
  pending_audit_events: number
  pending_grants: number
  error?: string
  limitation: string
  synced_audit_events?: number
  synced_grants?: number
  receipts?: { kind: string; local_id: string; transaction_hash: string; block_number: number }[]
  errors?: { kind: string; local_id: string; message: string }[]
}

export interface ResourceAccess {
  allowed: boolean
  resource_id: string
  resource_name: string
  scope: string | null
  expires_at?: string
  reason: string
  content: { title: string; records: unknown[] } | null
}

export interface AuditEvent {
  id: string
  timestamp: string
  event_type: string
  actor_id: string
  actor_name: string
  payload: Record<string, unknown>
  previous_hash: string
  hash: string
}

export interface Overview {
  stats: { pending_requests: number; active_grants: number; audit_events: number; review_queue: number; authentication_events: number }
  risk_distribution: { low: number; medium: number; high: number }
  recent_events: AuditEvent[]
  recent_requests: AccessRequest[]
  model: { name: string; version: string; synthetic: boolean }
  capabilities: Record<string, unknown>
}

export interface Verification {
  valid: boolean
  checked_events: number
  head_hash: string
  broken_at?: string
  ledger_type: string
  limitation: string
}

export interface Metrics {
  accuracy: number
  precision?: number
  recall?: number
  f1?: number
  roc_auc?: number
  brier_score?: number
  false_positive_rate?: number
  false_negative_rate?: number
  confusion_matrix?: number[][] | { true_negative: number; false_positive: number; false_negative: number; true_positive: number }
  [key: string]: unknown
}

export interface Evaluation {
  dataset: Record<string, unknown>
  baseline: Record<string, unknown>
  improved: Record<string, unknown>
  nlp?: Record<string, unknown>
  limitations?: string[]
  [key: string]: unknown
}

export interface ConnectedApp {
  client_id: string
  name: string
  client_type: 'public' | 'confidential'
  redirect_uris: string[]
  scopes: string[]
  resource_ids: string[]
  created_at: string
  active: boolean
  client_secret?: string
}

export interface AppRegistry {
  items: ConnectedApp[]
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  jwks_uri: string
  revocation_endpoint: string
}

export interface AuthorizationPacket {
  request_id: string
  app: { name: string; client_id: string }
  scopes: string[]
  resources: Resource[]
  expires_at: string
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

export async function api<T>(path: string, token?: string | null, body?: unknown, method?: 'GET' | 'POST' | 'DELETE'): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api${path}`, {
      method: method || (body === undefined ? 'GET' : 'POST'),
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  } catch {
    throw new ApiError('The API could not be reached. Start the backend and retry.', 0)
  }
  let data: unknown
  try { data = await response.json() } catch {
    throw new ApiError('The API returned an unreadable response. Check that the backend is running on port 8000.', response.status)
  }
  if (!response.ok) {
    const detail = (data as { detail?: unknown }).detail
    const message = typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map((item: { msg?: string }) => item.msg || 'Invalid input').join('. ') : 'The request could not be completed.'
    throw new ApiError(message, response.status)
  }
  return data as T
}
