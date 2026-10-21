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
  enrollment_required?: boolean
  session_scope?: 'factor_enrollment'
  session_id?: string
  factor_enrolled?: boolean
  status: 'authenticated' | 'mfa_required' | 'blocked'
  risk: Risk
  token?: string
  user?: Identity
  challenge_id?: string
  demo_code?: string
  expires_at?: string
  methods?: string[]
  verification_method?: string
}

export interface SessionInfo {
  enrollment_required?: boolean
  id?: string
  expires_at: string
  verification_method?: string
  verified_at?: string | null
  fresh_verification?: boolean
  step_up_required?: boolean
  factor_enrolled?: boolean
}

export interface Passkey {
  id: string
  label: string
  created_at: string
  last_used_at: string | null
}

export interface SecurityStatus {
  passkeys_available: boolean
  totp_enabled: boolean
  passkeys: Passkey[]
  recovery_codes_remaining: number
  fresh_verification: boolean
  enrollment_ready?: boolean
  step_up_required: boolean
  session: SessionInfo
  rp_id: string
  origin: string
  demo_mode: boolean
}

export interface ActiveSession {
  id: string
  created_at: string
  expires_at: string
  last_seen_at: string
  verification_method: string | null
  step_up_required: boolean
  current: boolean
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
  status: 'active' | 'expired' | 'revoked'
  can_revoke?: boolean
  blockchain?: { required: boolean; status: 'disabled' | 'pending' | 'confirmed' | 'failed'; transaction_hash?: string }
}

export interface GrantRevocation {
  grant_id: string
  status: 'revoked'
  blockchain: { enabled: boolean; ready: boolean; receipts?: unknown[]; errors?: unknown[] }
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
  organization_id?: string | null
  can_manage?: boolean
}

export interface Organization {
  id: string
  name: string
  role: string
  can_manage: boolean
  members: { user_id: string; name: string; role: string }[]
  resource_ids: string[]
}

export interface DeveloperWorkspace {
  notice?: string
  organizations: Organization[]
  apps: ConnectedApp[]
  available_users: { id: string; name: string }[]
  capabilities: { can_create_organization: boolean; recent_verification_required: boolean }
}

export interface CallbackDiagnostic {
  valid: boolean
  registered: boolean | null
  origin: string | null
  development_only: boolean
  checks: { name: string; passed: boolean; message: string }[]
}

export interface AttackCase {
  id: string
  name: string
  description: string
  category: string
}

export interface LabRun {
  notice?: string
  id: string
  case_id: string
  created_at: string
  mode: string
  risk: Risk
  nlp?: { label: string; confidence: number; engine: string; explanation: string } | null
  stages: { name: string; status: string; detail: string }[]
  checks: { name: string; passed: boolean; detail: string }[]
  human_approval_required: boolean
  grant_created: boolean
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

export interface UncertaintyStudy {
  schema_version: 'uncertainty-study-v1'
  synthetic: true
  alpha: number
  seeds: number[]
  summary: Record<string, Record<string, Record<string, { mean: number; sample_std: number; minimum: number; maximum: number }>>>
  protocol: Record<string, unknown>
  runs: unknown[]
  limitations: string[]
}

export interface LanlStudy {
  schema_version: 'lanl-study-v1'
  evidence_type: 'real_enterprise_authentication_with_exercise_redteam'
  synthetic: false
  source_real_enterprise: true
  source: { kind: string; bounded_auth_prefix: boolean; [key: string]: unknown }
  scan: { source_rows: number; selected_rows: number; source_first_second: number; source_last_second: number }
  partitions: Record<'warmup' | 'validation' | 'test', {
    events: number
    unlabeled_events: number
    matched_auth_rows: number
    known_redteam_unique_tuples: number
    first_second: number
    last_second: number
  }>
  labels: { detection_metrics_eligible: boolean; eligibility_reason: string; unique_redteam_tuples_in_reference: number }
  methods: Record<'new_user_source' | 'new_user_destination' | 'edge_surprise', {
    threshold: { validation_alert_fraction: number; [key: string]: unknown }
    test_alerts: number
    test_alert_fraction: number
    unlabeled_alerts: number
    alert_fraction_over_unlabeled: number | null
    known_redteam_alerted_auth_rows: number | null
    known_redteam_recalled_unique_tuples: number | null
    known_redteam_tuple_recall: number | null
  }>
  limitations: string[]
  [key: string]: unknown
}

export interface RealAuthModelsStudy {
  schema_version: 'real-auth-model-study-v1'
  synthetic: false
  protocol: Record<string, unknown>
  protocol_sha256?: string
  protocol_frozen_at_utc?: string
  datasets: Record<string, {
    source: { kind: string; auth_sha256: string; retrospective: boolean; bounded_prefix: boolean; source_url?: string; provenance?: Record<string, unknown>; [key: string]: unknown }
    scan: { source_rows: number; selected_rows: number; source_first_second: number; source_last_second: number }
    partition_cutoffs: Record<string, number>
    partitions: Record<'warmup' | 'validation' | 'test', { events: number; first_second: number | null; last_second: number | null; matched_auth_rows: number; known_redteam_unique_tuples: number | null; unlabeled_events: number }>
    labels: { available: boolean; detection_metrics_eligible: boolean; interpretation: string }
    methods: Record<'lifetime_user_computer' | 'hierarchical_static' | 'hierarchical_decay', {
      threshold: { minimum_score: number | null; validation_alerts: number; validation_events: number; validation_alert_fraction: number }
      test_alerts: number
      test_alert_fraction: number
      unlabeled_alerts: number
      alert_fraction_over_unlabeled: number | null
      known_redteam_alerted_auth_rows: number | null
      known_redteam_recalled_unique_tuples: number | null
      known_redteam_tuple_recall: number | null
    }>
    test_strata: Record<'cold_user' | 'known_user_new_computer' | 'familiar_user_computer', {
      events: number
      unlabeled_events: number
      matched_auth_rows: number
      known_redteam_unique_tuples: number | null
      methods: Record<'lifetime_user_computer' | 'hierarchical_static' | 'hierarchical_decay', { alerts: number; unlabeled_alerts: number; mean_score: number | null; zero_scores: number; alert_fraction_over_unlabeled: number | null; known_redteam_recalled_unique_tuples: number | null }>
    }>
  }>
  limitations: string[]
  [key: string]: unknown
}

export class ApiError extends Error {
  status: number
  code?: string
  constructor(message: string, status: number, code?: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

export async function api<T>(path: string, token?: string | null, body?: unknown, method?: 'GET' | 'POST' | 'DELETE', timeoutMs = 30_000): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api${path}`, {
      cache: 'no-store',
      method: method || (body === undefined ? 'GET' : 'POST'),
      signal: AbortSignal.timeout(timeoutMs),
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  } catch (failure) {
    if (failure instanceof DOMException && failure.name === 'TimeoutError') throw new ApiError('The API timed out. The result could not be confirmed. Refresh before retrying.', 0)
    throw new ApiError('The API could not be reached. Start the backend and retry.', 0)
  }
  let data: unknown
  try { data = await response.json() } catch (failure) {
    if (failure instanceof DOMException && failure.name === 'TimeoutError') throw new ApiError('The response timed out. Refresh to check the latest state.', 0)
    throw new ApiError('The API returned an unreadable response. Check that the backend is running on port 8000.', response.status)
  }
  if (!response.ok) {
    const detail = (data as { detail?: unknown }).detail
    const structured = typeof detail === 'object' && detail !== null && !Array.isArray(detail) ? detail as { message?: unknown; code?: unknown } : null
    const message = typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map((item: { msg?: string }) => item.msg || 'Invalid input').join('. ') : typeof structured?.message === 'string' ? structured.message : 'The request could not be completed.'
    throw new ApiError(message, response.status, typeof structured?.code === 'string' ? structured.code : undefined)
  }
  return data as T
}
