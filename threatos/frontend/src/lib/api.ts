import axios from 'axios'

export const apiClient = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

// ── Types ─────────────────────────────────────────────────────────────────────

export interface Alert {
  id: string
  technique_id: string
  tactic: string
  severity: number
  risk_score: number
  status: string
  entity_host: string | null
  entity_user: string | null
  created_at: string
}

export interface Rule {
  id: string
  name: string
  technique_id: string
  tactic: string
  severity: number
  confidence: number
  enabled: boolean
  trigger_count: number
}

export interface Asset {
  id: string
  hostname: string
  criticality: number
  owner_team: string | null
  environment: string
  os_type: string
  ip_addresses: string[]
  tags: string[]
}

export interface AttackChain {
  id: string
  host: string
  tactic_count: number
  technique_ids: string[]
  tactics_observed: string[]
  alert_ids: string[]
  risk_score: number
  is_multi_stage: boolean
  status: string
  first_seen: string
  last_seen: string
  duration_seconds: number
}

export interface CoverageSummary {
  total_techniques: number
  covered: number
  gaps: number
  coverage_pct: number
}

export interface CoverageRow {
  technique_id: string
  technique_name: string | null
  tactic: string | null
  rule_count: number
  confidence_avg: number
  covered: boolean
  platforms: string[]
  priority_gap: boolean
}

export interface ScanResult {
  id: string
  target: string
  scan_type: string
  status: string
  hosts_up: number
  hosts_down: number
  open_ports: { host: string; port: number; protocol: string; service: string }[]
  os_guesses: { host: string; os_guess: string; accuracy: number }[]
  duration_s: number | null
  error_detail: string | null
  started_at: string | null
  finished_at: string | null
}

export interface PurpleRun {
  id: string
  technique_id: string
  verdict: string
  detection_rate: number
  run_at: string
}

// ── API functions ─────────────────────────────────────────────────────────────

export const alertsApi = {
  list: (params?: object) => apiClient.get<Alert[]>('/alerts', { params }).then(r => r.data),
  updateStatus: (id: string, status: string) =>
    apiClient.put(`/alerts/${id}/status`, { status }).then(r => r.data),
}

export const rulesApi = {
  list: () => apiClient.get<Rule[]>('/rules').then(r => r.data),
  create: (data: object) => apiClient.post<Rule>('/rules', data).then(r => r.data),
  toggle: (id: string) => apiClient.put(`/rules/${id}/toggle`).then(r => r.data),
}

export const assetsApi = {
  list: (params?: object) => apiClient.get<Asset[]>('/assets', { params }).then(r => r.data),
  create: (data: object) => apiClient.post<Asset>('/assets', data).then(r => r.data),
  updateCriticality: (id: string, criticality: number) =>
    apiClient.put(`/assets/${id}/criticality`, { criticality }).then(r => r.data),
  delete: (id: string) => apiClient.delete(`/assets/${id}`).then(r => r.data),
}

export const chainsApi = {
  list: (params?: object) => apiClient.get<AttackChain[]>('/chains', { params }).then(r => r.data),
  correlate: (host: string, window_hours = 24) =>
    apiClient.post('/chains/correlate', { host, window_hours }).then(r => r.data),
  updateStatus: (id: string, status: string) =>
    apiClient.put(`/chains/${id}/status`, { status }).then(r => r.data),
}

export const coverageApi = {
  summary: () => apiClient.get<CoverageSummary>('/coverage/summary').then(r => r.data),
  matrix: (params?: object) => apiClient.get<CoverageRow[]>('/coverage', { params }).then(r => r.data),
  refresh: () => apiClient.post<CoverageSummary>('/coverage/refresh').then(r => r.data),
}

export const scansApi = {
  list: () => apiClient.get<ScanResult[]>('/scans').then(r => r.data),
  run: (target: string, scan_type = 'quick') =>
    apiClient.post<ScanResult>('/scans', { target, scan_type, timeout: 120 }).then(r => r.data),
}

export const purpleApi = {
  runs: () => apiClient.get<PurpleRun[]>('/purple/runs').then(r => r.data),
  validate: (technique_id: string, emulated_event: object) =>
    apiClient.post('/purple/validate', { technique_id, emulated_event }).then(r => r.data),
  score: (data: object) => apiClient.post('/purple/score', data).then(r => r.data),
}

// ── Asset delete ──────────────────────────────────────────────────────────────
export const assetsApiExt = {
  delete: (id: string) => apiClient.delete(`/assets/${id}`).then(r => r.data),
}

// ── Auth API ──────────────────────────────────────────────────────────────────
export const authApi = {
  login:          (username: string, password: string) =>
    apiClient.post('/auth/login', { username, password }).then(r => r.data),
  refresh:        (refresh_token: string) =>
    apiClient.post('/auth/refresh', { refresh_token }).then(r => r.data),
  me:             () => apiClient.get('/auth/me').then(r => r.data),
  changePassword: (current_password: string, new_password: string) =>
    apiClient.post('/auth/change-password', { current_password, new_password }).then(r => r.data),
  listUsers:      () => apiClient.get('/auth/users').then(r => r.data),
  createUser:     (data: object) => apiClient.post('/auth/users', data).then(r => r.data),
  updateUser:     (id: string, data: object) => apiClient.put(`/auth/users/${id}`, data).then(r => r.data),
  deactivate:     (id: string) => apiClient.post(`/auth/users/${id}/deactivate`).then(r => r.data),
  activate:       (id: string) => apiClient.post(`/auth/users/${id}/activate`).then(r => r.data),
  resetPassword:  (id: string, new_password: string) =>
    apiClient.post(`/auth/users/${id}/reset-password`, { new_password }).then(r => r.data),
  generateApiKey: (id: string) =>
    apiClient.post(`/auth/users/${id}/generate-api-key`).then(r => r.data),
  revokeApiKey:   (id: string) =>
    apiClient.delete(`/auth/users/${id}/api-key`).then(r => r.data),
}
