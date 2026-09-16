/**
 * frontend/src/lib/api.ts
 * ────────────────────────
 * Typed API client.
 * Types are derived directly from the tested route response schemas.
 * Never add a type here that hasn't been verified by a passing integration test.
 *
 * Currently contains: Module 1 — Ingest API types only.
 * New API groups are added here ONLY after their routes have passing tests.
 */
import axios from "axios";

export const apiClient = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
  timeout: 15_000,
});

// ── Module 1: Ingest types ─────────────────────────────────────────────────
// Derived from IngestResponse schema in ingest_router.py (verified by tests).

export interface IngestResponse {
  status: "accepted";          // always "accepted" on 202
  event_id: string;            // UUID string
  hash: string | null;         // 16-char fingerprint, null if unfingerprinted
}

export interface BatchIngestResponse {
  queued: number;
  failed: number;
  event_ids: string[];
}

export interface IngestRequest {
  log_source: "json" | "syslog" | "cef" | "winlog";
  payload: Record<string, unknown>;
}

// ── Ingest API functions ───────────────────────────────────────────────────

export const ingestApi = {
  /** POST /api/ingest/event — single log event */
  single: (req: IngestRequest): Promise<IngestResponse> =>
    apiClient
      .post<IngestResponse>("/ingest/event", req)
      .then((r) => r.data),

  /** POST /api/ingest/batch — up to 500 events */
  batch: (events: IngestRequest[]): Promise<BatchIngestResponse> =>
    apiClient
      .post<BatchIngestResponse>("/ingest/batch", events)
      .then((r) => r.data),

  /** POST /api/ingest/syslog — raw syslog line as plain text */
  syslog: (rawLine: string): Promise<IngestResponse> =>
    apiClient
      .post<IngestResponse>("/ingest/syslog", rawLine, {
        headers: { "Content-Type": "text/plain" },
      })
      .then((r) => r.data),
};

// ── Module 2: Detection rules types ────────────────────────────────────────
// Derived from RuleResponse and RuleCreate schemas in rules_router.py
// (verified by 14 integration tests passing)

export interface DetectionRule {
  id:             string;
  name:           string;
  technique_id:   string;          // e.g. "T1059.001"
  tactic:         string;          // e.g. "execution"
  severity:       number;          // 1–10
  confidence:     number;          // 0.0–1.0
  log_sources:    string[];        // [] = all sources
  platforms:      string[];
  tags:           string[];
  enabled:        boolean;
  trigger_count:  number;
  last_triggered: string | null;   // ISO 8601 or null
}

export interface RuleCreate {
  name:          string;
  technique_id:  string;
  tactic:        string;
  severity:      number;
  confidence:    number;
  log_sources:   string[];
  platforms:     string[];
  tags:          string[];
  detection_ast: Record<string, unknown>;
  description?:  string;
  author?:       string;
}

export interface ToggleResponse {
  id:      string;
  enabled: boolean;
}

// ── Rules API functions ──────────────────────────────────────────────────────

export const rulesApi = {
  /** GET /api/rules — list all rules (enabled only by default) */
  list: (enabledOnly = true): Promise<DetectionRule[]> =>
    apiClient
      .get<DetectionRule[]>("/rules", { params: { enabled_only: enabledOnly } })
      .then((r) => r.data),

  /** GET /api/rules/:id — single rule detail */
  get: (id: string): Promise<DetectionRule> =>
    apiClient
      .get<DetectionRule>(`/rules/${id}`)
      .then((r) => r.data),

  /** POST /api/rules — create a rule, returns 201 or 409/422 */
  create: (rule: RuleCreate): Promise<DetectionRule> =>
    apiClient
      .post<DetectionRule>("/rules", rule)
      .then((r) => r.data),

  /** PUT /api/rules/:id/toggle — flip enabled state */
  toggle: (id: string): Promise<ToggleResponse> =>
    apiClient
      .put<ToggleResponse>(`/rules/${id}/toggle`)
      .then((r) => r.data),
};

// ── Module 3: Alert types ───────────────────────────────────────────────────
// Derived from AlertResponse schema in alerts_router.py
// (verified by 17 integration tests passing)

export interface Alert {
  id:                string;
  rule_id:           string | null;
  rule_name:         string | null;
  technique_id:      string;
  tactic:            string;
  severity:          number;          // 1–10
  confidence:        number;          // 0.0–1.0
  asset_criticality: number;          // 1–4
  risk_score:        number;          // 0–100
  entity_host:       string | null;
  entity_user:       string | null;
  entity_process:    string | null;
  entity_ip:         string | null;
  status:            AlertStatus;
  description:       string | null;
  created_at:        string;          // ISO 8601
  updated_at:        string;
  closed_at:         string | null;
}

export type AlertStatus =
  | "open"
  | "investigating"
  | "escalated"
  | "closed"
  | "false_positive";

export interface AlertListParams {
  status?:       AlertStatus;
  technique_id?: string;
  tactic?:       string;
  entity_host?:  string;
  min_score?:    number;
  limit?:        number;
  offset?:       number;
}

// ── Alerts API functions ─────────────────────────────────────────────────────

export const alertsApi = {
  /** GET /api/alerts — filtered list, ordered by risk_score DESC */
  list: (params?: AlertListParams): Promise<Alert[]> =>
    apiClient
      .get<Alert[]>("/alerts", { params })
      .then((r) => r.data),

  /** GET /api/alerts/:id */
  get: (id: string): Promise<Alert> =>
    apiClient
      .get<Alert>(`/alerts/${id}`)
      .then((r) => r.data),

  /** PUT /api/alerts/:id/status */
  updateStatus: (id: string, status: AlertStatus): Promise<Alert> =>
    apiClient
      .put<Alert>(`/alerts/${id}/status`, { status })
      .then((r) => r.data),
};

// ── Module 4: Coverage types ────────────────────────────────────────────────
// Derived from CoverageRowResponse and CoverageSummaryResponse schemas
// in coverage_router.py (verified by 13 integration tests passing)

export interface CoverageRow {
  technique_id:   string;       // e.g. "T1059.001"
  technique_name: string | null;
  tactic:         string | null; // e.g. "execution"
  rule_count:     number;
  confidence_avg: number;        // 0.0–1.0
  covered:        boolean;
  last_triggered: string | null; // ISO 8601 or null
  platforms:      string[];
  priority_gap:   boolean;
}

export interface CoverageSummary {
  total_techniques: number;
  covered:          number;
  gaps:             number;
  coverage_pct:     number;      // 0.0–100.0
}

export interface CoverageListParams {
  tactic?:       string;
  covered_only?: boolean;
}

// ── Coverage API functions ───────────────────────────────────────────────────

export const coverageApi = {
  /** POST /api/coverage/refresh — recompute matrix, returns summary */
  refresh: (): Promise<CoverageSummary> =>
    apiClient
      .post<CoverageSummary>("/coverage/refresh")
      .then((r) => r.data),

  /** GET /api/coverage — current matrix with optional filters */
  getMatrix: (params?: CoverageListParams): Promise<CoverageRow[]> =>
    apiClient
      .get<CoverageRow[]>("/coverage", { params })
      .then((r) => r.data),

  /** GET /api/coverage/summary — fast aggregate stats */
  getSummary: (): Promise<CoverageSummary> =>
    apiClient
      .get<CoverageSummary>("/coverage/summary")
      .then((r) => r.data),
};

// ── Module 5: Asset types ───────────────────────────────────────────────────
// Derived from AssetResponse / AssetCreateRequest in assets_router.py
// (verified by 21 integration tests passing)

export interface Asset {
  id:           string;
  hostname:     string;
  criticality:  1 | 2 | 3 | 4;   // enforced by DB CheckConstraint
  owner_team:   string | null;
  environment:  AssetEnvironment;
  os_type:      string;
  ip_addresses: string[];
  tags:         string[];
}

export type AssetEnvironment =
  | "production" | "staging" | "development"
  | "dmz" | "ot" | "cloud" | "unknown";

export interface AssetCreatePayload {
  hostname:     string;
  criticality?: number;
  owner_team?:  string;
  environment?: AssetEnvironment;
  os_type?:     string;
  ip_addresses?:string[];
  tags?:        string[];
}

export interface AssetListParams {
  criticality?:   number;
  environment?:   AssetEnvironment;
  owner_team?:    string;
  hostname_like?: string;
  limit?:         number;
  offset?:        number;
}

// Criticality tier labels used throughout the UI
export const CRITICALITY_LABELS: Record<number, string> = {
  1: "Low",
  2: "Medium",
  3: "High",
  4: "Critical",
};

// ── Assets API functions ─────────────────────────────────────────────────────

export const assetsApi = {
  /** GET /api/assets */
  list: (params?: AssetListParams): Promise<Asset[]> =>
    apiClient.get<Asset[]>("/assets", { params }).then((r) => r.data),

  /** GET /api/assets/:id */
  get: (id: string): Promise<Asset> =>
    apiClient.get<Asset>(`/assets/${id}`).then((r) => r.data),

  /** POST /api/assets — returns 201 or 409 */
  create: (data: AssetCreatePayload): Promise<Asset> =>
    apiClient.post<Asset>("/assets", data).then((r) => r.data),

  /** POST /api/assets/upsert — always 200, create-or-update */
  upsert: (data: AssetCreatePayload): Promise<Asset> =>
    apiClient.post<Asset>("/assets/upsert", data).then((r) => r.data),

  /** PUT /api/assets/:id/criticality */
  updateCriticality: (id: string, criticality: 1 | 2 | 3 | 4): Promise<Asset> =>
    apiClient
      .put<Asset>(`/assets/${id}/criticality`, { criticality })
      .then((r) => r.data),
};

// ── Module 7: Attack chain types ────────────────────────────────────────────
// Derived from ChainResponse in chains_router.py
// (verified by 14 integration tests passing)

export interface AttackChain {
  id:               string;
  host:             string;
  tactic_count:     number;
  technique_ids:    string[];    // kill-chain ordered
  tactics_observed: string[];    // kill-chain ordered
  alert_ids:        string[];    // insertion-time ordered
  risk_score:       number;      // max risk_score among member alerts
  is_multi_stage:   boolean;     // true when tactic_count >= 3
  status:           ChainStatus;
  first_seen:       string;      // ISO 8601
  last_seen:        string;
  duration_seconds: number;
}

export type ChainStatus = "open" | "investigating" | "closed";

export interface CorrelateRequest {
  host:          string;
  window_hours?: number;   // default 24, max 168
}

export interface ChainListParams {
  host?:           string;
  status?:         ChainStatus;
  is_multi_stage?: boolean;
  min_tactics?:    number;
  limit?:          number;
  offset?:         number;
}

// ── Chains API functions ─────────────────────────────────────────────────────

export const chainsApi = {
  /** POST /api/chains/correlate — run correlation for one host */
  correlate: (req: CorrelateRequest): Promise<Record<string, unknown>> =>
    apiClient.post("/chains/correlate", req).then((r) => r.data),

  /** GET /api/chains */
  list: (params?: ChainListParams): Promise<AttackChain[]> =>
    apiClient.get<AttackChain[]>("/chains", { params }).then((r) => r.data),

  /** GET /api/chains/:id */
  get: (id: string): Promise<AttackChain> =>
    apiClient.get<AttackChain>(`/chains/${id}`).then((r) => r.data),

  /** PUT /api/chains/:id/status */
  updateStatus: (id: string, status: ChainStatus): Promise<AttackChain> =>
    apiClient
      .put<AttackChain>(`/chains/${id}/status`, { status })
      .then((r) => r.data),
};

// ── Module 8: Purple Team + Risk Score v2 types ─────────────────────────────

export interface PurpleTeamRun {
  id:             string;
  technique_id:   string;
  chain_id:       string | null;
  detection_rate: number;         // 0–100
  verdict:        PurpleVerdict;
  rules_expected: string[];
  rules_fired:    string[];
  rules_missed:   string[];
  run_by:         string | null;
  run_at:         string;
}

export type PurpleVerdict = "pass" | "partial" | "fail" | "unknown";

export interface ValidateRequest {
  technique_id:   string;
  emulated_event: Record<string, unknown>;
  chain_id?:      string;
  run_by?:        string;
  notes?:         string;
}

export interface ValidateChainRequest {
  chain_id:        string;
  technique_ids:   string[];
  emulated_events: Record<string, Record<string, unknown>>;
  run_by?:         string;
}

export interface ScoreV2Request {
  severity:           number;
  confidence:         number;
  asset_criticality:  number;
  chain_tactic_count: number;
  is_multi_stage:     boolean;
}

export interface ScoreV2Components {
  severity:           number;
  confidence:         number;
  asset_criticality:  number;
  chain_tactic_count: number;
  is_multi_stage:     boolean;
  base_score:         number;
  chain_boost:        number;
  stage_boost:        number;
  final_score:        number;
}

export const purpleApi = {
  validate: (req: ValidateRequest): Promise<Record<string, unknown>> =>
    apiClient.post("/purple/validate", req).then(r => r.data),

  validateChain: (req: ValidateChainRequest): Promise<Record<string, unknown>[]> =>
    apiClient.post("/purple/validate-chain", req).then(r => r.data),

  runs: (params?: { technique_id?: string; chain_id?: string }): Promise<PurpleTeamRun[]> =>
    apiClient.get<PurpleTeamRun[]>("/purple/runs", { params }).then(r => r.data),

  scoreV2: (req: ScoreV2Request): Promise<ScoreV2Components> =>
    apiClient.post<ScoreV2Components>("/purple/score", req).then(r => r.data),
};

// ── Module 9: Nmap Scan types ────────────────────────────────────────────────
// Derived from ScanResponse in scans_router.py
// (verified by 19 integration tests passing)

export type ScanType    = "quick" | "full" | "stealth" | "udp" | "vuln";
export type ScanStatus  = "pending" | "running" | "completed" | "failed" | "cancelled";

export interface OpenPort {
  host:     string;
  port:     number;
  protocol: string;
  service:  string;
  state:    string;
}

export interface OsGuess {
  host:     string;
  os_guess: string;
  accuracy: number;
}

export interface ScanResult {
  id:           string;
  target:       string;
  scan_type:    ScanType;
  status:       ScanStatus;
  hosts_up:     number;
  hosts_down:   number;
  open_ports:   OpenPort[];
  os_guesses:   OsGuess[];
  duration_s:   number | null;
  error_detail: string | null;
  started_at:   string | null;
  finished_at:  string | null;
  requested_by: string | null;
}

export interface ScanRequest {
  target:        string;
  scan_type?:    ScanType;
  requested_by?: string;
  timeout?:      number;
}

// ── Scans API functions ──────────────────────────────────────────────────────

export const scansApi = {
  /** POST /api/scans — create + run immediately (blocks until done) */
  run: (req: ScanRequest): Promise<ScanResult> =>
    apiClient.post<ScanResult>("/scans", req).then(r => r.data),

  /** POST /api/scans/create — create pending only */
  create: (req: ScanRequest): Promise<ScanResult> =>
    apiClient.post<ScanResult>("/scans/create", req).then(r => r.data),

  /** POST /api/scans/:id/run — execute a pending scan */
  execute: (id: string, timeout?: number): Promise<ScanResult> =>
    apiClient
      .post<ScanResult>(`/scans/${id}/run`, null, { params: { timeout } })
      .then(r => r.data),

  /** GET /api/scans */
  list: (params?: { target?: string; status?: ScanStatus }): Promise<ScanResult[]> =>
    apiClient.get<ScanResult[]>("/scans", { params }).then(r => r.data),

  /** GET /api/scans/:id */
  get: (id: string): Promise<ScanResult> =>
    apiClient.get<ScanResult>(`/scans/${id}`).then(r => r.data),
};
