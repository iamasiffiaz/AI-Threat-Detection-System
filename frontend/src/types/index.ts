// ─── Auth Types ────────────────────────────────────────────────────────────────

export type UserRole = 'admin' | 'analyst'

export interface User {
  id: number
  username: string
  email: string
  full_name: string | null
  role: UserRole
  is_active: boolean
  created_at: string
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

// ─── Log Entry Types ─────────────────────────────────────────────────────────

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'DNS' | 'FTP' | 'SSH' | 'OTHER'
export type Severity  = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface LogEntry {
  id: number
  timestamp: string
  source_ip: string
  destination_ip: string | null
  source_port: number | null
  destination_port: number | null
  protocol: Protocol
  event_type: string
  severity: Severity
  message: string | null
  bytes_sent: number | null
  bytes_received: number | null
  duration_ms: number | null
  username: string | null
  country_code: string | null
  geo_city: string | null
  geo_isp: string | null
  threat_reputation: number | null
  is_known_bad_ip: boolean | null
  is_blacklisted: boolean | null
  anomaly_score: number | null
  risk_score: number | null
  attack_type: string | null
  ingested_at: string
}

export interface LogStatistics {
  total_logs: number
  logs_last_hour: number
  logs_last_24h: number
  top_source_ips: Array<{ ip: string; count: number }>
  events_by_severity: Record<string, number>
  events_by_protocol: Record<string, number>
  traffic_timeline: Array<{ timestamp: string; count: number }>
}

// ─── Alert Types ─────────────────────────────────────────────────────────────

export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus   = 'open' | 'investigating' | 'resolved' | 'false_positive'
export type AlertType     = 'anomaly' | 'rule_based' | 'hybrid'

export interface Alert {
  id: number
  title: string
  description: string
  severity: AlertSeverity
  alert_type: AlertType
  status: AlertStatus
  source_ip: string | null
  rule_name: string | null
  anomaly_score: number | null
  llm_explanation: string | null
  attack_type: string | null
  mitigation_steps: string | null
  log_entry_id: number | null
  // Enterprise fields
  risk_score: number | null
  incident_id: number | null
  geo_country: string | null
  geo_city: string | null
  threat_reputation: number | null
  is_known_bad_ip: boolean | null
  kill_chain_phase: string | null
  mitre_ttps: string | null
  false_positive_likelihood: string | null
  behavior_score: number | null
  triggered_at: string
  resolved_at: string | null
}

export interface AlertSummary {
  total_alerts: number
  open_alerts: number
  critical_alerts: number
  high_alerts: number
  alerts_last_24h: number
  by_type: Record<string, number>
  by_status: Record<string, number>
  recent_alerts: Alert[]
}

// ─── Incident Types ───────────────────────────────────────────────────────────

export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical'
export type IncidentStatus   = 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive'

export interface Incident {
  id: number
  title: string
  description: string | null
  severity: IncidentSeverity
  status: IncidentStatus
  risk_score: number
  alert_count: number
  source_ip: string | null
  attack_types: string[] | null
  mitre_ttps: string | null
  kill_chain_phases: string[] | null
  geo_country: string | null
  threat_reputation: number | null
  is_known_bad_ip: boolean
  assigned_to: string | null
  llm_summary: string | null
  recommended_playbook: string | null
  auto_actions_taken: string[] | null
  first_seen: string
  last_seen: string
  resolved_at: string | null
}

export interface IncidentSummary {
  total: number
  open: number
  investigating: number
  resolved: number
  critical: number
  high: number
  avg_risk_score: number
}

// ─── Threat Intelligence Types ────────────────────────────────────────────────

export interface ThreatIntelResult {
  ip_address: string
  country_code: string
  country_name: string
  region: string
  city: string
  isp: string
  asn: string
  latitude: number
  longitude: number
  timezone_name: string
  is_known_bad: boolean
  is_tor_exit: boolean
  is_proxy: boolean
  is_datacenter: boolean
  reputation_score: number
  threat_categories: string[]
  abuse_confidence: number
  source: string
  cached: boolean
}

// ─── SOAR / Blacklist Types ───────────────────────────────────────────────────

export interface BlacklistEntry {
  id: number
  ip_address: string
  reason: string
  attack_types: string[] | null
  risk_score: number | null
  added_by: string
  is_active: boolean
  block_hits: number
  expires_at: string | null
  created_at: string
}

export interface Playbook {
  name: string
  steps: string[]
  auto_actions: string[]
  sla_minutes: number
  severity_trigger: string
}

// ─── Investigation / Forensic Types ──────────────────────────────────────────

export interface ForensicReport {
  ip_address: string
  first_seen: string | null
  last_seen: string | null
  total_logs: number
  total_alerts: number
  open_incidents: number
  risk_score_max: number
  attack_types: string[]
  geo_info: {
    country_code: string
    country_name: string
    city: string
    isp: string
    asn: string
    latitude: number
    longitude: number
    is_tor_exit: boolean
    is_proxy: boolean
    is_known_bad: boolean
    reputation_score: number
    threat_categories: string[]
  }
  behavior_summary: {
    requests_1h: number
    failed_logins_1h: number
    unique_ports_1h: number
    unique_dests_1h: number
    bytes_out_1h: number
    requests_24h: number
    deviation_score: number
    is_new_source: boolean
    baseline_requests: number
    baseline_failures: number
  }
  recent_alerts: Array<{
    id: number
    title: string
    severity: AlertSeverity
    risk_score: number | null
    attack_type: string | null
    rule_name: string | null
    triggered_at: string
    status: AlertStatus
  }>
  timeline_events: Array<{
    time: string
    type: 'log' | 'alert'
    event: string
    severity: string
    details: string
    risk_score: number | null
    attack_type: string | null
  }>
}

// ─── SOC Assistant Types ──────────────────────────────────────────────────────

export interface SOCResponse {
  answer: string
  sources_used: string[]
  confidence: string
  recommended_actions: string[] | null
}

// ─── Anomaly Types ───────────────────────────────────────────────────────────

export interface Anomaly {
  id: number
  log_entry_id: number
  anomaly_score: number
  model_name: string
  feature_vector: Record<string, unknown> | null
  source_ip: string | null
  event_type: string | null
  explanation: string | null
  detected_at: string
}

export interface ModelInfo {
  model_name: string
  algorithm: string
  trained_at: string | null
  training_samples: number
  threshold: number
  is_trained: boolean
}

// ─── Dashboard Types ─────────────────────────────────────────────────────────

export interface DashboardOverview {
  logs: {
    total: number
    last_hour: number
    last_24h: number
  }
  alerts: {
    total: number
    open: number
    critical: number
    last_24h: number
    by_severity: Record<string, number>
  }
  anomalies: {
    total: number
    last_24h: number
    avg_score_24h: number
  }
  model: ModelInfo
  system: {
    llm_available: boolean
    server_time: string
  }
  charts: {
    traffic_timeline: Array<{ timestamp: string; count: number }>
  }
  recent_alerts: Array<{
    id: number
    title: string
    severity: AlertSeverity
    status: AlertStatus
    risk_score: number | null
    attack_type: string | null
    triggered_at: string
  }>
  recent_anomalies: Array<{
    id: number
    source_ip: string | null
    anomaly_score: number
    detected_at: string
  }>
}

// ─── Pagination ──────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  pages: number
}

// ─── WebSocket Message ───────────────────────────────────────────────────────

export interface WSMessage {
  type: 'connected' | 'heartbeat' | 'new_alert' | 'log_entry'
  message?: string
  timestamp?: string
  alert?: Partial<Alert>
  data?: Partial<LogEntry>
}
