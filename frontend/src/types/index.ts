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
