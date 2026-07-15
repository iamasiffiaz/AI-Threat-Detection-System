/**
 * Formatting utilities for dates, bytes, and severity levels.
 * SaaS semantic color tokens (severity ≠ brand).
 */
import { format, formatDistanceToNow } from 'date-fns'

export function formatDate(dateString: string): string {
  try {
    return format(new Date(dateString), 'MMM dd, yyyy HH:mm:ss')
  } catch {
    return dateString
  }
}

export function formatRelativeTime(dateString: string): string {
  try {
    return formatDistanceToNow(new Date(dateString), { addSuffix: true })
  } catch {
    return dateString
  }
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

export function formatScore(score: number | null | undefined): string {
  if (score == null) return '—'
  return (score * 100).toFixed(1) + '%'
}

/** Semantic severity tokens — distinct from brand blue for scannability */
export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-threat-critical bg-threat-critical/12 border-threat-critical/30',
  high:     'text-threat-high bg-threat-high/12 border-threat-high/30',
  medium:   'text-threat-medium bg-threat-medium/12 border-threat-medium/30',
  low:      'text-threat-low bg-threat-low/12 border-threat-low/30',
  info:     'text-soc-muted bg-soc-panel border-soc-border',
}

export const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-threat-critical',
  high:     'bg-threat-high',
  medium:   'bg-threat-medium',
  low:      'bg-threat-low',
  info:     'bg-soc-faint',
}

export const SEVERITY_HEX: Record<string, string> = {
  critical: '#EF4444',
  high:     '#F97316',
  medium:   '#EAB308',
  low:      '#22C55E',
}

/** Align with severity scoring service bands: Low 1–39, Medium 40–69, High 70–89, Critical 90–100 */
export function riskToSeverity(score: number): 'critical' | 'high' | 'medium' | 'low' {
  if (score >= 90) return 'critical'
  if (score >= 70) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}

export const STATUS_COLORS: Record<string, string> = {
  open:           'text-threat-critical bg-threat-critical/10 border-threat-critical/30',
  investigating:  'text-threat-medium bg-threat-medium/10 border-threat-medium/30',
  contained:      'text-cyber-400 bg-cyber-500/10 border-cyber-500/30',
  resolved:       'text-threat-low bg-threat-low/10 border-threat-low/30',
  false_positive: 'text-soc-faint bg-soc-panel border-soc-border',
}

export const CHART_COLORS = [
  '#3B82F6', '#0EA5E9', '#EF4444', '#F97316',
  '#EAB308', '#22C55E', '#14B8A6', '#94A3B8',
]

export const CHART_TOOLTIP_STYLE = {
  background: '#182234',
  border: '1px solid #2A3548',
  borderRadius: '10px',
  fontSize: '12px',
  color: '#F1F5F9',
  boxShadow: '0 8px 24px rgba(0,0,0,0.35)',
}
