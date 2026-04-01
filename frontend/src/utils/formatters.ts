/**
 * Formatting utilities for dates, bytes, and severity levels.
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

export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high:     'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  low:      'text-blue-400 bg-blue-400/10 border-blue-400/30',
  info:     'text-gray-400 bg-gray-400/10 border-gray-400/30',
}

export const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-400',
  high:     'bg-orange-400',
  medium:   'bg-yellow-400',
  low:      'bg-blue-400',
  info:     'bg-gray-400',
}

export const STATUS_COLORS: Record<string, string> = {
  open:           'text-red-400 bg-red-400/10',
  investigating:  'text-yellow-400 bg-yellow-400/10',
  resolved:       'text-green-400 bg-green-400/10',
  false_positive: 'text-gray-400 bg-gray-400/10',
}

export const CHART_COLORS = [
  '#1ebef2', '#3b82f6', '#8b5cf6', '#ec4899',
  '#f97316', '#10b981', '#eab308', '#ef4444',
]
