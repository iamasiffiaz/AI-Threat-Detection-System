import clsx from 'clsx'
import { SEVERITY_COLORS } from '../../utils/formatters'

interface SeverityBadgeProps {
  severity: string
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  return (
    <span className={clsx(
      'inline-flex items-center gap-1.5 font-medium rounded-md border capitalize',
      SEVERITY_COLORS[severity] || SEVERITY_COLORS.info,
      size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-sm px-2.5 py-1'
    )}>
      <span className={clsx(
        'w-1.5 h-1.5 rounded-full',
        severity === 'critical' ? 'bg-red-400' :
        severity === 'high'     ? 'bg-orange-400' :
        severity === 'medium'   ? 'bg-yellow-400' :
        severity === 'low'      ? 'bg-blue-400' : 'bg-gray-400'
      )} />
      {severity}
    </span>
  )
}

interface StatusBadgeProps {
  status: string
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const colors: Record<string, string> = {
    open:           'text-red-400 bg-red-400/10 border-red-400/20',
    investigating:  'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
    resolved:       'text-green-400 bg-green-400/10 border-green-400/20',
    false_positive: 'text-gray-400 bg-gray-800 border-gray-700',
  }
  return (
    <span className={clsx(
      'inline-flex items-center text-xs font-medium px-2 py-0.5 rounded-md border capitalize',
      colors[status] || 'text-gray-400 bg-gray-800 border-gray-700'
    )}>
      {status.replace('_', ' ')}
    </span>
  )
}
