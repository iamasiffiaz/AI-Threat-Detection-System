import clsx from 'clsx'
import { SEVERITY_COLORS, SEVERITY_DOT, STATUS_COLORS } from '../../utils/formatters'

interface SeverityBadgeProps {
  severity: string
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const key = (severity || 'info').toLowerCase()
  return (
    <span className={clsx(
      'inline-flex items-center gap-1.5 font-semibold rounded-md border capitalize tracking-wide',
      SEVERITY_COLORS[key] || SEVERITY_COLORS.info,
      size === 'sm' ? 'text-[11px] px-2 py-0.5' : 'text-sm px-2.5 py-1'
    )}>
      <span className={clsx('w-1.5 h-1.5 rounded-full shrink-0', SEVERITY_DOT[key] || SEVERITY_DOT.info)} />
      {key}
    </span>
  )
}

interface StatusBadgeProps {
  status: string
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const key = (status || '').toLowerCase()
  return (
    <span className={clsx(
      'inline-flex items-center text-[11px] font-semibold px-2 py-0.5 rounded-md border capitalize tracking-wide',
      STATUS_COLORS[key] || 'text-soc-faint bg-soc-panel border-soc-border'
    )}>
      {key.replace(/_/g, ' ')}
    </span>
  )
}
