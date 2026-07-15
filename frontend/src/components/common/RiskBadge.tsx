import clsx from 'clsx'
import { riskToSeverity, SEVERITY_COLORS } from '../../utils/formatters'

interface RiskBadgeProps {
  score: number | null | undefined
  showLabel?: boolean
  size?: 'sm' | 'md'
}

export function RiskBadge({ score, showLabel = false, size = 'sm' }: RiskBadgeProps) {
  if (score == null) return <span className="text-soc-faint text-xs">—</span>

  const level = riskToSeverity(score)
  const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded border font-mono font-semibold',
        SEVERITY_COLORS[level],
        size === 'sm' ? 'text-[11px] px-1.5 py-0.5' : 'text-sm px-2 py-1'
      )}
    >
      {Number(score).toFixed(0)}
      {showLabel && <span className="font-sans font-normal opacity-90">{labels[level]}</span>}
    </span>
  )
}

export function getRiskColor(score: number | null | undefined): string {
  if (score == null) return 'text-soc-faint'
  const level = riskToSeverity(score)
  return {
    critical: 'text-threat-critical',
    high: 'text-threat-high',
    medium: 'text-threat-medium',
    low: 'text-threat-low',
  }[level]
}
