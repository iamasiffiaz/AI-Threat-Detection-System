import clsx from 'clsx'

interface RiskBadgeProps {
  score: number | null | undefined
  showLabel?: boolean
  size?: 'sm' | 'md'
}

function getRiskLevel(score: number) {
  if (score >= 76) return { label: 'Critical', color: 'text-red-400 bg-red-500/15 border-red-500/30' }
  if (score >= 51) return { label: 'High',     color: 'text-orange-400 bg-orange-500/15 border-orange-500/30' }
  if (score >= 26) return { label: 'Medium',   color: 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30' }
  return              { label: 'Low',           color: 'text-green-400 bg-green-500/15 border-green-500/30' }
}

export function RiskBadge({ score, showLabel = false, size = 'sm' }: RiskBadgeProps) {
  if (score == null) return <span className="text-gray-600 text-xs">—</span>

  const { label, color } = getRiskLevel(score)
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded border font-mono font-semibold',
        color,
        size === 'sm' ? 'text-xs px-1.5 py-0.5' : 'text-sm px-2 py-1'
      )}
    >
      {score.toFixed(0)}
      {showLabel && <span className="font-sans font-normal opacity-80">{label}</span>}
    </span>
  )
}

export function getRiskColor(score: number | null | undefined): string {
  if (score == null) return 'text-gray-500'
  if (score >= 76) return 'text-red-400'
  if (score >= 51) return 'text-orange-400'
  if (score >= 26) return 'text-yellow-400'
  return 'text-green-400'
}
