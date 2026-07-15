import clsx from 'clsx'
import type { ReactNode } from 'react'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon?: ReactNode
  trend?: { value: number; label: string }
  color?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'green' | 'cyber'
  className?: string
}

const colorMap = {
  default:  'border-soc-border bg-soc-card',
  critical: 'border-threat-critical/25 bg-threat-critical/5',
  high:     'border-threat-high/25 bg-threat-high/5',
  medium:   'border-threat-medium/25 bg-threat-medium/5',
  low:      'border-cyber-500/25 bg-cyber-500/5',
  green:    'border-threat-low/25 bg-threat-low/5',
  cyber:    'border-cyber-500/25 bg-cyber-500/5',
}

const iconColorMap = {
  default:  'text-soc-muted bg-soc-elevated',
  critical: 'text-threat-critical bg-threat-critical/10',
  high:     'text-threat-high bg-threat-high/10',
  medium:   'text-threat-medium bg-threat-medium/10',
  low:      'text-cyber-400 bg-cyber-500/10',
  green:    'text-threat-low bg-threat-low/10',
  cyber:    'text-cyber-400 bg-cyber-500/10',
}

export function StatCard({
  title, value, subtitle, icon, trend, color = 'default', className
}: StatCardProps) {
  return (
    <div className={clsx(
      'rounded-xl border p-5 flex flex-col gap-3 shadow-card transition-colors hover:border-cyber-500/30',
      colorMap[color],
      className
    )}>
      <div className="flex items-start justify-between">
        <p className="text-sm text-soc-muted font-medium">{title}</p>
        {icon && (
          <span className={clsx('p-2 rounded-lg', iconColorMap[color])}>
            {icon}
          </span>
        )}
      </div>
      <div>
        <p className="text-3xl font-semibold text-soc-text tabular-nums tracking-tight">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </p>
        {subtitle && <p className="text-xs text-soc-faint mt-1">{subtitle}</p>}
      </div>
      {trend && (
        <div className={clsx(
          'text-xs flex items-center gap-1',
          trend.value >= 0 ? 'text-threat-low' : 'text-threat-critical'
        )}>
          <span>{trend.value >= 0 ? '↑' : '↓'}</span>
          <span>{Math.abs(trend.value)}% {trend.label}</span>
        </div>
      )}
    </div>
  )
}
