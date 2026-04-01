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
  default:  'border-gray-700/50 bg-gray-900',
  critical: 'border-red-500/20 bg-red-500/5',
  high:     'border-orange-500/20 bg-orange-500/5',
  medium:   'border-yellow-500/20 bg-yellow-500/5',
  low:      'border-blue-500/20 bg-blue-500/5',
  green:    'border-green-500/20 bg-green-500/5',
  cyber:    'border-cyber-500/20 bg-cyber-500/5',
}

const iconColorMap = {
  default:  'text-gray-400 bg-gray-800',
  critical: 'text-red-400 bg-red-400/10',
  high:     'text-orange-400 bg-orange-400/10',
  medium:   'text-yellow-400 bg-yellow-400/10',
  low:      'text-blue-400 bg-blue-400/10',
  green:    'text-green-400 bg-green-400/10',
  cyber:    'text-cyber-400 bg-cyber-400/10',
}

export function StatCard({
  title, value, subtitle, icon, trend, color = 'default', className
}: StatCardProps) {
  return (
    <div className={clsx(
      'rounded-xl border p-5 flex flex-col gap-3 transition-all hover:border-opacity-50',
      colorMap[color],
      className
    )}>
      <div className="flex items-start justify-between">
        <p className="text-sm text-gray-400 font-medium">{title}</p>
        {icon && (
          <span className={clsx('p-2 rounded-lg', iconColorMap[color])}>
            {icon}
          </span>
        )}
      </div>
      <div>
        <p className="text-3xl font-bold text-white tabular-nums">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </p>
        {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
      </div>
      {trend && (
        <div className={clsx(
          'text-xs flex items-center gap-1',
          trend.value >= 0 ? 'text-green-400' : 'text-red-400'
        )}>
          <span>{trend.value >= 0 ? '↑' : '↓'}</span>
          <span>{Math.abs(trend.value)}% {trend.label}</span>
        </div>
      )}
    </div>
  )
}
