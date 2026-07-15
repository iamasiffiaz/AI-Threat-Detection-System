import clsx from 'clsx'
import { AlertCircle, Inbox } from 'lucide-react'

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg'
  className?: string
  message?: string
}

export function LoadingSpinner({ size = 'md', className, message }: LoadingSpinnerProps) {
  const sizes = { sm: 'w-4 h-4', md: 'w-8 h-8', lg: 'w-12 h-12' }
  return (
    <div className={clsx('flex flex-col items-center justify-center gap-3', className)}>
      <div className={clsx(
        'border-2 border-soc-border border-t-cyber-400 rounded-full animate-spin',
        sizes[size]
      )} />
      {message && <p className="text-sm text-soc-muted font-medium">{message}</p>}
    </div>
  )
}

export function PageLoader({ message = 'Loading SOC data…' }: { message?: string }) {
  return (
    <div className="flex-1 flex items-center justify-center min-h-[400px]">
      <LoadingSpinner size="lg" message={message} />
    </div>
  )
}

export function EmptyState({
  message = 'No data found',
  hint,
  icon,
  action,
}: {
  message?: string
  hint?: string
  icon?: React.ReactNode
  action?: React.ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center py-14 text-center px-4">
      <div className="mb-3 text-soc-faint">
        {icon ?? <Inbox className="w-10 h-10 opacity-60" />}
      </div>
      <p className="text-soc-muted text-sm font-medium">{message}</p>
      {hint && <p className="text-soc-faint text-xs mt-1 max-w-sm">{hint}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function ErrorState({
  message = 'Something went wrong',
  hint = 'Check API connectivity and try again.',
  onRetry,
}: {
  message?: string
  hint?: string
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col items-center justify-center py-14 text-center px-4 soc-card">
      <AlertCircle className="w-10 h-10 text-threat-critical mb-3 opacity-80" />
      <p className="text-soc-text text-sm font-semibold">{message}</p>
      <p className="text-soc-faint text-xs mt-1 max-w-sm">{hint}</p>
      {onRetry && (
        <button type="button" className="soc-btn-primary mt-4" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  )
}
