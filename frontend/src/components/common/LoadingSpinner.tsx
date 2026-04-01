import clsx from 'clsx'

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
        'border-2 border-gray-700 border-t-cyber-400 rounded-full animate-spin',
        sizes[size]
      )} />
      {message && <p className="text-sm text-gray-400">{message}</p>}
    </div>
  )
}

export function PageLoader() {
  return (
    <div className="flex-1 flex items-center justify-center min-h-[400px]">
      <LoadingSpinner size="lg" message="Loading..." />
    </div>
  )
}

export function EmptyState({ message = 'No data found', icon }: { message?: string; icon?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      {icon && <div className="text-gray-600 mb-3">{icon}</div>}
      <p className="text-gray-500 text-sm">{message}</p>
    </div>
  )
}
