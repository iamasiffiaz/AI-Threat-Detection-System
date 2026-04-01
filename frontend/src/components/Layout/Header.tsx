import { useState } from 'react'
import { Bell, RefreshCw, Wifi, WifiOff } from 'lucide-react'
import { formatDate } from '../../utils/formatters'

interface HeaderProps {
  title: string
  subtitle?: string
  wsConnected?: boolean
  onRefresh?: () => void
  isRefreshing?: boolean
}

export function Header({ title, subtitle, wsConnected, onRefresh, isRefreshing }: HeaderProps) {
  const [now] = useState(() => new Date().toISOString())

  return (
    <header className="sticky top-0 z-40 bg-gray-950/95 backdrop-blur border-b border-gray-800">
      <div className="flex items-center justify-between px-6 py-4">
        <div>
          <h1 className="text-lg font-semibold text-white">{title}</h1>
          {subtitle && <p className="text-sm text-gray-400 mt-0.5">{subtitle}</p>}
        </div>

        <div className="flex items-center gap-3">
          {/* WebSocket status */}
          {wsConnected !== undefined && (
            <div className={`flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-full border ${
              wsConnected
                ? 'text-green-400 border-green-400/20 bg-green-400/5'
                : 'text-gray-500 border-gray-700 bg-gray-800/50'
            }`}>
              {wsConnected ? (
                <><Wifi className="w-3 h-3" /> Live</>
              ) : (
                <><WifiOff className="w-3 h-3" /> Offline</>
              )}
            </div>
          )}

          {/* Refresh button */}
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors px-2.5 py-1.5 rounded-lg hover:bg-gray-800 disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          )}

          {/* Timestamp */}
          <span className="text-xs text-gray-600 font-mono">{formatDate(now)}</span>
        </div>
      </div>
    </header>
  )
}
