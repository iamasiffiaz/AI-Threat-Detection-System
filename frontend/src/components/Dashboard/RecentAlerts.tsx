import { useNavigate } from 'react-router-dom'
import { formatRelativeTime } from '../../utils/formatters'
import { SeverityBadge } from '../Common/SeverityBadge'
import { AlertTriangle, ChevronRight } from 'lucide-react'

interface RecentAlert {
  id: number
  title: string
  severity: string
  status: string
  triggered_at: string
}

export function RecentAlerts({ alerts }: { alerts: RecentAlert[] }) {
  const navigate = useNavigate()

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-200">Recent Alerts</h3>
        <button
          onClick={() => navigate('/alerts')}
          className="text-xs text-cyber-400 hover:text-cyber-300 flex items-center gap-1"
        >
          View all <ChevronRight className="w-3 h-3" />
        </button>
      </div>

      {alerts.length === 0 ? (
        <div className="py-8 text-center text-gray-600 text-sm">
          <AlertTriangle className="w-8 h-8 mx-auto mb-2 opacity-30" />
          No recent alerts
        </div>
      ) : (
        <div className="space-y-2">
          {alerts.map((alert) => (
            <button
              key={alert.id}
              onClick={() => navigate('/alerts')}
              className="w-full flex items-start gap-3 p-3 rounded-lg hover:bg-gray-800/60 transition-colors text-left group"
            >
              <div className="mt-0.5">
                <SeverityBadge severity={alert.severity} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-gray-200 font-medium truncate group-hover:text-white">
                  {alert.title}
                </p>
                <p className="text-xs text-gray-500 mt-0.5">
                  {formatRelativeTime(alert.triggered_at)}
                </p>
              </div>
              <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-gray-400 flex-shrink-0 mt-1" />
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
