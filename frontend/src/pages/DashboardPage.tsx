import { useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, FileText, TrendingUp, Brain, Wifi } from 'lucide-react'
import { dashboardApi } from '../services/api'
import { Header } from '../components/Layout/Header'
import { StatCard } from '../components/Common/StatCard'
import { TrafficChart } from '../components/Dashboard/TrafficChart'
import { SeverityChart } from '../components/Dashboard/SeverityChart'
import { TopIPsChart } from '../components/Dashboard/TopIPsChart'
import { AnomalyTrendChart } from '../components/Dashboard/AnomalyTrendChart'
import { RecentAlerts } from '../components/Dashboard/RecentAlerts'
import { PageLoader } from '../components/Common/LoadingSpinner'
import { useWebSocket } from '../hooks/useWebSocket'
import { anomaliesApi, logsApi } from '../services/api'
import toast from 'react-hot-toast'
import type { DashboardOverview, WSMessage } from '../types'

export function DashboardPage() {
  const { data, isLoading, refetch, isFetching } = useQuery<DashboardOverview>({
    queryKey: ['dashboard-overview'],
    queryFn: async () => (await dashboardApi.getOverview()).data,
    refetchInterval: 30_000, // Auto-refresh every 30s
  })

  const { data: anomalyTrends } = useQuery({
    queryKey: ['anomaly-trends'],
    queryFn: async () => (await anomaliesApi.getTrends(24)).data,
    refetchInterval: 60_000,
  })

  const { data: topIPs } = useQuery({
    queryKey: ['logs-stats'],
    queryFn: async () => (await logsApi.getStatistics()).data,
    refetchInterval: 60_000,
  })

  // Real-time WebSocket for live alerts
  const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/alerts`
  const { connected } = useWebSocket({
    url: wsUrl,
    onMessage: (msg: WSMessage) => {
      if (msg.type === 'new_alert' && msg.alert) {
        toast.custom((t) => (
          <div className={`${t.visible ? 'animate-slide-in' : ''} bg-gray-800 border border-red-500/30 rounded-xl px-4 py-3 shadow-xl flex items-start gap-3 max-w-sm`}>
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-white">New Alert</p>
              <p className="text-xs text-gray-400 mt-0.5">{msg.alert.title}</p>
            </div>
          </div>
        ), { duration: 5000 })
        refetch()
      }
    },
  })

  if (isLoading) return <PageLoader />

  const overview = data!

  return (
    <div className="flex flex-col flex-1">
      <Header
        title="Security Operations Center"
        subtitle="Real-time threat detection and analysis"
        wsConnected={connected}
        onRefresh={() => refetch()}
        isRefreshing={isFetching}
      />

      <div className="flex-1 p-6 space-y-6">
        {/* KPI Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Total Logs"
            value={overview.logs.total}
            subtitle={`+${overview.logs.last_24h.toLocaleString()} today`}
            icon={<FileText className="w-4 h-4" />}
            color="cyber"
          />
          <StatCard
            title="Open Alerts"
            value={overview.alerts.open}
            subtitle={`${overview.alerts.last_24h} in last 24h`}
            icon={<AlertTriangle className="w-4 h-4" />}
            color={overview.alerts.open > 10 ? 'critical' : overview.alerts.open > 5 ? 'high' : 'default'}
          />
          <StatCard
            title="Anomalies"
            value={overview.anomalies.total}
            subtitle={`${overview.anomalies.last_24h} detected today`}
            icon={<TrendingUp className="w-4 h-4" />}
            color={overview.anomalies.last_24h > 20 ? 'high' : 'medium'}
          />
          <StatCard
            title="Events/Hour"
            value={overview.logs.last_hour}
            subtitle={overview.model.is_trained ? 'ML model active' : 'ML model not trained'}
            icon={<Activity className="w-4 h-4" />}
            color="green"
          />
        </div>

        {/* Model & System Status */}
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-4 flex items-center gap-4">
            <div className={`p-2.5 rounded-lg ${overview.model.is_trained ? 'bg-green-400/10' : 'bg-gray-800'}`}>
              <Brain className={`w-5 h-5 ${overview.model.is_trained ? 'text-green-400' : 'text-gray-500'}`} />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-200">ML Anomaly Model</p>
              <p className="text-xs text-gray-500">
                {overview.model.is_trained
                  ? `Trained on ${overview.model.training_samples.toLocaleString()} samples`
                  : 'Not trained — generate sample data to train'}
              </p>
            </div>
            <span className={`ml-auto text-xs px-2.5 py-1 rounded-full ${overview.model.is_trained ? 'bg-green-400/10 text-green-400' : 'bg-gray-800 text-gray-500'}`}>
              {overview.model.is_trained ? 'Active' : 'Inactive'}
            </span>
          </div>

          <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-4 flex items-center gap-4">
            <div className={`p-2.5 rounded-lg ${overview.system.llm_available ? 'bg-cyber-400/10' : 'bg-gray-800'}`}>
              <Wifi className={`w-5 h-5 ${overview.system.llm_available ? 'text-cyber-400' : 'text-gray-500'}`} />
            </div>
            <div>
              <p className="text-sm font-medium text-gray-200">Ollama LLM</p>
              <p className="text-xs text-gray-500">
                {overview.system.llm_available
                  ? 'AI threat explanation available'
                  : 'Offline — using fallback analysis'}
              </p>
            </div>
            <span className={`ml-auto text-xs px-2.5 py-1 rounded-full ${overview.system.llm_available ? 'bg-cyber-400/10 text-cyber-400' : 'bg-gray-800 text-gray-500'}`}>
              {overview.system.llm_available ? 'Online' : 'Offline'}
            </span>
          </div>
        </div>

        {/* Charts Row 1 */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="xl:col-span-2">
            <TrafficChart data={overview.charts.traffic_timeline} />
          </div>
          <SeverityChart data={overview.alerts.by_severity} />
        </div>

        {/* Charts Row 2 */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="xl:col-span-2">
            <AnomalyTrendChart data={anomalyTrends || []} />
          </div>
          <TopIPsChart data={topIPs?.top_source_ips || []} />
        </div>

        {/* Recent Alerts Table */}
        <RecentAlerts alerts={overview.recent_alerts} />
      </div>
    </div>
  )
}
