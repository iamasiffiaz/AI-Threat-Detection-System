import { useQuery } from '@tanstack/react-query'
import { anomaliesApi } from '../services/api'
import { Header } from '../components/Layout/Header'
import { PageLoader } from '../components/Common/LoadingSpinner'
import { AnomalyTrendChart } from '../components/Dashboard/AnomalyTrendChart'
import { formatDate, formatScore } from '../utils/formatters'
import type { Anomaly } from '../types'
import { Brain, TrendingUp, Target } from 'lucide-react'

function AnomalyScoreBar({ score }: { score: number }) {
  const pct = Math.round(score * 100)
  const color = score >= 0.9 ? 'bg-red-400' : score >= 0.75 ? 'bg-orange-400' : score >= 0.6 ? 'bg-yellow-400' : 'bg-blue-400'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-gray-800 rounded-full h-1.5 max-w-[80px]">
        <div className={`h-1.5 rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-mono font-semibold ${score >= 0.9 ? 'text-red-400' : score >= 0.75 ? 'text-orange-400' : score >= 0.6 ? 'text-yellow-400' : 'text-blue-400'}`}>
        {formatScore(score)}
      </span>
    </div>
  )
}

export function AnomaliesPage() {
  const { data: anomaliesData, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['anomalies'],
    queryFn: async () => (await anomaliesApi.getAll({ page: 1, page_size: 100, min_score: 0.5 })).data,
    refetchInterval: 30_000,
  })

  const { data: trendsData } = useQuery({
    queryKey: ['anomaly-trends-24h'],
    queryFn: async () => (await anomaliesApi.getTrends(24)).data,
    refetchInterval: 60_000,
  })

  const { data: topIPsData } = useQuery({
    queryKey: ['anomaly-top-ips'],
    queryFn: async () => (await anomaliesApi.getTopIPs(10)).data,
    refetchInterval: 60_000,
  })

  const { data: modelInfo } = useQuery({
    queryKey: ['model-info'],
    queryFn: async () => (await anomaliesApi.getModelInfo()).data,
    refetchInterval: 120_000,
  })

  if (isLoading) return <PageLoader />

  const items: Anomaly[] = anomaliesData?.items || []
  const total: number = anomaliesData?.total || 0

  return (
    <div className="flex flex-col flex-1">
      <Header
        title="Anomaly Detection"
        subtitle={`${total.toLocaleString()} anomalies detected`}
        onRefresh={() => refetch()}
        isRefreshing={isFetching}
      />

      <div className="p-6 space-y-6">
        {/* Model Info Card */}
        {modelInfo && (
          <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-5">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Brain className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-gray-200">Anomaly Detection Model</h3>
                <p className="text-xs text-gray-400">{modelInfo.algorithm}</p>
              </div>
              <span className={`ml-auto px-3 py-1 rounded-full text-xs font-medium ${modelInfo.is_trained ? 'bg-green-400/10 text-green-400' : 'bg-gray-800 text-gray-500'}`}>
                {modelInfo.is_trained ? 'Trained & Active' : 'Not Trained'}
              </span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Training Samples', value: modelInfo.training_samples.toLocaleString() },
                { label: 'Detection Threshold', value: `${(modelInfo.threshold * 100).toFixed(0)}%` },
                { label: 'Algorithm', value: modelInfo.algorithm.split(' +')[0] },
                { label: 'Trained At', value: modelInfo.trained_at
                    ? formatDate(modelInfo.trained_at)
                    : 'Never' },
              ].map(({ label, value }) => (
                <div key={label} className="bg-gray-800/50 rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">{label}</p>
                  <p className="text-sm font-semibold text-gray-200">{value}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Charts */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <AnomalyTrendChart data={trendsData || []} />

          {/* Top Anomalous IPs */}
          <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-5">
            <div className="flex items-center gap-2 mb-4">
              <Target className="w-4 h-4 text-orange-400" />
              <h3 className="text-sm font-semibold text-gray-200">Top Anomalous IPs (24h)</h3>
            </div>
            {(topIPsData || []).length === 0 ? (
              <p className="text-sm text-gray-600 text-center py-8">No anomalous IPs detected</p>
            ) : (
              <div className="space-y-3">
                {(topIPsData || []).map((ip: { source_ip: string; count: number; avg_score: number; max_score: number }) => (
                  <div key={ip.source_ip} className="flex items-center gap-3">
                    <span className="text-xs font-mono text-gray-300 w-28 truncate">{ip.source_ip}</span>
                    <div className="flex-1">
                      <AnomalyScoreBar score={ip.max_score} />
                    </div>
                    <span className="text-xs text-gray-500 w-12 text-right">{ip.count}x</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Anomaly Table */}
        <div className="bg-gray-900 rounded-xl border border-gray-700/50 overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-800 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-orange-400" />
            <h3 className="text-sm font-semibold text-gray-200">Recent Anomalies</h3>
            <span className="text-xs text-gray-500 ml-auto">Sorted by score</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {['Detected At', 'Source IP', 'Event Type', 'Model', 'Anomaly Score'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-12 text-center text-gray-500">
                      No anomalies detected. Train the ML model and ingest data.
                    </td>
                  </tr>
                ) : (
                  items.map((a) => (
                    <tr key={a.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                      <td className="px-4 py-3 text-gray-400 font-mono text-xs whitespace-nowrap">
                        {formatDate(a.detected_at)}
                      </td>
                      <td className="px-4 py-3 text-gray-200 font-mono text-xs">{a.source_ip || '—'}</td>
                      <td className="px-4 py-3 text-gray-300 text-xs">{a.event_type || '—'}</td>
                      <td className="px-4 py-3">
                        <span className="text-xs bg-purple-400/10 text-purple-300 border border-purple-400/20 px-2 py-0.5 rounded-md">
                          {a.model_name}
                        </span>
                      </td>
                      <td className="px-4 py-3 min-w-[140px]">
                        <AnomalyScoreBar score={a.anomaly_score} />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
