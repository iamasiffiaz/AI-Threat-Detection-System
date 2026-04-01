import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Brain, ChevronDown, ChevronUp, Filter, X } from 'lucide-react'
import toast from 'react-hot-toast'
import { alertsApi } from '../services/api'
import { Header } from '../components/Layout/Header'
import { SeverityBadge, StatusBadge } from '../components/Common/SeverityBadge'
import { PageLoader } from '../components/Common/LoadingSpinner'
import { formatDate, formatRelativeTime, formatScore } from '../utils/formatters'
import type { Alert, AlertSeverity, AlertStatus } from '../types'

const SEVERITIES: AlertSeverity[] = ['low', 'medium', 'high', 'critical']
const STATUSES: AlertStatus[] = ['open', 'investigating', 'resolved', 'false_positive']

function AlertRow({ alert, onAnalyze }: { alert: Alert; onAnalyze: (id: number) => void }) {
  const [expanded, setExpanded] = useState(false)
  const qc = useQueryClient()

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Record<string, string> }) =>
      alertsApi.update(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      toast.success('Alert updated')
    },
  })

  return (
    <>
      <tr className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors cursor-pointer"
          onClick={() => setExpanded(!expanded)}>
        <td className="px-4 py-3 text-gray-400 text-xs font-mono whitespace-nowrap">
          {formatRelativeTime(alert.triggered_at)}
        </td>
        <td className="px-4 py-3">
          <p className="text-sm text-gray-200 font-medium">{alert.title}</p>
          {alert.rule_name && (
            <p className="text-xs text-gray-500 mt-0.5">Rule: {alert.rule_name}</p>
          )}
        </td>
        <td className="px-4 py-3"><SeverityBadge severity={alert.severity} /></td>
        <td className="px-4 py-3"><StatusBadge status={alert.status} /></td>
        <td className="px-4 py-3 text-gray-400 font-mono text-xs">{alert.source_ip || '—'}</td>
        <td className="px-4 py-3 text-gray-400 text-xs">{formatScore(alert.anomaly_score)}</td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <button
              onClick={(e) => { e.stopPropagation(); onAnalyze(alert.id) }}
              className="flex items-center gap-1 text-xs text-cyber-400 hover:text-cyber-300 px-2 py-1 rounded-md hover:bg-cyber-400/10 transition-colors"
            >
              <Brain className="w-3 h-3" /> AI Analysis
            </button>
            {expanded ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
          </div>
        </td>
      </tr>

      {expanded && (
        <tr className="border-b border-gray-800/50 bg-gray-800/20">
          <td colSpan={7} className="px-4 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Description */}
              <div>
                <p className="text-xs font-medium text-gray-400 mb-1">Description</p>
                <p className="text-sm text-gray-300">{alert.description}</p>

                {alert.attack_type && (
                  <div className="mt-3">
                    <p className="text-xs font-medium text-gray-400 mb-1">Attack Type</p>
                    <span className="text-xs bg-red-400/10 border border-red-400/20 text-red-400 px-2 py-1 rounded-md">
                      {alert.attack_type}
                    </span>
                  </div>
                )}

                {/* Status Update */}
                <div className="mt-3">
                  <p className="text-xs font-medium text-gray-400 mb-1.5">Update Status</p>
                  <div className="flex gap-2 flex-wrap">
                    {STATUSES.map(s => (
                      <button
                        key={s}
                        onClick={(e) => {
                          e.stopPropagation()
                          updateMutation.mutate({ id: alert.id, data: { status: s } })
                        }}
                        className={`text-xs px-2.5 py-1 rounded-md border transition-colors capitalize ${
                          alert.status === s
                            ? 'bg-cyber-500/20 text-cyber-300 border-cyber-500/30'
                            : 'bg-gray-800 text-gray-400 border-gray-700 hover:border-gray-600'
                        }`}
                      >
                        {s.replace('_', ' ')}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* LLM Analysis */}
              {(alert.llm_explanation || alert.mitigation_steps) && (
                <div>
                  {alert.llm_explanation && (
                    <div className="mb-3">
                      <p className="text-xs font-medium text-gray-400 mb-1">AI Explanation</p>
                      <p className="text-sm text-gray-300">{alert.llm_explanation}</p>
                    </div>
                  )}
                  {alert.mitigation_steps && (
                    <div>
                      <p className="text-xs font-medium text-gray-400 mb-1">Mitigation Steps</p>
                      <div className="text-sm text-gray-300 whitespace-pre-line">{alert.mitigation_steps}</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export function AlertsPage() {
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState<{ severity?: AlertSeverity; status?: AlertStatus }>({})
  const [showFilters, setShowFilters] = useState(false)

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['alerts', page, filters],
    queryFn: async () => (await alertsApi.getAll({ page, page_size: 50, ...filters })).data,
    refetchInterval: 15_000,
    placeholderData: (prev) => prev,
  })

  const { data: summary } = useQuery({
    queryKey: ['alert-summary'],
    queryFn: async () => (await alertsApi.getSummary()).data,
    refetchInterval: 15_000,
  })

  const analyzeMutation = useMutation({
    mutationFn: (id: number) => alertsApi.analyze(id),
    onSuccess: () => {
      toast.success('AI analysis complete!')
      qc.invalidateQueries({ queryKey: ['alerts'] })
    },
    onError: () => toast.error('Analysis failed'),
  })

  if (isLoading) return <PageLoader />

  const items: Alert[] = data?.items || []
  const total: number = data?.total || 0
  const pages: number = data?.pages || 1

  return (
    <div className="flex flex-col flex-1">
      <Header
        title="Security Alerts"
        subtitle={`${summary?.open_alerts || 0} open alerts requiring attention`}
        onRefresh={() => refetch()}
        isRefreshing={isFetching}
      />

      <div className="p-6 space-y-4">
        {/* Summary Cards */}
        {summary && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { label: 'Total Alerts', value: summary.total_alerts, color: 'text-gray-200' },
              { label: 'Open', value: summary.open_alerts, color: 'text-red-400' },
              { label: 'Critical', value: summary.critical_alerts, color: 'text-red-400' },
              { label: 'Last 24h', value: summary.alerts_last_24h, color: 'text-orange-400' },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-gray-900 rounded-xl border border-gray-700/50 px-4 py-3">
                <p className="text-xs text-gray-500">{label}</p>
                <p className={`text-2xl font-bold mt-1 ${color}`}>{value.toLocaleString()}</p>
              </div>
            ))}
          </div>
        )}

        {/* Action Bar */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${showFilters ? 'bg-cyber-500/20 text-cyber-300 border border-cyber-500/30' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
          >
            <Filter className="w-4 h-4" /> Filters
          </button>
        </div>

        {showFilters && (
          <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-4 flex items-center gap-4 flex-wrap">
            <select
              value={filters.severity || ''}
              onChange={(e) => setFilters(f => ({ ...f, severity: e.target.value as AlertSeverity || undefined }))}
              className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:border-cyber-500"
            >
              <option value="">All Severities</option>
              {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>

            <select
              value={filters.status || ''}
              onChange={(e) => setFilters(f => ({ ...f, status: e.target.value as AlertStatus || undefined }))}
              className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:border-cyber-500"
            >
              <option value="">All Statuses</option>
              {STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>

            {(filters.severity || filters.status) && (
              <button onClick={() => setFilters({})} className="flex items-center gap-1 text-xs text-red-400 hover:text-red-300">
                <X className="w-3 h-3" /> Clear
              </button>
            )}
          </div>
        )}

        {/* Alerts Table */}
        <div className="bg-gray-900 rounded-xl border border-gray-700/50 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {['Time', 'Alert', 'Severity', 'Status', 'Source IP', 'Anomaly Score', 'Actions'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-gray-500">
                      No alerts found. Generate sample data to see alerts.
                    </td>
                  </tr>
                ) : (
                  items.map((alert) => (
                    <AlertRow
                      key={alert.id}
                      alert={alert}
                      onAnalyze={(id) => analyzeMutation.mutate(id)}
                    />
                  ))
                )}
              </tbody>
            </table>
          </div>

          {pages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-800">
              <span className="text-xs text-gray-500">
                Page {page} of {pages} ({total.toLocaleString()} alerts)
              </span>
              <div className="flex gap-2">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  className="px-3 py-1 text-xs bg-gray-800 rounded-lg text-gray-400 hover:bg-gray-700 disabled:opacity-40">Previous</button>
                <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page === pages}
                  className="px-3 py-1 text-xs bg-gray-800 rounded-lg text-gray-400 hover:bg-gray-700 disabled:opacity-40">Next</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
