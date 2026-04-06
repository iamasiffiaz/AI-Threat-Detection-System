import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, RefreshCw, Search, Filter, ExternalLink, Shield, Globe, Zap } from 'lucide-react'
import { alertsApi, socAssistantApi, soarApi } from '../services/api'
import { type Alert, type AlertSeverity, type AlertStatus } from '../types'
import { LoadingSpinner } from '../components/common/LoadingSpinner'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { RiskBadge } from '../components/common/RiskBadge'
import { format } from 'date-fns'
import toast from 'react-hot-toast'

const STATUS_COLORS: Record<string, string> = {
  open:           'text-red-400    bg-red-500/10    border-red-500/20',
  investigating:  'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  resolved:       'text-green-400  bg-green-500/10  border-green-500/20',
  false_positive: 'text-gray-400   bg-gray-500/10   border-gray-500/20',
}

function AlertDetailPanel({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [aiAnswer, setAiAnswer] = useState<string>('')
  const [aiLoading, setAiLoading] = useState(false)

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: object }) => alertsApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      toast.success('Alert updated')
    },
  })

  const blockMutation = useMutation({
    mutationFn: (ip: string) =>
      soarApi.blockIP({ ip_address: ip, reason: `Manual block from alert #${alert.id}` }),
    onSuccess: () => toast.success('IP blocked via SOAR'),
    onError: () => toast.error('Block failed'),
  })

  const handleAsk = async (mode: 'explain' | 'advise') => {
    setAiLoading(true)
    try {
      const fn = mode === 'explain'
        ? () => socAssistantApi.explainAlert(alert.id)
        : () => socAssistantApi.adviseAlert(alert.id)
      const { data } = await fn()
      setAiAnswer(data.answer)
    } catch {
      toast.error('AI assistant unavailable')
    } finally {
      setAiLoading(false)
    }
  }

  const mitre = (() => {
    if (!alert.mitre_ttps) return []
    try { return JSON.parse(alert.mitre_ttps) } catch { return [alert.mitre_ttps] }
  })()

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-gray-800">
          <div className="flex-1 pr-4">
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge severity={alert.severity} />
              {alert.risk_score != null && <RiskBadge score={alert.risk_score} showLabel />}
              <span className={`text-xs px-2 py-0.5 rounded-full border ${STATUS_COLORS[alert.status]}`}>
                {alert.status}
              </span>
            </div>
            <h2 className="text-base font-semibold text-white mt-1">{alert.title}</h2>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-lg font-bold">✕</button>
        </div>

        <div className="p-5 space-y-4">
          {/* Core Info Grid */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'Source IP',    value: alert.source_ip ?? '—' },
              { label: 'Attack Type',  value: alert.attack_type ?? 'Unknown' },
              { label: 'Rule',         value: alert.rule_name ?? '—' },
              { label: 'Kill Chain',   value: alert.kill_chain_phase ?? '—' },
              { label: 'Geo Country',  value: alert.geo_country ?? '—' },
              { label: 'TI Reputation', value: alert.threat_reputation != null ? `${alert.threat_reputation.toFixed(0)}/100` : '—' },
              { label: 'Anomaly Score', value: alert.anomaly_score?.toFixed(3) ?? '—' },
              { label: 'FP Likelihood', value: alert.false_positive_likelihood ?? '—' },
            ].map(item => (
              <div key={item.label} className="bg-gray-800/60 rounded-lg p-3">
                <p className="text-xs text-gray-500">{item.label}</p>
                <p className="text-sm font-medium text-gray-200 mt-0.5 font-mono">{item.value}</p>
              </div>
            ))}
          </div>

          {/* MITRE TTPs */}
          {mitre.length > 0 && (
            <div>
              <p className="text-xs text-gray-500 mb-2">MITRE ATT&CK TTPs</p>
              <div className="flex flex-wrap gap-1.5">
                {mitre.map((ttp: string) => (
                  <span key={ttp} className="text-xs px-2 py-0.5 rounded bg-purple-500/15 border border-purple-500/30 text-purple-300 font-mono">
                    {ttp}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Description */}
          <div>
            <p className="text-xs text-gray-500 mb-1">Description</p>
            <p className="text-sm text-gray-300">{alert.description}</p>
          </div>

          {/* LLM Explanation */}
          {alert.llm_explanation && (
            <div className="bg-gray-800/60 rounded-lg p-4 border border-cyber-500/20">
              <p className="text-xs text-cyber-400 mb-2 font-semibold">AI Analysis</p>
              <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">{alert.llm_explanation}</p>
            </div>
          )}

          {/* Mitigation Steps */}
          {alert.mitigation_steps && (
            <div>
              <p className="text-xs text-gray-500 mb-2">Recommended Mitigation</p>
              <div className="bg-gray-800/40 rounded-lg p-3">
                <p className="text-sm text-gray-300 whitespace-pre-wrap">{alert.mitigation_steps}</p>
              </div>
            </div>
          )}

          {/* AI Query Buttons */}
          <div className="flex gap-2">
            <button
              onClick={() => handleAsk('explain')}
              disabled={aiLoading}
              className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg bg-cyber-500/10 border border-cyber-500/30 text-cyber-300 text-sm hover:bg-cyber-500/20 transition-colors disabled:opacity-50"
            >
              {aiLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
              Explain Alert
            </button>
            <button
              onClick={() => handleAsk('advise')}
              disabled={aiLoading}
              className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-300 text-sm hover:bg-purple-500/20 transition-colors disabled:opacity-50"
            >
              <Shield className="w-3.5 h-3.5" />
              What Should I Do?
            </button>
          </div>

          {/* AI Answer */}
          {aiAnswer && (
            <div className="bg-gray-800/80 rounded-lg p-4 border border-gray-700">
              <p className="text-xs text-gray-500 mb-2">AI Response</p>
              <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">{aiAnswer}</p>
            </div>
          )}

          {/* Actions */}
          <div className="flex flex-wrap gap-2 pt-2 border-t border-gray-800">
            {['investigating', 'resolved', 'false_positive'].map(s => (
              <button
                key={s}
                onClick={() => updateMutation.mutate({ id: alert.id, data: { status: s } })}
                className="text-xs px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-300 hover:border-gray-600 transition-colors capitalize"
              >
                Mark {s.replace('_', ' ')}
              </button>
            ))}
            {alert.source_ip && (
              <button
                onClick={() => blockMutation.mutate(alert.source_ip!)}
                className="text-xs px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 transition-colors"
              >
                Block IP
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export function AlertsPage() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<AlertSeverity | ''>('')
  const [statusFilter, setStatusFilter] = useState<AlertStatus | ''>('')
  const [selected, setSelected] = useState<Alert | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['alerts', page, severityFilter, statusFilter],
    queryFn: () => alertsApi.getAll({
      page,
      page_size: 50,
      severity: severityFilter || undefined,
      status: statusFilter || undefined,
    }).then(r => r.data),
  })

  const reanalyzeMutation = useMutation({
    mutationFn: () => alertsApi.reanalyzeAll(),
    onSuccess: (r) => {
      toast.success(`Re-analyzing ${r.data.reanalysis_triggered} alerts`)
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const alerts: Alert[] = data?.items ?? []
  const filtered = search
    ? alerts.filter(a =>
        a.title.toLowerCase().includes(search.toLowerCase()) ||
        a.source_ip?.includes(search) ||
        a.attack_type?.toLowerCase().includes(search.toLowerCase())
      )
    : alerts

  if (isLoading) return <LoadingSpinner />

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Bell className="w-6 h-6 text-orange-400" />
            Alerts
          </h1>
          <p className="text-sm text-gray-400 mt-0.5">{data?.total ?? 0} total alerts</p>
        </div>
        <button
          onClick={() => reanalyzeMutation.mutate()}
          disabled={reanalyzeMutation.isPending}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-cyber-500/10 border border-cyber-500/30 text-cyber-300 text-sm hover:bg-cyber-500/20 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${reanalyzeMutation.isPending ? 'animate-spin' : ''}`} />
          Re-analyze All
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-48 relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search alerts, IPs, types…"
            className="w-full pl-8 pr-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyber-500"
          />
        </div>
        <select
          value={severityFilter}
          onChange={e => { setSeverityFilter(e.target.value as AlertSeverity | ''); setPage(1) }}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-cyber-500"
        >
          <option value="">All Severities</option>
          {['critical','high','medium','low'].map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={e => { setStatusFilter(e.target.value as AlertStatus | ''); setPage(1) }}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-cyber-500"
        >
          <option value="">All Statuses</option>
          {['open','investigating','resolved','false_positive'].map(s => (
            <option key={s} value={s}>{s.replace('_',' ')}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700 bg-gray-900/50">
              {['Severity','Title','Source IP','Attack Type','Risk','Status','Geo','Time',''].map(h => (
                <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(alert => (
              <tr
                key={alert.id}
                onClick={() => setSelected(alert)}
                className="border-b border-gray-700/30 hover:bg-gray-700/30 cursor-pointer transition-colors"
              >
                <td className="px-4 py-3"><SeverityBadge severity={alert.severity} /></td>
                <td className="px-4 py-3 max-w-xs">
                  <p className="text-gray-200 font-medium truncate">{alert.title}</p>
                  {alert.rule_name && (
                    <p className="text-xs text-gray-500 truncate">{alert.rule_name}</p>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="font-mono text-gray-300 text-xs">{alert.source_ip ?? '—'}</span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-gray-400">{alert.attack_type ?? '—'}</span>
                </td>
                <td className="px-4 py-3">
                  <RiskBadge score={alert.risk_score} />
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-0.5 rounded-full border ${STATUS_COLORS[alert.status]}`}>
                    {alert.status}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {alert.geo_country ? (
                    <span className="flex items-center gap-1 text-xs text-gray-400">
                      <Globe className="w-3 h-3" />
                      {alert.geo_country}
                    </span>
                  ) : <span className="text-gray-600">—</span>}
                </td>
                <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                  {format(new Date(alert.triggered_at), 'MM/dd HH:mm')}
                </td>
                <td className="px-4 py-3">
                  <ExternalLink className="w-3.5 h-3.5 text-gray-600 hover:text-cyber-400" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="py-16 text-center text-gray-600">
            <Bell className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p>No alerts found</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {(data?.pages ?? 0) > 1 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-500">Page {page} of {data?.pages}</span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(p => p - 1)}
              className="px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-300 disabled:opacity-40"
            >Previous</button>
            <button
              disabled={page >= (data?.pages ?? 1)}
              onClick={() => setPage(p => p + 1)}
              className="px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-300 disabled:opacity-40"
            >Next</button>
          </div>
        </div>
      )}

      {/* Detail Panel */}
      {selected && <AlertDetailPanel alert={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
