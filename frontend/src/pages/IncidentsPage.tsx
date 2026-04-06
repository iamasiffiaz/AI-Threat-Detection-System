import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Siren, ChevronDown, Globe, Shield, Clock, ArrowUp } from 'lucide-react'
import { incidentsApi, socAssistantApi } from '../services/api'
import { type Incident, type IncidentStatus, type IncidentSeverity } from '../types'
import { LoadingSpinner } from '../components/common/LoadingSpinner'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { RiskBadge } from '../components/common/RiskBadge'
import { format, formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'

const STATUS_COLORS: Record<string, string> = {
  open:           'text-red-400    bg-red-500/10    border-red-500/20',
  investigating:  'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  contained:      'text-blue-400   bg-blue-500/10   border-blue-500/20',
  resolved:       'text-green-400  bg-green-500/10  border-green-500/20',
  false_positive: 'text-gray-400   bg-gray-500/10   border-gray-500/20',
}

function IncidentDetail({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [aiSummary, setAiSummary] = useState('')
  const [aiLoading, setAiLoading] = useState(false)

  const { data: timeline } = useQuery({
    queryKey: ['incident-timeline', incident.id],
    queryFn: () => incidentsApi.getTimeline(incident.id).then(r => r.data),
  })

  const updateMutation = useMutation({
    mutationFn: (data: object) => incidentsApi.update(incident.id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      toast.success('Incident updated')
    },
  })

  const escalateMutation = useMutation({
    mutationFn: () => incidentsApi.escalate(incident.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      toast.success('Incident escalated')
    },
  })

  const handleAISummary = async () => {
    setAiLoading(true)
    try {
      const { data } = await socAssistantApi.incidentSummary(incident.id)
      setAiSummary(data.answer)
    } catch {
      toast.error('AI assistant unavailable')
    } finally {
      setAiLoading(false)
    }
  }

  const attackTypes = incident.attack_types ?? []
  const phases = incident.kill_chain_phases ?? []

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-3xl max-h-[92vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-gray-800">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge severity={incident.severity as never} />
              <RiskBadge score={incident.risk_score} showLabel />
              <span className={`text-xs px-2 py-0.5 rounded-full border ${STATUS_COLORS[incident.status]}`}>
                {incident.status}
              </span>
              {incident.is_known_bad_ip && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/15 border border-red-500/30 text-red-400">
                  Known Bad IP
                </span>
              )}
            </div>
            <h2 className="text-base font-semibold text-white mt-1">{incident.title}</h2>
            <p className="text-xs text-gray-500 mt-0.5">
              First seen {formatDistanceToNow(new Date(incident.first_seen))} ago
              · Last activity {formatDistanceToNow(new Date(incident.last_seen))} ago
            </p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-lg font-bold ml-4">✕</button>
        </div>

        <div className="p-5 space-y-4">
          {/* Info Grid */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'Source IP',    value: incident.source_ip ?? '—', mono: true },
              { label: 'Alerts',       value: incident.alert_count },
              { label: 'Risk Score',   value: `${incident.risk_score}/100` },
              { label: 'Country',      value: incident.geo_country ?? '—' },
              { label: 'TI Rep Score', value: incident.threat_reputation != null ? `${incident.threat_reputation.toFixed(0)}/100` : '—' },
              { label: 'Assigned To',  value: incident.assigned_to ?? 'Unassigned' },
            ].map(item => (
              <div key={item.label} className="bg-gray-800/60 rounded-lg p-3">
                <p className="text-xs text-gray-500">{item.label}</p>
                <p className={`text-sm font-medium text-gray-200 mt-0.5 ${item.mono ? 'font-mono' : ''}`}>
                  {String(item.value)}
                </p>
              </div>
            ))}
          </div>

          {/* Attack Types + Kill Chain */}
          {(attackTypes.length > 0 || phases.length > 0) && (
            <div className="flex gap-6">
              {attackTypes.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-2">Attack Types</p>
                  <div className="flex flex-wrap gap-1.5">
                    {attackTypes.map(t => (
                      <span key={t} className="text-xs px-2 py-0.5 rounded bg-orange-500/15 border border-orange-500/30 text-orange-300">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {phases.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-2">Kill Chain Phases</p>
                  <div className="flex flex-wrap gap-1.5">
                    {phases.map(p => (
                      <span key={p} className="text-xs px-2 py-0.5 rounded bg-purple-500/15 border border-purple-500/30 text-purple-300">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* AI Summary */}
          {incident.llm_summary ? (
            <div className="bg-gray-800/60 rounded-lg p-4 border border-cyber-500/20">
              <p className="text-xs text-cyber-400 mb-2 font-semibold">AI Incident Summary</p>
              <p className="text-sm text-gray-300 leading-relaxed">{incident.llm_summary}</p>
            </div>
          ) : (
            <button
              onClick={handleAISummary}
              disabled={aiLoading}
              className="w-full py-2.5 rounded-lg bg-cyber-500/10 border border-cyber-500/30 text-cyber-300 text-sm hover:bg-cyber-500/20 transition-colors"
            >
              {aiLoading ? 'Generating summary…' : '✦ Generate AI Incident Summary'}
            </button>
          )}
          {aiSummary && !incident.llm_summary && (
            <div className="bg-gray-800/60 rounded-lg p-4 border border-cyber-500/20">
              <p className="text-xs text-cyber-400 mb-2 font-semibold">AI Incident Summary</p>
              <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">{aiSummary}</p>
            </div>
          )}

          {/* Playbook */}
          {incident.recommended_playbook && (
            <div className="bg-gray-800/40 rounded-lg p-3 border border-gray-700">
              <p className="text-xs text-gray-500 mb-1">Recommended Playbook</p>
              <p className="text-sm text-gray-200">{incident.recommended_playbook}</p>
            </div>
          )}

          {/* Alert Timeline */}
          {Array.isArray(timeline) && timeline.length > 0 && (
            <div>
              <p className="text-xs text-gray-500 mb-2">Alert Timeline ({timeline.length})</p>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {timeline.map((a: { id: number; title: string; severity: string; risk_score?: number | null; attack_type?: string | null; triggered_at: string }) => (
                  <div key={a.id} className="flex items-center gap-3 p-2 rounded bg-gray-800/60">
                    <SeverityBadge severity={a.severity as never} />
                    <span className="text-xs text-gray-300 flex-1 truncate">{a.title}</span>
                    {a.risk_score != null && <RiskBadge score={a.risk_score} />}
                    <span className="text-xs text-gray-600 whitespace-nowrap">
                      {format(new Date(a.triggered_at), 'HH:mm:ss')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex flex-wrap gap-2 pt-2 border-t border-gray-800">
            {(['investigating','contained','resolved','false_positive'] as IncidentStatus[]).map(s => (
              <button
                key={s}
                onClick={() => updateMutation.mutate({ status: s })}
                className="text-xs px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-300 hover:border-gray-600 capitalize transition-colors"
              >
                {s.replace('_',' ')}
              </button>
            ))}
            <button
              onClick={() => escalateMutation.mutate()}
              className="text-xs px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 flex items-center gap-1 transition-colors"
            >
              <ArrowUp className="w-3 h-3" />
              Escalate
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | ''>('')
  const [severityFilter, setSeverityFilter] = useState<IncidentSeverity | ''>('')
  const [selected, setSelected] = useState<Incident | null>(null)

  const { data: summary } = useQuery({
    queryKey: ['incidents-summary'],
    queryFn: () => incidentsApi.getSummary().then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: incidents, isLoading } = useQuery({
    queryKey: ['incidents', statusFilter, severityFilter],
    queryFn: () => incidentsApi.getAll({
      status:   statusFilter || undefined,
      severity: severityFilter || undefined,
      limit: 100,
    }).then(r => r.data),
    refetchInterval: 15_000,
  })

  if (isLoading) return <LoadingSpinner />

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Siren className="w-6 h-6 text-red-400" />
          Incident Management
        </h1>
        <p className="text-sm text-gray-400 mt-0.5">Correlated multi-event security incidents</p>
      </div>

      {/* Summary Tiles */}
      {summary && (
        <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
          {[
            { label: 'Total',        value: summary.total,         color: 'text-gray-200' },
            { label: 'Open',         value: summary.open,          color: 'text-red-400' },
            { label: 'Investigating',value: summary.investigating,  color: 'text-yellow-400' },
            { label: 'Resolved',     value: summary.resolved,       color: 'text-green-400' },
            { label: 'Critical',     value: summary.critical,       color: 'text-red-400' },
            { label: 'Avg Risk',     value: summary.avg_risk_score?.toFixed(1), color: 'text-orange-400' },
          ].map(tile => (
            <div key={tile.label} className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-4 text-center">
              <p className={`text-2xl font-bold ${tile.color}`}>{tile.value}</p>
              <p className="text-xs text-gray-500 mt-1">{tile.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3">
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value as IncidentStatus | '')}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-cyber-500"
        >
          <option value="">All Statuses</option>
          {['open','investigating','contained','resolved','false_positive'].map(s => (
            <option key={s} value={s}>{s.replace('_',' ')}</option>
          ))}
        </select>
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value as IncidentSeverity | '')}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-cyber-500"
        >
          <option value="">All Severities</option>
          {['critical','high','medium','low'].map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
      </div>

      {/* Incidents List */}
      <div className="space-y-3">
        {(incidents ?? []).map((inc: Incident) => (
          <div
            key={inc.id}
            onClick={() => setSelected(inc)}
            className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-4 cursor-pointer hover:border-gray-600 transition-colors"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={inc.severity as never} />
                <RiskBadge score={inc.risk_score} showLabel />
                <span className={`text-xs px-2 py-0.5 rounded-full border ${STATUS_COLORS[inc.status]}`}>
                  {inc.status}
                </span>
                {inc.is_known_bad_ip && (
                  <span className="text-xs text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                    Known Bad IP
                  </span>
                )}
              </div>
              <div className="flex items-center gap-3 text-xs text-gray-500 shrink-0">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {formatDistanceToNow(new Date(inc.last_seen))} ago
                </span>
                <span className="text-gray-600">{inc.alert_count} alerts</span>
              </div>
            </div>
            <h3 className="text-sm font-semibold text-gray-200 mt-2">{inc.title}</h3>
            <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
              <span className="font-mono text-gray-400">{inc.source_ip ?? '—'}</span>
              {inc.geo_country && (
                <span className="flex items-center gap-1">
                  <Globe className="w-3 h-3" />
                  {inc.geo_country}
                </span>
              )}
              {(inc.attack_types ?? []).length > 0 && (
                <span className="text-orange-400">{inc.attack_types!.join(', ')}</span>
              )}
            </div>
          </div>
        ))}
        {(incidents ?? []).length === 0 && (
          <div className="py-20 text-center">
            <Siren className="w-12 h-12 mx-auto mb-3 text-gray-700" />
            <p className="text-gray-500">No incidents found</p>
            <p className="text-xs text-gray-600 mt-1">Incidents are auto-created when 3+ alerts correlate from the same source</p>
          </div>
        )}
      </div>

      {selected && <IncidentDetail incident={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
