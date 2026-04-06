import { useQuery } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, Eye, TrendingUp, Shield,
  Siren, Lock, Globe, Zap, Server,
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { dashboardApi, incidentsApi, soarApi } from '../services/api'
import { LoadingSpinner } from '../components/common/LoadingSpinner'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { RiskBadge } from '../components/common/RiskBadge'
import { format } from 'date-fns'
import { Link } from 'react-router-dom'

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
}

const ATTACK_COLORS = [
  '#6366f1','#ec4899','#f97316','#eab308','#22c55e',
  '#06b6d4','#8b5cf6','#14b8a6','#f43f5e','#84cc16',
]

function StatCard({
  icon: Icon, label, value, sub, color = 'cyber',
}: {
  icon: React.ElementType
  label: string
  value: string | number
  sub?: string
  color?: string
}) {
  const colorMap: Record<string, string> = {
    cyber:  'bg-cyber-500/10  border-cyber-500/20  text-cyber-400',
    red:    'bg-red-500/10    border-red-500/20    text-red-400',
    orange: 'bg-orange-500/10 border-orange-500/20 text-orange-400',
    green:  'bg-green-500/10  border-green-500/20  text-green-400',
    purple: 'bg-purple-500/10 border-purple-500/20 text-purple-400',
    blue:   'bg-blue-500/10   border-blue-500/20   text-blue-400',
  }
  return (
    <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5 flex items-start gap-4">
      <div className={`p-2.5 rounded-lg border ${colorMap[color]}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-2xl font-bold text-white">{value}</p>
        <p className="text-sm text-gray-400">{label}</p>
        {sub && <p className="text-xs text-gray-500 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

export function DashboardPage() {
  const { data: overview, isLoading } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: () => dashboardApi.getOverview().then(r => r.data),
    refetchInterval: 15_000,
  })

  const { data: incidentSummary } = useQuery({
    queryKey: ['incidents-summary'],
    queryFn: () => incidentsApi.getSummary().then(r => r.data),
    refetchInterval: 30_000,
  })

  const { data: soarStats } = useQuery({
    queryKey: ['soar-stats'],
    queryFn: () => soarApi.getStats().then(r => r.data),
    refetchInterval: 60_000,
  })

  if (isLoading) return <LoadingSpinner />

  const d = overview
  const severityData = Object.entries(d?.alerts?.by_severity ?? {}).map(([k, v]) => ({
    name: k.charAt(0).toUpperCase() + k.slice(1),
    value: v as number,
    color: SEV_COLORS[k] ?? '#6b7280',
  }))

  const timeline = (d?.charts?.traffic_timeline ?? []).map((t: { timestamp: string; count: number }) => ({
    time: format(new Date(t.timestamp), 'HH:mm'),
    logs: t.count,
  }))

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">SOC Dashboard</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Enterprise Threat Detection Platform
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-800 border border-gray-700">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-xs text-gray-300">Live</span>
          {d?.system?.llm_available && (
            <>
              <span className="text-gray-600">·</span>
              <span className="text-xs text-cyber-400">AI Active</span>
            </>
          )}
        </div>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-4">
        <StatCard icon={Activity}       label="Logs (24h)"       value={d?.logs?.last_24h ?? 0}           color="cyber"  />
        <StatCard icon={AlertTriangle}  label="Open Alerts"      value={d?.alerts?.open ?? 0}              color="orange" />
        <StatCard icon={Siren}          label="Open Incidents"   value={incidentSummary?.open ?? 0}        color="red"    />
        <StatCard icon={Eye}            label="Critical Alerts"  value={d?.alerts?.critical ?? 0}          color="red"    />
        <StatCard icon={Lock}           label="Blocked IPs"      value={soarStats?.active_blocks ?? 0}     color="purple" />
        <StatCard icon={Globe}          label="Block Hits"       value={soarStats?.total_block_hits ?? 0}  color="blue"   />
      </div>

      {/* Incident + Risk row */}
      {incidentSummary && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-gray-300">Incident Status</h3>
              <Link to="/incidents" className="text-xs text-cyber-400 hover:text-cyber-300">View all →</Link>
            </div>
            <div className="space-y-2">
              {[
                { label: 'Open',           value: incidentSummary.open,         color: 'bg-red-400' },
                { label: 'Investigating',  value: incidentSummary.investigating, color: 'bg-orange-400' },
                { label: 'Resolved',       value: incidentSummary.resolved,      color: 'bg-green-400' },
              ].map(row => (
                <div key={row.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${row.color}`} />
                    <span className="text-sm text-gray-400">{row.label}</span>
                  </div>
                  <span className="text-sm font-semibold text-white">{row.value}</span>
                </div>
              ))}
            </div>
            <div className="mt-4 pt-3 border-t border-gray-700">
              <div className="flex justify-between text-xs text-gray-500">
                <span>Avg Risk Score</span>
                <span className="font-mono text-orange-400">{incidentSummary.avg_risk_score?.toFixed(1)}</span>
              </div>
            </div>
          </div>

          {/* Alert Severity Pie */}
          <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-3">Alert Severity Distribution</h3>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie data={severityData} cx="50%" cy="50%" innerRadius={40} outerRadius={60} dataKey="value">
                    {severityData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', fontSize: '12px' }}
                    formatter={(v: number, name: string) => [v, name]}
                  />
                  <Legend iconType="circle" iconSize={8}
                    formatter={(v) => <span style={{ color: '#9ca3af', fontSize: '12px' }}>{v}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-36 flex items-center justify-center text-gray-600 text-sm">No alerts yet</div>
            )}
          </div>

          {/* System Health */}
          <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-4">System Health</h3>
            <div className="space-y-3">
              {[
                { label: 'ML Model',        ok: d?.model?.is_trained,          detail: d?.model?.algorithm },
                { label: 'LLM (Ollama)',     ok: d?.system?.llm_available,      detail: 'Threat analysis' },
                { label: 'Detection Rules',  ok: true,                          detail: '15 active rules' },
                { label: 'Correlation Eng.', ok: true,                          detail: '4 strategies' },
                { label: 'SOAR Engine',      ok: true,                          detail: '9 playbooks' },
              ].map(row => (
                <div key={row.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${row.ok ? 'bg-green-400' : 'bg-red-400'}`} />
                    <span className="text-xs text-gray-400">{row.label}</span>
                  </div>
                  <span className="text-xs text-gray-600">{row.detail}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Traffic Timeline */}
      <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-gray-300 mb-4">Log Traffic — Last 24h</h3>
        {timeline.length > 0 ? (
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="logGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}   />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 11 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', fontSize: '12px' }}
              />
              <Area type="monotone" dataKey="logs" stroke="#06b6d4" strokeWidth={2} fill="url(#logGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-44 flex items-center justify-center text-gray-600 text-sm">
            Ingest logs to see traffic data
          </div>
        )}
      </div>

      {/* Recent Alerts + ML Info */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Recent Alerts */}
        <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-300">Recent Alerts</h3>
            <Link to="/alerts" className="text-xs text-cyber-400 hover:text-cyber-300">View all →</Link>
          </div>
          <div className="space-y-2">
            {(d?.recent_alerts ?? []).slice(0, 8).map((a: { id: number; title: string; severity: string; status: string; risk_score?: number | null; attack_type?: string | null; triggered_at: string }) => (
              <div key={a.id} className="flex items-center gap-3 p-2.5 rounded-lg bg-gray-900/60 hover:bg-gray-900 transition-colors">
                <SeverityBadge severity={a.severity as never} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-gray-200 truncate">{a.title}</p>
                  <p className="text-xs text-gray-500">{a.attack_type ?? 'Unknown'}</p>
                </div>
                {a.risk_score != null && <RiskBadge score={a.risk_score} />}
              </div>
            ))}
            {!d?.recent_alerts?.length && (
              <p className="text-center text-gray-600 text-sm py-8">No alerts yet</p>
            )}
          </div>
        </div>

        {/* ML Model info + top anomalous IPs */}
        <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-300">ML Detection Engine</h3>
            <span className={`text-xs px-2 py-0.5 rounded-full border ${
              d?.model?.is_trained
                ? 'text-green-400 bg-green-500/10 border-green-500/20'
                : 'text-red-400 bg-red-500/10 border-red-500/20'
            }`}>
              {d?.model?.is_trained ? 'Trained' : 'Untrained'}
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3 mb-4">
            {[
              { label: 'Algorithm',   value: d?.model?.algorithm ?? '—' },
              { label: 'Samples',     value: d?.model?.training_samples?.toLocaleString() ?? '0' },
              { label: 'Threshold',   value: d?.model?.threshold?.toFixed(2) ?? '0.60' },
              { label: 'Total Logs',  value: d?.logs?.total?.toLocaleString() ?? '0' },
            ].map(item => (
              <div key={item.label} className="bg-gray-900/60 rounded-lg p-3">
                <p className="text-xs text-gray-500">{item.label}</p>
                <p className="text-sm font-semibold text-gray-200 mt-0.5">{item.value}</p>
              </div>
            ))}
          </div>
          <div>
            <p className="text-xs text-gray-500 mb-2">Recent Anomalies</p>
            {(d?.recent_anomalies ?? []).slice(0, 4).map((a: { id: number; source_ip: string | null; anomaly_score: number; detected_at: string }) => (
              <div key={a.id} className="flex justify-between items-center py-1.5 border-b border-gray-700/50 last:border-0">
                <span className="text-xs text-gray-400 font-mono">{a.source_ip ?? 'Unknown'}</span>
                <span className="text-xs font-mono text-orange-400">{a.anomaly_score.toFixed(3)}</span>
              </div>
            ))}
            {!d?.recent_anomalies?.length && (
              <p className="text-center text-gray-600 text-xs py-4">No anomalies detected</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
