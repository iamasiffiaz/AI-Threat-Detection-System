import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, AlertTriangle, Activity, Clock, Globe, Shield, TrendingUp } from 'lucide-react'
import { investigationApi } from '../services/api'
import { type ForensicReport } from '../types'
import { LoadingSpinner } from '../components/common/LoadingSpinner'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { RiskBadge } from '../components/common/RiskBadge'
import { format, formatDistanceToNow } from 'date-fns'

function DeviationBar({ score }: { score: number }) {
  const pct  = Math.min(score * 100, 100)
  const color = pct >= 60 ? 'bg-red-500' : pct >= 40 ? 'bg-orange-500' : pct >= 20 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-700 rounded-full">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-gray-400">{(score * 100).toFixed(0)}%</span>
    </div>
  )
}

export function InvestigationPage() {
  const [ipInput, setIpInput] = useState('')
  const [targetIP, setTargetIP] = useState<string | null>(null)
  const [hours, setHours] = useState(24)

  const { data: report, isLoading, error } = useQuery({
    queryKey: ['forensic-report', targetIP, hours],
    queryFn: () => investigationApi.forensicReport(targetIP!, hours).then(r => r.data as ForensicReport),
    enabled: !!targetIP,
  })

  const handleSearch = () => {
    const ip = ipInput.trim()
    if (!ip) return
    setTargetIP(ip)
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Search className="w-6 h-6 text-purple-400" />
          Forensic Investigation
        </h1>
        <p className="text-sm text-gray-400 mt-0.5">Full IP activity analysis with behavior, alerts, and threat intel</p>
      </div>

      {/* Search */}
      <div className="flex gap-3">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={ipInput}
            onChange={e => setIpInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder="Enter IP address to investigate…"
            className="w-full pl-10 pr-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyber-500"
          />
        </div>
        <select
          value={hours}
          onChange={e => setHours(Number(e.target.value))}
          className="px-3 py-3 bg-gray-800 border border-gray-700 rounded-xl text-sm text-gray-300 focus:outline-none focus:border-cyber-500"
        >
          {[1, 6, 24, 72, 168].map(h => (
            <option key={h} value={h}>Last {h}h</option>
          ))}
        </select>
        <button
          onClick={handleSearch}
          className="px-5 py-3 rounded-xl bg-purple-500/15 border border-purple-500/30 text-purple-300 text-sm hover:bg-purple-500/25 transition-colors font-medium"
        >
          Investigate
        </button>
      </div>

      {isLoading && <LoadingSpinner />}
      {error && <p className="text-red-400 text-sm">Investigation failed — no data found for this IP.</p>}

      {report && !isLoading && (
        <div className="space-y-5">
          {/* IP Header Card */}
          <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-xl font-mono font-bold text-white">{report.ip_address}</h2>
                <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
                  {report.first_seen && (
                    <span>First seen: {format(new Date(report.first_seen), 'MMM dd, HH:mm')}</span>
                  )}
                  {report.last_seen && (
                    <span>Last seen: {formatDistanceToNow(new Date(report.last_seen))} ago</span>
                  )}
                </div>
              </div>
              <RiskBadge score={report.risk_score_max} showLabel size="md" />
            </div>

            {/* Quick stats */}
            <div className="grid grid-cols-4 gap-3 mt-4">
              {[
                { label: 'Log Events',     value: report.total_logs },
                { label: 'Alerts',         value: report.total_alerts },
                { label: 'Open Incidents', value: report.open_incidents },
                { label: 'Attack Types',   value: report.attack_types.length },
              ].map(s => (
                <div key={s.label} className="bg-gray-900/60 rounded-lg p-3 text-center">
                  <p className="text-xl font-bold text-white">{s.value}</p>
                  <p className="text-xs text-gray-500">{s.label}</p>
                </div>
              ))}
            </div>

            {report.attack_types.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-3">
                {report.attack_types.map(t => (
                  <span key={t} className="text-xs px-2 py-0.5 rounded bg-orange-500/15 border border-orange-500/30 text-orange-300">
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Geo + Behavior Row */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Geo Info */}
            <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                Threat Intelligence
              </h3>
              <div className="space-y-2 text-sm">
                {[
                  { label: 'Country',   value: report.geo_info.country_name || '—' },
                  { label: 'City',      value: report.geo_info.city || '—' },
                  { label: 'ISP',       value: report.geo_info.isp || '—' },
                  { label: 'ASN',       value: report.geo_info.asn || '—', mono: true },
                ].map(r => (
                  <div key={r.label} className="flex justify-between">
                    <span className="text-gray-500">{r.label}</span>
                    <span className={`text-gray-200 ${r.mono ? 'font-mono' : ''}`}>{r.value}</span>
                  </div>
                ))}
                <div className="flex justify-between">
                  <span className="text-gray-500">Reputation</span>
                  <span className={`font-semibold ${
                    report.geo_info.reputation_score >= 75 ? 'text-red-400' :
                    report.geo_info.reputation_score >= 50 ? 'text-orange-400' : 'text-green-400'
                  }`}>{report.geo_info.reputation_score.toFixed(0)}/100</span>
                </div>
              </div>
              {(report.geo_info.is_known_bad || report.geo_info.is_tor_exit || report.geo_info.is_proxy) && (
                <div className="flex flex-wrap gap-1.5 mt-3">
                  {report.geo_info.is_known_bad && <span className="text-xs px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30">Known Bad</span>}
                  {report.geo_info.is_tor_exit  && <span className="text-xs px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">Tor Exit</span>}
                  {report.geo_info.is_proxy     && <span className="text-xs px-2 py-0.5 rounded bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">Proxy</span>}
                </div>
              )}
            </div>

            {/* Behavior */}
            <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                <Activity className="w-4 h-4 text-green-400" />
                Behavioral Profile
              </h3>
              <div className="space-y-3">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-500">Behavioral Deviation</span>
                    <span className="text-gray-400">{(report.behavior_summary.deviation_score * 100).toFixed(0)}%</span>
                  </div>
                  <DeviationBar score={report.behavior_summary.deviation_score} />
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {[
                    { label: 'Requests (1h)',     value: report.behavior_summary.requests_1h },
                    { label: 'Failed Logins (1h)', value: report.behavior_summary.failed_logins_1h },
                    { label: 'Unique Ports (1h)',  value: report.behavior_summary.unique_ports_1h },
                    { label: 'Bytes Out (1h)',     value: `${(report.behavior_summary.bytes_out_1h / 1024).toFixed(1)}KB` },
                  ].map(s => (
                    <div key={s.label} className="bg-gray-900/60 rounded p-2">
                      <p className="text-gray-500">{s.label}</p>
                      <p className="font-semibold text-gray-200 font-mono">{s.value}</p>
                    </div>
                  ))}
                </div>
                {report.behavior_summary.is_new_source && (
                  <div className="text-xs text-yellow-400 bg-yellow-500/10 rounded-lg p-2 border border-yellow-500/20">
                    ⚠ New source IP — no historical baseline available
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Timeline */}
          <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />
              Activity Timeline
            </h3>
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {(report.timeline_events ?? []).map((ev, idx) => (
                <div
                  key={idx}
                  className={`flex items-start gap-3 p-2.5 rounded-lg text-xs ${
                    ev.type === 'alert'
                      ? 'bg-red-500/5 border border-red-500/20'
                      : 'bg-gray-900/40'
                  }`}
                >
                  <span className={`shrink-0 px-1.5 py-0.5 rounded text-xs font-semibold ${
                    ev.type === 'alert'
                      ? 'bg-red-500/20 text-red-400'
                      : 'bg-gray-700 text-gray-400'
                  }`}>
                    {ev.type.toUpperCase()}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-gray-300 font-medium truncate">{ev.event}</p>
                    {ev.details && <p className="text-gray-600 truncate">{ev.details}</p>}
                  </div>
                  {ev.risk_score != null && <RiskBadge score={ev.risk_score} />}
                  <span className="text-gray-600 whitespace-nowrap shrink-0">
                    {format(new Date(ev.time), 'HH:mm:ss')}
                  </span>
                </div>
              ))}
              {report.timeline_events.length === 0 && (
                <p className="text-center text-gray-600 py-6 text-sm">No activity in selected time range</p>
              )}
            </div>
          </div>

          {/* Recent Alerts */}
          {report.recent_alerts.length > 0 && (
            <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-300 mb-3">Recent Alerts for this IP</h3>
              <div className="space-y-2">
                {report.recent_alerts.map(a => (
                  <div key={a.id} className="flex items-center gap-3 p-2.5 rounded bg-gray-900/60">
                    <SeverityBadge severity={a.severity} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-gray-200 truncate">{a.title}</p>
                      <p className="text-xs text-gray-500">{a.attack_type ?? a.rule_name ?? '—'}</p>
                    </div>
                    <RiskBadge score={a.risk_score} />
                    <span className={`text-xs px-1.5 py-0.5 rounded ${
                      a.status === 'open' ? 'text-red-400 bg-red-500/10' : 'text-gray-500 bg-gray-700'
                    }`}>{a.status}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {!targetIP && (
        <div className="py-20 text-center">
          <Search className="w-16 h-16 mx-auto mb-4 text-gray-700" />
          <p className="text-gray-500 text-lg">Enter an IP address to investigate</p>
          <p className="text-gray-600 text-sm mt-1">
            View full log history, behavioral analysis, threat intel, and alert timeline
          </p>
        </div>
      )}
    </div>
  )
}
