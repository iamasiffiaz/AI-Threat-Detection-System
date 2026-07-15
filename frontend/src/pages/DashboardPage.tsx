import { useQuery } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, Eye, TrendingUp, Shield,
  Siren, Lock, Globe, Crosshair, FileBarChart2, Settings, Users,
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'
import { Link } from 'react-router-dom'
import { format } from 'date-fns'
import { dashboardApi, incidentsApi, soarApi, socApi } from '../services/api'
import { PageLoader, EmptyState, ErrorState } from '../components/common/LoadingSpinner'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { RiskBadge } from '../components/common/RiskBadge'
import { ROLE_LABELS, useRoleStore, type DashboardRole } from '../store/roleStore'
import { CHART_TOOLTIP_STYLE, SEVERITY_HEX } from '../utils/formatters'

function StatCard({
  icon: Icon, label, value, sub, tone = 'cyan',
}: {
  icon: React.ElementType
  label: string
  value: string | number
  sub?: string
  tone?: 'cyan' | 'crit' | 'high' | 'med' | 'low' | 'blue'
}) {
  const tones = {
    cyan: 'bg-cyber-500/10 border-cyber-500/30 text-cyber-400',
    crit: 'bg-threat-critical/10 border-threat-critical/30 text-threat-critical',
    high: 'bg-threat-high/10 border-threat-high/30 text-threat-high',
    med:  'bg-threat-medium/10 border-threat-medium/30 text-threat-medium',
    low:  'bg-threat-low/10 border-threat-low/30 text-threat-low',
    blue: 'bg-soc-blue/10 border-soc-blue/30 text-soc-blue',
  }
  return (
    <div className="soc-card p-4 flex items-start gap-3 hover:border-cyber-500/30 transition-colors">
      <div className={`p-2 rounded-md border ${tones[tone]}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="min-w-0">
        <p className="text-xl font-display font-semibold text-soc-text leading-none">{value}</p>
        <p className="text-xs text-soc-muted mt-1 truncate">{label}</p>
        {sub && <p className="text-[10px] text-soc-faint mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

function roleCopy(role: DashboardRole) {
  switch (role) {
    case 'soc_analyst':
      return { title: 'Analyst Workbench', blurb: 'Prioritize open alerts, assigned incidents, and investigation tasks.' }
    case 'soc_manager':
      return { title: 'SOC Manager Overview', blurb: 'Track severity mix, incident posture, escalations, and team workload.' }
    case 'threat_intel_analyst':
      return { title: 'Threat Intelligence Desk', blurb: 'Monitor feed matches, IOC volume, and MITRE technique trends.' }
    case 'executive_viewer':
      return { title: 'Executive Risk Summary', blurb: 'High-level risk, critical incidents, and report readiness for leadership.' }
    default:
      return { title: 'Platform Administration', blurb: 'Users, settings, feed configuration, and role controls.' }
  }
}

export function DashboardPage() {
  const { dashboardRole } = useRoleStore()
  const copy = roleCopy(dashboardRole)

  const { data: overview, isLoading, isError, refetch } = useQuery({
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

  const { data: socStats } = useQuery({
    queryKey: ['soc-dashboard-stats', dashboardRole],
    queryFn: () => socApi.dashboardStats(dashboardRole).then(r => r.data),
    refetchInterval: 20_000,
  })

  if (isLoading) return <PageLoader message="Loading command center…" />
  if (isError) return <div className="p-6"><ErrorState message="Dashboard failed to load" onRetry={() => refetch()} /></div>

  const d = overview
  const severityData = Object.entries(socStats?.alert_severity_chart ?? d?.alerts?.by_severity ?? {}).map(([k, v]) => ({
    name: k.charAt(0).toUpperCase() + k.slice(1),
    value: v as number,
    color: SEVERITY_HEX[k] ?? '#64748B',
  }))

  const statusData = Object.entries(socStats?.incident_status_chart ?? {}).map(([k, v]) => ({
    name: k.replace(/_/g, ' '),
    value: v as number,
  }))

  const mitreData = Object.entries(socStats?.mitre_tactics_detected ?? {}).map(([name, value]) => ({ name, value: value as number }))
  const iocTypeData = Object.entries(socStats?.top_ioc_types ?? {}).map(([name, value]) => ({ name, value: value as number }))

  const timeline = (d?.charts?.traffic_timeline ?? []).map((t: { timestamp: string; count: number }) => ({
    time: format(new Date(t.timestamp), 'HH:mm'),
    logs: t.count,
  }))

  const showAnalyst = dashboardRole === 'soc_analyst'
  const showManager = dashboardRole === 'soc_manager'
  const showIntel = dashboardRole === 'threat_intel_analyst'
  const showExec = dashboardRole === 'executive_viewer'
  const showAdmin = dashboardRole === 'admin'

  return (
    <div className="p-4 sm:p-6 space-y-5 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.2em] text-cyber-400 font-semibold">Enterprise SOC</p>
          <h1 className="page-title mt-1">{copy.title}</h1>
          <p className="text-sm text-soc-muted mt-0.5">{copy.blurb}</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg soc-card">
          <span className="px-2 py-0.5 rounded text-[11px] border border-cyber-500/40 bg-cyber-500/10 text-cyber-300 font-semibold">
            {ROLE_LABELS[dashboardRole]}
          </span>
          <span className="w-2 h-2 rounded-full bg-threat-low animate-pulse" />
          <span className="text-xs text-soc-muted">Live</span>
        </div>
      </div>

      {/* Shared KPI strip — order/priority changes by role */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3">
        {(showExec || showManager) && (
          <StatCard icon={Eye} label="Critical Alerts" value={socStats?.critical_alerts ?? 0} tone="crit" />
        )}
        <StatCard icon={AlertTriangle} label="Total Alerts" value={socStats?.total_alerts ?? d?.alerts?.total ?? 0} tone="cyan" />
        <StatCard icon={Siren} label="Open Incidents" value={socStats?.open_incidents ?? incidentSummary?.open ?? 0} tone="high" />
        {(showIntel || showAnalyst) && (
          <StatCard icon={Shield} label="IOC Matches" value={socStats?.threat_feed_matches ?? 0} tone="med" />
        )}
        <StatCard icon={Globe} label="Threat Feeds" value={socStats?.threat_feed_items ?? 0} tone="blue" />
        <StatCard icon={TrendingUp} label="Avg Risk" value={socStats?.average_risk_score ?? 0} tone="high" />
        <StatCard icon={Crosshair} label="MITRE Tactics" value={Object.keys(socStats?.mitre_tactics_detected ?? {}).length} tone="low" />
        <StatCard icon={Lock} label="Blocked IPs" value={soarStats?.active_blocks ?? 0} tone="crit" />
        {showAdmin && <StatCard icon={Users} label="Open Alerts" value={socStats?.open_alerts ?? 0} tone="cyan" />}
      </div>

      {/* Role-specific priority panels */}
      {showAnalyst && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="soc-card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-cyber-300 uppercase tracking-wide">Investigation Queue</h3>
              <Link to="/alerts" className="text-xs text-cyber-400 hover:text-cyber-300">Open alerts →</Link>
            </div>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {(d?.recent_alerts ?? []).slice(0, 8).map((a: { id: number; title: string; severity: string; risk_score?: number | null; attack_type?: string | null }) => (
                <div key={a.id} className="flex items-center gap-3 p-2.5 rounded-md bg-soc-panel border border-soc-border/60">
                  <SeverityBadge severity={a.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-soc-text truncate font-medium">{a.title}</p>
                    <p className="text-[10px] text-soc-faint">{a.attack_type ?? 'triage'}</p>
                  </div>
                  <RiskBadge score={a.risk_score} />
                </div>
              ))}
              {!d?.recent_alerts?.length && <EmptyState message="No open investigation items" hint="Generate sample logs or seed demo data." />}
            </div>
          </div>
          <div className="soc-card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-cyber-300 uppercase tracking-wide">Assigned Incidents</h3>
              <Link to="/incidents" className="text-xs text-cyber-400 hover:text-cyber-300">Incidents →</Link>
            </div>
            <div className="space-y-2 text-sm text-soc-muted">
              <p>Open: <span className="text-soc-text font-semibold">{incidentSummary?.open ?? 0}</span></p>
              <p>Investigating: <span className="text-threat-medium font-semibold">{incidentSummary?.investigating ?? 0}</span></p>
              <p>Avg risk: <span className="text-threat-high font-mono">{incidentSummary?.avg_risk_score?.toFixed(1) ?? '—'}</span></p>
              <p className="text-xs text-soc-faint pt-2 border-t border-soc-border">Use timeline + notes panels on each incident to document investigation steps.</p>
            </div>
          </div>
        </div>
      )}

      {showManager && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="soc-card p-4">
            <h3 className="text-xs font-semibold text-cyber-300 uppercase mb-3">Severity Distribution</h3>
            {severityData.length ? (
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={severityData} cx="50%" cy="50%" innerRadius={42} outerRadius={62} dataKey="value">
                    {severityData.map((e) => <Cell key={e.name} fill={e.color} />)}
                  </Pie>
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Legend iconType="circle" iconSize={8} formatter={(v) => <span style={{ color: '#9CA3AF', fontSize: 11 }}>{v}</span>} />
                </PieChart>
              </ResponsiveContainer>
            ) : <EmptyState message="No severity data" />}
          </div>
          <div className="soc-card p-4">
            <h3 className="text-xs font-semibold text-cyber-300 uppercase mb-3">Incident Status</h3>
            {statusData.length ? (
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={statusData}>
                  <XAxis dataKey="name" tick={{ fill: '#64748B', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#64748B', fontSize: 10 }} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Bar dataKey="value" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <EmptyState message="No incident status data" />}
          </div>
          <div className="soc-card p-4 space-y-3">
            <h3 className="text-xs font-semibold text-cyber-300 uppercase">Team Workload</h3>
            <p className="text-sm text-soc-muted">Critical queue: <span className="text-threat-critical font-semibold">{socStats?.critical_alerts ?? 0}</span></p>
            <p className="text-sm text-soc-muted">Open incidents: <span className="text-threat-high font-semibold">{socStats?.open_incidents ?? 0}</span></p>
            <p className="text-sm text-soc-muted">MTTR placeholder: <span className="text-soc-text font-mono">4.2h</span></p>
            <p className="text-xs text-soc-faint">Escalate critical cases from Incidents → Escalate.</p>
          </div>
        </div>
      )}

      {showIntel && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="soc-card p-4">
            <div className="flex justify-between mb-3">
              <h3 className="text-xs font-semibold text-cyber-300 uppercase">Recent IOC Matches</h3>
              <Link to="/threat-feeds" className="text-xs text-cyber-400">Threat Feeds →</Link>
            </div>
            <div className="space-y-2">
              {(socStats?.recent_ioc_matches ?? []).slice(0, 8).map((ioc: { id: number; ioc_type: string; ioc_value: string; feed_match: boolean }) => (
                <div key={ioc.id} className="flex items-center gap-2 text-xs font-mono border border-soc-border rounded px-3 py-2 bg-soc-panel">
                  <span className="text-cyber-400 shrink-0">{ioc.ioc_type}</span>
                  <span className="text-soc-text truncate flex-1">{ioc.ioc_value}</span>
                  {ioc.feed_match && <span className="text-threat-critical font-sans font-semibold">MATCH</span>}
                </div>
              ))}
              {!socStats?.recent_ioc_matches?.length && <EmptyState message="No IOC matches yet" hint="Ingest a mock feed and extract IOCs from alerts." />}
            </div>
          </div>
          <div className="soc-card p-4">
            <h3 className="text-xs font-semibold text-cyber-300 uppercase mb-3">Top IOC Types</h3>
            {iocTypeData.length ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={iocTypeData}>
                  <XAxis dataKey="name" tick={{ fill: '#64748B', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#64748B', fontSize: 10 }} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Bar dataKey="value" fill="#2563EB" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <EmptyState message="No extracted IOCs" />}
          </div>
        </div>
      )}

      {showExec && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="soc-card p-5 border-glow-cyber">
            <p className="text-[10px] uppercase tracking-widest text-cyber-400">Business Risk</p>
            <p className="text-3xl font-display text-soc-text mt-2">{socStats?.average_risk_score ?? 0}</p>
            <p className="text-xs text-soc-muted mt-1">Average composite risk score</p>
          </div>
          <div className="soc-card p-5">
            <p className="text-[10px] uppercase tracking-widest text-threat-critical">Critical Incidents</p>
            <p className="text-3xl font-display text-threat-critical mt-2">{socStats?.critical_alerts ?? 0}</p>
            <p className="text-xs text-soc-muted mt-1">Requires leadership visibility</p>
          </div>
          <div className="soc-card p-5">
            <div className="flex items-center justify-between">
              <p className="text-[10px] uppercase tracking-widest text-cyber-400">Reports</p>
              <FileBarChart2 className="w-4 h-4 text-cyber-400" />
            </div>
            <Link to="/reports" className="soc-btn-primary mt-4 w-full justify-center">Download Report Center</Link>
            <p className="text-xs text-soc-faint mt-2">Executive-ready PDF/HTML incident packages</p>
          </div>
        </div>
      )}

      {showAdmin && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Link to="/settings" className="soc-card p-4 hover:border-cyber-500/40 transition-colors">
            <Settings className="w-5 h-5 text-cyber-400 mb-2" />
            <p className="text-sm font-semibold text-soc-text">Platform Settings</p>
            <p className="text-xs text-soc-faint mt-1">Org name, AI provider, severity thresholds</p>
          </Link>
          <Link to="/threat-feeds" className="soc-card p-4 hover:border-cyber-500/40 transition-colors">
            <Globe className="w-5 h-5 text-cyber-400 mb-2" />
            <p className="text-sm font-semibold text-soc-text">Feed Configuration</p>
            <p className="text-xs text-soc-faint mt-1">Manual / CSV / JSON / mock ingestion</p>
          </Link>
          <div className="soc-card p-4">
            <Users className="w-5 h-5 text-cyber-400 mb-2" />
            <p className="text-sm font-semibold text-soc-text">Role Controls</p>
            <p className="text-xs text-soc-faint mt-1">Use topbar Role View for portfolio demos. JWT RBAC ready on backend.</p>
          </div>
        </div>
      )}

      {/* Shared command charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="soc-card p-4 lg:col-span-1">
          <h3 className="text-xs font-semibold text-cyber-300 uppercase mb-3">Alert Severity</h3>
          {severityData.length ? (
            <ResponsiveContainer width="100%" height={170}>
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={45} outerRadius={65} dataKey="value">
                  {severityData.map((e) => <Cell key={e.name} fill={e.color} />)}
                </Pie>
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                <Legend iconType="circle" iconSize={8} formatter={(v) => <span style={{ color: '#9CA3AF', fontSize: 11 }}>{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          ) : <EmptyState message="No alerts yet" />}
        </div>
        <div className="soc-card p-4 lg:col-span-2">
          <h3 className="text-xs font-semibold text-cyber-300 uppercase mb-3">Traffic — Last 24h</h3>
          {timeline.length ? (
            <ResponsiveContainer width="100%" height={170}>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="logGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fill: '#64748B', fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fill: '#64748B', fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                <Area type="monotone" dataKey="logs" stroke="#3B82F6" strokeWidth={2} fill="url(#logGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          ) : <EmptyState message="Ingest logs to populate traffic" />}
        </div>
      </div>

      {(mitreData.length > 0 || showIntel) && (
        <div className="soc-card p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-cyber-300 uppercase">MITRE Tactics Detected</h3>
            <Link to="/mitre" className="text-xs text-cyber-400">MITRE page →</Link>
          </div>
          {mitreData.length ? (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={mitreData}>
                <XAxis dataKey="name" tick={{ fill: '#64748B', fontSize: 10 }} interval={0} angle={-15} textAnchor="end" height={55} />
                <YAxis tick={{ fill: '#64748B', fontSize: 10 }} />
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                <Bar dataKey="value" fill="#3B82F6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <EmptyState message="Map alerts to MITRE to populate tactics" />}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="soc-card p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-cyber-300 uppercase">Recent Alerts</h3>
            <Link to="/alerts" className="text-xs text-cyber-400">View all →</Link>
          </div>
          <div className="space-y-2">
            {(d?.recent_alerts ?? []).slice(0, 6).map((a: { id: number; title: string; severity: string; risk_score?: number | null; attack_type?: string | null }) => (
              <div key={a.id} className="flex items-center gap-3 p-2.5 rounded-md bg-soc-panel/80 border border-soc-border/50">
                <SeverityBadge severity={a.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-soc-text truncate">{a.title}</p>
                  <p className="text-[10px] text-soc-faint">{a.attack_type ?? 'Unknown'}</p>
                </div>
                <RiskBadge score={a.risk_score} />
              </div>
            ))}
            {!d?.recent_alerts?.length && <EmptyState message="No alerts yet" />}
          </div>
        </div>
        <div className="soc-card p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-cyber-300 uppercase">ML Detection Engine</h3>
            <span className={`text-[11px] px-2 py-0.5 rounded border ${d?.model?.is_trained ? 'text-threat-low border-threat-low/30 bg-threat-low/10' : 'text-threat-critical border-threat-critical/30 bg-threat-critical/10'}`}>
              {d?.model?.is_trained ? 'Trained' : 'Untrained'}
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2 mb-3">
            {[
              { label: 'Algorithm', value: d?.model?.algorithm ?? '—' },
              { label: 'Samples', value: d?.model?.training_samples?.toLocaleString() ?? '0' },
              { label: 'Threshold', value: d?.model?.threshold?.toFixed(2) ?? '0.60' },
              { label: 'Total Logs', value: d?.logs?.total?.toLocaleString() ?? '0' },
            ].map((item) => (
              <div key={item.label} className="bg-soc-panel border border-soc-border rounded-md p-3">
                <p className="text-[10px] text-soc-faint uppercase tracking-wide">{item.label}</p>
                <p className="text-sm font-semibold text-soc-text mt-0.5">{item.value}</p>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-2 text-xs text-soc-muted">
            <Activity className="w-3.5 h-3.5 text-cyber-400" />
            Anomaly + SIEM hybrid detection active
          </div>
        </div>
      </div>
    </div>
  )
}
