import { useQuery } from '@tanstack/react-query'
import { mitreApi } from '../services/api'
import { LoadingSpinner } from '../components/common/LoadingSpinner'
import { Crosshair } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const COLORS = ['#3B82F6', '#0EA5E9', '#EF4444', '#F97316', '#EAB308', '#22C55E', '#94A3B8']

export function MitrePage() {
  const { data: mappings = [], isLoading } = useQuery({
    queryKey: ['mitre-all'],
    queryFn: () => mitreApi.getMappings({ limit: 200 }).then((r) => r.data),
  })

  const tactics: Record<string, number> = {}
  for (const m of mappings as Array<Record<string, unknown>>) {
    const t = String(m.tactic)
    tactics[t] = (tactics[t] || 0) + 1
  }
  const chartData = Object.entries(tactics).map(([name, value]) => ({ name, value }))

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="page-title flex items-center gap-2"><Crosshair className="w-6 h-6 text-cyber-400" /> MITRE ATT&CK</h1>
        <p className="text-sm text-soc-muted mt-1">Tactic distribution and technique mappings across alerts and incidents.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="soc-card p-4 h-80">
          <h2 className="text-sm font-semibold text-cyber-300 uppercase mb-3">Tactic Distribution</h2>
          {chartData.length === 0 ? (
            <p className="text-soc-faint text-sm">No mappings yet. Map alerts/incidents to populate.</p>
          ) : (
            <ResponsiveContainer width="100%" height="90%">
              <BarChart data={chartData}>
                <XAxis dataKey="name" tick={{ fill: '#9CA3AF', fontSize: 10 }} interval={0} angle={-20} textAnchor="end" height={60} />
                <YAxis tick={{ fill: '#9CA3AF', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#182234', border: '1px solid #2A3548', borderRadius: 10, color: '#F1F5F9' }} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {chartData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
        <div className="soc-card p-4">
          <h2 className="text-sm font-semibold text-cyber-300 uppercase mb-3">Coverage</h2>
          <p className="text-3xl font-display text-soc-text">{mappings.length}</p>
          <p className="text-sm text-soc-muted">Total technique mappings</p>
          <p className="text-xl font-display text-cyber-400 mt-4">{chartData.length}</p>
          <p className="text-sm text-soc-muted">Distinct tactics observed</p>
        </div>
      </div>

      {isLoading ? <LoadingSpinner /> : (
        <div className="soc-card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-soc-faint border-b border-soc-border bg-soc-panel/50">
                <th className="p-3">Tactic</th>
                <th className="p-3">ID</th>
                <th className="p-3">Technique</th>
                <th className="p-3">Confidence</th>
                <th className="p-3">Alert</th>
                <th className="p-3">Incident</th>
              </tr>
            </thead>
            <tbody>
              {(mappings as Array<Record<string, unknown>>).map((m) => (
                <tr key={String(m.id)} className="border-b border-soc-border/40">
                  <td className="p-3">{String(m.tactic)}</td>
                  <td className="p-3 font-mono text-cyber-400 text-xs">{String(m.technique_id)}</td>
                  <td className="p-3 text-soc-muted">{String(m.technique_name)}</td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 rounded text-xs border border-cyber-500/30 bg-cyber-500/10 text-cyber-300">
                      {Number(m.confidence).toFixed(0)}%
                    </span>
                  </td>
                  <td className="p-3">{m.alert_id ? `#${m.alert_id}` : '—'}</td>
                  <td className="p-3">{m.incident_id ? `#${m.incident_id}` : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
