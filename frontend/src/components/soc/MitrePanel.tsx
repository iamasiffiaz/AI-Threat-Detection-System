import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Crosshair, Lightbulb } from 'lucide-react'
import { mitreApi } from '../../services/api'
import toast from 'react-hot-toast'
import { EmptyState, LoadingSpinner, ErrorState } from '../common/LoadingSpinner'

interface Props {
  alertId?: number
  incidentId?: number
}

export function MitrePanel({ alertId, incidentId }: Props) {
  const qc = useQueryClient()

  const { data: mappings = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['mitre-mappings', alertId, incidentId],
    queryFn: () =>
      mitreApi.getMappings({ alert_id: alertId, incident_id: incidentId }).then((r) => r.data),
  })

  const mapMut = useMutation({
    mutationFn: async () => {
      if (alertId) return mitreApi.mapAlert(alertId).then((r) => r.data)
      if (incidentId) return mitreApi.mapIncident(incidentId).then((r) => r.data)
      throw new Error('No target')
    },
    onSuccess: (data) => {
      toast.success(`Mapped ${data.mappings?.length || 0} techniques`)
      qc.invalidateQueries({ queryKey: ['mitre-mappings'] })
      refetch()
    },
  })

  const recommendations: string[] = mapMut.data?.recommendations
    || mapMut.data?.summary?.recommendations
    || []

  return (
    <div className="soc-card p-4 space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h3 className="text-xs font-semibold text-cyber-300 tracking-wide uppercase flex items-center gap-2">
          <Crosshair className="w-4 h-4" /> MITRE ATT&CK Mapping
        </h3>
        <button className="soc-btn-primary py-1.5" onClick={() => mapMut.mutate()} disabled={mapMut.isPending}>
          {mapMut.isPending ? 'Mapping…' : 'Map Now'}
        </button>
      </div>

      {isLoading ? (
        <LoadingSpinner size="sm" message="Loading mappings…" />
      ) : isError ? (
        <ErrorState message="Failed to load MITRE mappings" onRetry={() => refetch()} />
      ) : mappings.length === 0 ? (
        <EmptyState message="No MITRE mappings yet" hint="Click Map Now to attach tactics and techniques from detection context." />
      ) : (
        <div className="overflow-x-auto rounded-md border border-soc-border">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Tactic</th>
                <th>ID</th>
                <th>Technique</th>
                <th>Confidence</th>
                <th>Reasoning</th>
              </tr>
            </thead>
            <tbody>
              {(mappings as Array<Record<string, unknown>>).map((m) => (
                <tr key={String(m.id)}>
                  <td className="text-soc-text font-medium whitespace-nowrap">{String(m.tactic)}</td>
                  <td className="font-mono text-cyber-400 text-xs whitespace-nowrap">{String(m.technique_id)}</td>
                  <td className="text-soc-muted">{String(m.technique_name)}</td>
                  <td>
                    <span className="px-2 py-0.5 rounded text-[11px] border border-cyber-500/30 bg-cyber-500/10 text-cyber-300 font-semibold">
                      {Number(m.confidence).toFixed(0)}%
                    </span>
                  </td>
                  <td className="text-xs text-soc-faint max-w-[220px] truncate" title={String(m.reasoning || '')}>
                    {String(m.reasoning || '—')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {recommendations.length > 0 && (
        <div className="bg-soc-panel border border-soc-border rounded-md p-3">
          <p className="text-[11px] text-cyber-400 font-semibold uppercase tracking-wide flex items-center gap-1.5 mb-2">
            <Lightbulb className="w-3.5 h-3.5" /> Defensive Recommendations
          </p>
          <ul className="space-y-1.5">
            {recommendations.map((r, i) => (
              <li key={i} className="text-xs text-soc-muted leading-relaxed pl-2 border-l-2 border-cyber-500/40">{r}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
