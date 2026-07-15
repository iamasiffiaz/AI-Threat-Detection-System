import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Clock, AlertTriangle } from 'lucide-react'
import clsx from 'clsx'
import { socApi } from '../../services/api'
import { EmptyState, LoadingSpinner, ErrorState } from '../common/LoadingSpinner'
import { SEVERITY_DOT } from '../../utils/formatters'

interface Props {
  incidentId: number
}

export function TimelinePanel({ incidentId }: Props) {
  const [typeFilter, setTypeFilter] = useState('')
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['incident-timeline-v2', incidentId],
    queryFn: () => socApi.getTimeline(incidentId).then((r) => r.data),
  })

  const events = ((data?.events || []) as Array<Record<string, unknown>>).filter(
    (e) => !typeFilter || e.event_type === typeFilter
  )
  const types = Array.from(
    new Set(((data?.events || []) as Array<Record<string, unknown>>).map((e) => String(e.event_type)))
  )

  return (
    <div className="soc-card p-4 space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-xs font-semibold text-cyber-300 tracking-wide uppercase flex items-center gap-2">
          <Clock className="w-4 h-4" /> Incident Timeline
        </h3>
        <select className="soc-input w-auto py-1 text-xs" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
          <option value="">All event types</option>
          {types.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
        </select>
      </div>

      {data?.summary && (
        <div className="text-xs text-soc-muted bg-soc-panel border border-cyber-500/20 rounded-md p-3 border-l-2 border-l-cyber-400">
          <span className="text-cyber-400 font-semibold">AI Timeline Summary · </span>
          {data.summary}
        </div>
      )}

      {Array.isArray(data?.gaps) && data.gaps.length > 0 && (
        <div className="flex items-start gap-2 text-xs text-threat-medium bg-threat-medium/5 border border-threat-medium/20 rounded-md p-2">
          <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
          <span>{data.gaps.length} investigation gap(s) detected — review missing telemetry windows.</span>
        </div>
      )}

      {isLoading ? (
        <LoadingSpinner size="sm" message="Reconstructing timeline…" />
      ) : isError ? (
        <ErrorState message="Timeline unavailable" onRetry={() => refetch()} />
      ) : events.length === 0 ? (
        <EmptyState message="No timeline events" hint="Status changes, notes, IOC matches, and reports appear here." />
      ) : (
        <div className="relative pl-7 space-y-0 max-h-96 overflow-y-auto">
          <div className="absolute left-[11px] top-2 bottom-2 w-px bg-gradient-to-b from-cyber-500/60 via-soc-border to-transparent" />
          {events.map((e, idx) => {
            const sev = String(e.severity || 'medium').toLowerCase()
            return (
              <div key={String(e.id)} className={clsx('relative pb-4', idx === events.length - 1 && 'pb-1')}>
                <span
                  className={clsx(
                    'absolute -left-[1.05rem] top-1.5 w-3 h-3 rounded-full border-2 border-soc-card ring-2 ring-soc-bg',
                    SEVERITY_DOT[sev] || 'bg-cyber-500'
                  )}
                />
                <div className="bg-soc-panel/50 border border-soc-border/70 rounded-md px-3 py-2 hover:border-cyber-500/30 transition-colors">
                  <p className="text-sm text-soc-text font-medium leading-snug">{String(e.title)}</p>
                  {e.description && (
                    <p className="text-xs text-soc-muted mt-1 leading-relaxed">{String(e.description)}</p>
                  )}
                  <p className="text-[10px] text-soc-faint mt-1.5 font-mono tracking-wide">
                    {e.timestamp ? new Date(String(e.timestamp)).toLocaleString() : '—'}
                    {' · '}{String(e.event_type).replace(/_/g, ' ')}
                    {e.source ? ` · ${String(e.source)}` : ''}
                  </p>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
