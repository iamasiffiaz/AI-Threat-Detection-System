import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Upload, Trash2, Radar } from 'lucide-react'
import { threatFeedsApi } from '../services/api'
import { EmptyState, ErrorState, PageLoader } from '../components/common/LoadingSpinner'
import { SeverityBadge } from '../components/common/SeverityBadge'
import toast from 'react-hot-toast'

const IOC_TYPES = ['ip', 'domain', 'url', 'file_hash', 'email', 'cve', 'malware_family', 'threat_actor']
const SEVERITIES = ['low', 'medium', 'high', 'critical']

export function ThreatFeedsPage() {
  const qc = useQueryClient()
  const [q, setQ] = useState('')
  const [iocType, setIocType] = useState('')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [activeOnly, setActiveOnly] = useState(true)
  const [minConf, setMinConf] = useState('')
  const [manual, setManual] = useState({
    ioc_value: '', ioc_type: 'ip', source: 'manual', confidence_score: 70,
    threat_category: '', description: '', severity: 'medium',
  })

  const params = useMemo(() => ({
    q: q || undefined,
    ioc_type: iocType || undefined,
    severity: severity || undefined,
    source: source || undefined,
    is_active: activeOnly ? true : undefined,
    min_confidence: minConf ? Number(minConf) : undefined,
    limit: 200,
  }), [q, iocType, severity, source, activeOnly, minConf])

  const { data: items = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['threat-feeds', params],
    queryFn: () => threatFeedsApi.getAll(params).then((r) => r.data),
  })

  const createMut = useMutation({
    mutationFn: () => threatFeedsApi.createManual(manual),
    onSuccess: () => {
      toast.success('IOC added')
      qc.invalidateQueries({ queryKey: ['threat-feeds'] })
      setManual({ ...manual, ioc_value: '', description: '' })
    },
  })

  const mockMut = useMutation({
    mutationFn: () => threatFeedsApi.importMock(),
    onSuccess: (r) => {
      toast.success(`Imported ${r.data.imported} mock IOCs`)
      qc.invalidateQueries({ queryKey: ['threat-feeds'] })
    },
  })

  const uploadMut = useMutation({
    mutationFn: (file: File) => threatFeedsApi.importFile(file),
    onSuccess: (r) => {
      toast.success(`Imported ${r.data.imported} IOCs`)
      qc.invalidateQueries({ queryKey: ['threat-feeds'] })
    },
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => threatFeedsApi.delete(id),
    onSuccess: () => {
      toast.success('Deleted')
      qc.invalidateQueries({ queryKey: ['threat-feeds'] })
    },
  })

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="page-title flex items-center gap-2"><Radar className="w-6 h-6 text-cyber-400" /> Threat Feeds</h1>
          <p className="text-sm text-soc-muted mt-1">Ingest and manage IOC threat intelligence for the SOC.</p>
        </div>
        <div className="flex gap-2">
          <button className="soc-btn-primary" onClick={() => mockMut.mutate()}>Ingest Mock Feed</button>
          <label className="soc-btn-primary cursor-pointer">
            <Upload className="w-4 h-4" /> CSV/JSON
            <input type="file" className="hidden" accept=".csv,.json,.txt" onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) uploadMut.mutate(f)
            }} />
          </label>
        </div>
      </div>

      <div className="soc-card p-4 grid grid-cols-1 md:grid-cols-6 gap-3">
        <input className="soc-input md:col-span-2" placeholder="Search IOCs…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="soc-input" value={iocType} onChange={(e) => setIocType(e.target.value)}>
          <option value="">All types</option>
          {IOC_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className="soc-input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severity</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input className="soc-input" placeholder="Source" value={source} onChange={(e) => setSource(e.target.value)} />
        <div className="flex items-center gap-2">
          <input type="checkbox" checked={activeOnly} onChange={(e) => setActiveOnly(e.target.checked)} />
          <span className="text-xs text-soc-muted">Active only</span>
          <input className="soc-input w-20 ml-auto" placeholder="Min %" value={minConf} onChange={(e) => setMinConf(e.target.value)} />
        </div>
      </div>

      <div className="soc-card p-4 space-y-3">
        <h2 className="text-sm font-semibold text-cyber-300 uppercase tracking-wide">Manual IOC Entry</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
          <input className="soc-input md:col-span-2" placeholder="IOC value" value={manual.ioc_value} onChange={(e) => setManual({ ...manual, ioc_value: e.target.value })} />
          <select className="soc-input" value={manual.ioc_type} onChange={(e) => setManual({ ...manual, ioc_type: e.target.value })}>
            {IOC_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <select className="soc-input" value={manual.severity} onChange={(e) => setManual({ ...manual, severity: e.target.value })}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input className="soc-input" placeholder="Category" value={manual.threat_category} onChange={(e) => setManual({ ...manual, threat_category: e.target.value })} />
          <input className="soc-input md:col-span-2" placeholder="Description" value={manual.description} onChange={(e) => setManual({ ...manual, description: e.target.value })} />
          <button className="soc-btn-primary" onClick={() => createMut.mutate()} disabled={!manual.ioc_value}>
            <Plus className="w-4 h-4" /> Add IOC
          </button>
        </div>
      </div>

      {isLoading ? <PageLoader message="Loading threat feeds…" /> : isError ? (
        <ErrorState message="Failed to load threat feeds" onRetry={() => refetch()} />
      ) : (items as Array<Record<string, unknown>>).length === 0 ? (
        <div className="soc-card">
          <EmptyState
            message="No IOC feed items match your filters"
            hint="Ingest Mock Feed, upload CSV/JSON, or add an IOC manually."
            action={<button className="soc-btn-primary" onClick={() => mockMut.mutate()}>Ingest Mock Feed</button>}
          />
        </div>
      ) : (
        <div className="soc-card overflow-x-auto">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Source</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Active</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(items as Array<Record<string, unknown>>).map((item) => (
                <tr key={String(item.id)}>
                  <td className="font-mono text-xs text-cyber-400">{String(item.ioc_type)}</td>
                  <td className="font-mono text-xs text-soc-text max-w-[280px] truncate" title={String(item.ioc_value)}>{String(item.ioc_value)}</td>
                  <td className="text-soc-muted text-xs">{String(item.source)}</td>
                  <td><SeverityBadge severity={String(item.severity)} /></td>
                  <td className="font-mono text-xs">{Number(item.confidence_score).toFixed(0)}%</td>
                  <td className="text-xs">{item.is_active ? <span className="text-threat-low">Active</span> : <span className="text-soc-faint">Inactive</span>}</td>
                  <td>
                    <button className="text-soc-faint hover:text-threat-critical" onClick={() => deleteMut.mutate(Number(item.id))}>
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
