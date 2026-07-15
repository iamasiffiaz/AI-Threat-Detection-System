import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { reportsApi } from '../services/api'
import { PageLoader, EmptyState, ErrorState } from '../components/common/LoadingSpinner'
import { SeverityBadge } from '../components/common/SeverityBadge'
import { RiskBadge } from '../components/common/RiskBadge'
import { FileBarChart2, Download, Eye } from 'lucide-react'
import toast from 'react-hot-toast'

export function ReportsPage() {
  const [previewId, setPreviewId] = useState<number | null>(null)
  const { data: reports = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['reports'],
    queryFn: () => reportsApi.getAll().then((r) => r.data),
  })

  const { data: preview, isLoading: previewLoading } = useQuery({
    queryKey: ['report-preview', previewId],
    queryFn: () => reportsApi.getById(previewId!).then((r) => r.data),
    enabled: previewId != null,
  })

  const download = async (id: number) => {
    try {
      const token = localStorage.getItem('access_token')
      const url = reportsApi.downloadUrl(id)
      const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      if (!res.ok) throw new Error('Download failed')
      const blob = await res.blob()
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `incident_report_${id}`
      a.click()
      toast.success('Report downloaded')
    } catch {
      toast.error('Download failed — generate report first')
    }
  }

  const report = preview?.report as Record<string, unknown> | undefined

  if (isLoading) return <PageLoader message="Loading reports…" />
  if (isError) return <div className="p-6"><ErrorState onRetry={() => refetch()} /></div>

  return (
    <div className="p-4 sm:p-6 space-y-6 animate-fade-in">
      <div>
        <p className="text-[10px] uppercase tracking-[0.2em] text-cyber-400 font-semibold">Reporting</p>
        <h1 className="page-title flex items-center gap-2 mt-1">
          <FileBarChart2 className="w-6 h-6 text-cyber-400" /> Incident Reports
        </h1>
        <p className="text-sm text-soc-muted mt-1">Executive-ready incident packages for stakeholders and leadership reviews.</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="soc-card overflow-hidden">
          {(reports as Array<Record<string, unknown>>).length === 0 ? (
            <EmptyState
              message="No reports generated yet"
              hint="Open an incident and click Generate Report to create an executive package."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Generated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {(reports as Array<Record<string, unknown>>).map((r) => (
                    <tr
                      key={String(r.id)}
                      className={previewId === Number(r.id) ? 'bg-cyber-500/5' : ''}
                    >
                      <td className="text-soc-text font-medium max-w-[220px] truncate">{String(r.title)}</td>
                      <td><SeverityBadge severity={String(r.severity || 'medium')} /></td>
                      <td><RiskBadge score={Number(r.risk_score || 0)} showLabel /></td>
                      <td className="text-xs text-soc-faint whitespace-nowrap">
                        {r.created_at ? new Date(String(r.created_at)).toLocaleString() : '—'}
                      </td>
                      <td>
                        <div className="flex gap-2">
                          <button className="soc-btn-primary py-1" onClick={() => setPreviewId(Number(r.id))}>
                            <Eye className="w-3.5 h-3.5" /> View
                          </button>
                          <button className="soc-btn-primary py-1" onClick={() => download(Number(r.id))}>
                            <Download className="w-3.5 h-3.5" /> Export
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="soc-card p-5 min-h-[420px]">
          <h2 className="text-xs font-semibold text-cyber-300 uppercase tracking-wide mb-4">Executive Preview</h2>
          {!previewId ? (
            <EmptyState message="Select a report to preview" hint="Choose View on any report row." />
          ) : previewLoading ? (
            <PageLoader message="Loading preview…" />
          ) : !preview ? (
            <EmptyState message="Report not found" />
          ) : (
            <div className="space-y-4 text-sm max-h-[70vh] overflow-y-auto pr-1">
              <div className="border-b border-soc-border pb-4">
                <p className="font-display text-xl text-soc-text leading-snug">{preview.title}</p>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  <SeverityBadge severity={String(preview.severity || 'medium')} size="md" />
                  <RiskBadge score={Number(preview.risk_score || 0)} showLabel size="md" />
                  <span className="text-xs text-soc-faint">Incident #{preview.incident_id}</span>
                </div>
              </div>

              <section>
                <h3 className="text-[11px] uppercase tracking-wider text-cyber-400 font-semibold mb-1.5">Executive Summary</h3>
                <p className="text-soc-muted leading-relaxed">{String(report?.executive_summary || '—')}</p>
              </section>
              <section>
                <h3 className="text-[11px] uppercase tracking-wider text-cyber-400 font-semibold mb-1.5">Technical Summary</h3>
                <p className="text-soc-muted leading-relaxed">{String(report?.technical_summary || '—')}</p>
              </section>
              <section>
                <h3 className="text-[11px] uppercase tracking-wider text-cyber-400 font-semibold mb-1.5">Likely Impact</h3>
                <p className="text-soc-muted leading-relaxed">{String(report?.likely_impact || '—')}</p>
              </section>
              <section>
                <h3 className="text-[11px] uppercase tracking-wider text-cyber-400 font-semibold mb-1.5">Recommended Actions</h3>
                <ul className="space-y-1">
                  {(Array.isArray(report?.recommended_actions) ? report!.recommended_actions as string[] : []).map((a, i) => (
                    <li key={i} className="text-soc-muted text-xs pl-2 border-l-2 border-threat-high/40">{a}</li>
                  ))}
                </ul>
              </section>
              <section>
                <h3 className="text-[11px] uppercase tracking-wider text-cyber-400 font-semibold mb-1.5">Timeline Summary</h3>
                <p className="text-xs text-soc-faint leading-relaxed font-mono bg-soc-panel border border-soc-border rounded-md p-3">
                  {String(report?.timeline_summary || '—')}
                </p>
              </section>
              <section>
                <h3 className="text-[11px] uppercase tracking-wider text-cyber-400 font-semibold mb-1.5">IOCs</h3>
                <div className="overflow-x-auto rounded border border-soc-border">
                  <table className="soc-table text-xs">
                    <thead><tr><th>Type</th><th>Value</th><th>Feed</th></tr></thead>
                    <tbody>
                      {(Array.isArray(report?.iocs) ? report!.iocs as Array<Record<string, unknown>> : []).map((ioc, i) => (
                        <tr key={i}>
                          <td className="text-cyber-400 font-mono">{String(ioc.ioc_type)}</td>
                          <td className="font-mono">{String(ioc.ioc_value)}</td>
                          <td>{ioc.feed_match ? <span className="text-threat-critical">MATCH</span> : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
