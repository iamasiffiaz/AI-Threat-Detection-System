import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Search, Loader2 } from 'lucide-react'
import { iocsApi } from '../../services/api'
import toast from 'react-hot-toast'

interface Props {
  alertId?: number
  incidentId?: number
  initialText?: string
}

export function IOCExtractionPanel({ alertId, incidentId, initialText = '' }: Props) {
  const [text, setText] = useState(initialText)
  const [results, setResults] = useState<Array<Record<string, unknown>>>([])

  const mutation = useMutation({
    mutationFn: () =>
      iocsApi.extract({
        text,
        alert_id: alertId,
        incident_id: incidentId,
        persist: true,
        source_context: alertId ? 'alert' : incidentId ? 'incident' : 'manual',
      }).then((r) => r.data),
    onSuccess: (data) => {
      setResults(data.iocs || [])
      toast.success(`Extracted ${data.count} IOCs`)
    },
  })

  return (
    <div className="soc-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-cyber-300 tracking-wide uppercase">IOC Extraction</h3>
        <button
          className="soc-btn-primary"
          disabled={!text.trim() || mutation.isPending}
          onClick={() => mutation.mutate()}
        >
          {mutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          Extract
        </button>
      </div>
      <textarea
        className="soc-input min-h-[100px]"
        placeholder="Paste alert text, logs, or analyst notes to extract IOCs…"
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      {results.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-soc-faint border-b border-soc-border">
                <th className="py-2 pr-3">Type</th>
                <th className="py-2 pr-3">Value</th>
                <th className="py-2 pr-3">Context</th>
                <th className="py-2">Feed Match</th>
              </tr>
            </thead>
            <tbody>
              {results.map((ioc, idx) => (
                <tr key={idx} className="border-b border-soc-border/50 text-soc-text">
                  <td className="py-2 pr-3 font-mono text-xs text-cyber-400">{String(ioc.ioc_type)}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{String(ioc.ioc_value)}</td>
                  <td className="py-2 pr-3 text-xs text-soc-muted max-w-xs truncate">{String(ioc.source_text || '')}</td>
                  <td className="py-2">
                    <span className={ioc.feed_match ? 'text-threat-critical' : 'text-soc-faint'}>
                      {ioc.feed_match ? 'MATCH' : '—'}
                    </span>
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
