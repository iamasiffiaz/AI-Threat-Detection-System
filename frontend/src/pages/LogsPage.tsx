import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, Play, Download, Filter, X, Database } from 'lucide-react'
import toast from 'react-hot-toast'
import { logsApi } from '../services/api'
import { Header } from '../components/Layout/Header'
import { SeverityBadge } from '../components/Common/SeverityBadge'
import { PageLoader } from '../components/Common/LoadingSpinner'
import { formatDate, formatBytes } from '../utils/formatters'
import type { LogEntry, Severity } from '../types'

const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical']

export function LogsPage() {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState<{ severity?: Severity; source_ip?: string }>({})
  const [showFilters, setShowFilters] = useState(false)

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['logs', page, filters],
    queryFn: async () => (await logsApi.getAll({ page, page_size: 50, ...filters })).data,
    placeholderData: (prev) => prev,
  })

  const uploadMutation = useMutation({
    mutationFn: (file: File) => logsApi.upload(file),
    onSuccess: (res) => {
      toast.success(`Uploaded ${res.data.ingested} log entries`)
      qc.invalidateQueries({ queryKey: ['logs'] })
      qc.invalidateQueries({ queryKey: ['dashboard-overview'] })
    },
    onError: () => toast.error('Upload failed'),
  })

  const generateMutation = useMutation({
    mutationFn: () => logsApi.generateSample(500),
    onSuccess: (res) => {
      toast.success(`Generated ${res.data.ingested} sample logs`)
      qc.invalidateQueries({ queryKey: ['logs'] })
      qc.invalidateQueries({ queryKey: ['dashboard-overview'] })
    },
  })

  const trainMutation = useMutation({
    mutationFn: () => logsApi.trainModel(true),
    onSuccess: (res) => {
      if (res.data.status === 'trained') {
        toast.success(`Model trained on ${res.data.training_samples} samples`)
      } else {
        toast(res.data.reason)
      }
    },
  })

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) uploadMutation.mutate(file)
    e.target.value = ''
  }

  async function downloadCSV() {
    const res = await logsApi.getAll({ page: 1, page_size: 5000, ...filters })
    const logs: LogEntry[] = res.data.items
    const csv = [
      ['ID', 'Timestamp', 'Source IP', 'Destination IP', 'Port', 'Protocol', 'Event Type', 'Severity'],
      ...logs.map(l => [
        l.id, l.timestamp, l.source_ip, l.destination_ip || '',
        l.destination_port || '', l.protocol, l.event_type, l.severity,
      ]),
    ].map(row => row.join(',')).join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `logs-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('CSV downloaded')
  }

  if (isLoading) return <PageLoader />

  const items: LogEntry[] = data?.items || []
  const total: number = data?.total || 0
  const pages: number = data?.pages || 1

  return (
    <div className="flex flex-col flex-1">
      <Header
        title="Log Management"
        subtitle={`${total.toLocaleString()} total log entries`}
        onRefresh={() => refetch()}
        isRefreshing={isFetching}
      />

      <div className="p-6 space-y-4">
        {/* Action Bar */}
        <div className="flex items-center gap-3 flex-wrap">
          <input type="file" ref={fileRef} className="hidden" accept=".csv,.json,.log,.txt" onChange={handleFileUpload} />

          <button
            onClick={() => fileRef.current?.click()}
            disabled={uploadMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-cyber-600 hover:bg-cyber-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Upload className="w-4 h-4" />
            {uploadMutation.isPending ? 'Uploading...' : 'Upload Logs'}
          </button>

          <button
            onClick={() => generateMutation.mutate()}
            disabled={generateMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Database className="w-4 h-4" />
            {generateMutation.isPending ? 'Generating...' : 'Generate Sample Data'}
          </button>

          <button
            onClick={() => trainMutation.mutate()}
            disabled={trainMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-purple-700 hover:bg-purple-600 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Play className="w-4 h-4" />
            {trainMutation.isPending ? 'Training...' : 'Train ML Model'}
          </button>

          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors ${showFilters ? 'bg-cyber-500/20 text-cyber-300 border border-cyber-500/30' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
          >
            <Filter className="w-4 h-4" />
            Filters
          </button>

          <button
            onClick={downloadCSV}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium rounded-lg transition-colors ml-auto"
          >
            <Download className="w-4 h-4" /> Export CSV
          </button>
        </div>

        {/* Filters Panel */}
        {showFilters && (
          <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-4 flex items-center gap-4 flex-wrap">
            <select
              value={filters.severity || ''}
              onChange={(e) => setFilters(f => ({ ...f, severity: e.target.value as Severity || undefined }))}
              className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:border-cyber-500"
            >
              <option value="">All Severities</option>
              {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>

            <input
              type="text"
              placeholder="Source IP..."
              value={filters.source_ip || ''}
              onChange={(e) => setFilters(f => ({ ...f, source_ip: e.target.value || undefined }))}
              className="bg-gray-800 border border-gray-700 text-sm text-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:border-cyber-500 w-44"
            />

            {(filters.severity || filters.source_ip) && (
              <button
                onClick={() => setFilters({})}
                className="flex items-center gap-1 text-xs text-red-400 hover:text-red-300"
              >
                <X className="w-3 h-3" /> Clear
              </button>
            )}
          </div>
        )}

        {/* Log Table */}
        <div className="bg-gray-900 rounded-xl border border-gray-700/50 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  {['Timestamp', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'Event Type', 'Severity', 'Bytes Sent'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center text-gray-500">
                      No logs found. Try generating sample data or uploading a log file.
                    </td>
                  </tr>
                ) : (
                  items.map((log) => (
                    <tr key={log.id} className="border-b border-gray-800/50 hover:bg-gray-800/40 transition-colors">
                      <td className="px-4 py-3 text-gray-400 font-mono text-xs whitespace-nowrap">
                        {formatDate(log.timestamp)}
                      </td>
                      <td className="px-4 py-3 text-gray-200 font-mono text-xs">{log.source_ip}</td>
                      <td className="px-4 py-3 text-gray-400 font-mono text-xs">{log.destination_ip || '—'}</td>
                      <td className="px-4 py-3 text-gray-400 text-xs">{log.destination_port ?? '—'}</td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-mono bg-gray-800 px-2 py-0.5 rounded text-gray-300">
                          {log.protocol}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-300 text-xs max-w-[160px] truncate">{log.event_type}</td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={log.severity} />
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-xs">{formatBytes(log.bytes_sent)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {pages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-800">
              <span className="text-xs text-gray-500">
                Page {page} of {pages} ({total.toLocaleString()} entries)
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 text-xs bg-gray-800 rounded-lg text-gray-400 hover:bg-gray-700 disabled:opacity-40"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage(p => Math.min(pages, p + 1))}
                  disabled={page === pages}
                  className="px-3 py-1 text-xs bg-gray-800 rounded-lg text-gray-400 hover:bg-gray-700 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
