import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock, Plus, Trash2, CheckCircle, BookOpen, AlertTriangle, Shield } from 'lucide-react'
import { soarApi } from '../services/api'
import { type BlacklistEntry, type Playbook } from '../types'
import { LoadingSpinner } from '../components/common/LoadingSpinner'
import { format } from 'date-fns'
import toast from 'react-hot-toast'

function PlaybookCard({ name, pb }: { name: string; pb: Playbook }) {
  const [open, setOpen] = useState(false)
  const slaColor = pb.sla_minutes <= 15 ? 'text-red-400' : pb.sla_minutes <= 60 ? 'text-orange-400' : 'text-green-400'

  return (
    <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-4 hover:bg-gray-700/30 transition-colors text-left"
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyber-500/10 border border-cyber-500/20 flex items-center justify-center">
            <Shield className="w-4 h-4 text-cyber-400" />
          </div>
          <div>
            <p className="text-sm font-semibold text-gray-200">{pb.name}</p>
            <p className="text-xs text-gray-500">{pb.steps.length} steps</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`text-xs ${slaColor}`}>SLA: {pb.sla_minutes}m</span>
          <span className="text-gray-600">{open ? '▲' : '▼'}</span>
        </div>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-2 border-t border-gray-700/50">
          {pb.auto_actions.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-3">
              {pb.auto_actions.map(a => (
                <span key={a} className="text-xs px-2 py-0.5 rounded bg-cyan-500/15 border border-cyan-500/30 text-cyan-300">
                  {a.replace(/_/g,' ')}
                </span>
              ))}
            </div>
          )}
          <ol className="space-y-1.5 pt-2">
            {pb.steps.map((step, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-gray-400">
                <span className="shrink-0 w-5 h-5 rounded-full bg-gray-700 text-gray-400 flex items-center justify-center font-mono text-[10px] mt-0.5">
                  {i + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}

function BlockIPModal({ onClose, onBlock }: {
  onClose: () => void
  onBlock: (data: { ip_address: string; reason: string; expires_in_hours?: number }) => void
}) {
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')
  const [expiry, setExpiry] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!ip || !reason) return
    onBlock({ ip_address: ip.trim(), reason, expires_in_hours: expiry ? Number(expiry) : undefined })
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-md p-6">
        <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
          <Lock className="w-4 h-4 text-red-400" />
          Block IP Address
        </h2>
        <form onSubmit={handleSubmit} className="space-y-3">
          <input
            value={ip}
            onChange={e => setIp(e.target.value)}
            placeholder="IP address (e.g. 1.2.3.4)"
            className="w-full px-3 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-red-500 font-mono"
            required
          />
          <textarea
            value={reason}
            onChange={e => setReason(e.target.value)}
            placeholder="Reason for blocking…"
            rows={3}
            className="w-full px-3 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-red-500 resize-none"
            required
          />
          <select
            value={expiry}
            onChange={e => setExpiry(e.target.value)}
            className="w-full px-3 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 focus:outline-none focus:border-red-500"
          >
            <option value="">No expiry (permanent)</option>
            <option value="1">1 hour</option>
            <option value="24">24 hours</option>
            <option value="168">7 days</option>
            <option value="720">30 days</option>
          </select>
          <div className="flex gap-2 pt-2">
            <button
              type="submit"
              className="flex-1 py-2.5 rounded-lg bg-red-500/15 border border-red-500/30 text-red-300 text-sm hover:bg-red-500/25 transition-colors font-medium"
            >
              Block IP
            </button>
            <button
              type="button"
              onClick={onClose}
              className="flex-1 py-2.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-300 text-sm hover:bg-gray-700 transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export function SOARPage() {
  const queryClient = useQueryClient()
  const [showBlockModal, setShowBlockModal] = useState(false)
  const [activeTab, setActiveTab] = useState<'blacklist' | 'playbooks'>('blacklist')

  const { data: blacklist, isLoading } = useQuery({
    queryKey: ['soar-blacklist'],
    queryFn: () => soarApi.getBlacklist(false).then(r => r.data as BlacklistEntry[]),
    refetchInterval: 15_000,
  })

  const { data: stats } = useQuery({
    queryKey: ['soar-stats'],
    queryFn: () => soarApi.getStats().then(r => r.data),
  })

  const { data: playbooks } = useQuery({
    queryKey: ['soar-playbooks'],
    queryFn: () => soarApi.getPlaybooks().then(r => r.data),
  })

  const blockMutation = useMutation({
    mutationFn: (data: { ip_address: string; reason: string; expires_in_hours?: number }) =>
      soarApi.blockIP(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['soar-blacklist'] })
      queryClient.invalidateQueries({ queryKey: ['soar-stats'] })
      toast.success('IP blocked successfully')
    },
    onError: () => toast.error('Failed to block IP'),
  })

  const unblockMutation = useMutation({
    mutationFn: (ip: string) => soarApi.unblockIP(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['soar-blacklist'] })
      toast.success('IP unblocked')
    },
  })

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Lock className="w-6 h-6 text-red-400" />
            SOAR Automation
          </h1>
          <p className="text-sm text-gray-400 mt-0.5">Security Orchestration, Automation & Response</p>
        </div>
        <button
          onClick={() => setShowBlockModal(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-sm hover:bg-red-500/20 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          Block IP
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: 'Total Blocked',  value: stats.total_entries,    color: 'text-gray-200' },
            { label: 'Active Blocks',  value: stats.active_blocks,    color: 'text-red-400' },
            { label: 'Block Hits',     value: stats.total_block_hits, color: 'text-orange-400' },
            { label: 'Auto-Blocked',   value: stats.auto_blocked,     color: 'text-purple-400' },
            { label: 'Manual Blocks',  value: stats.manual_blocked,   color: 'text-blue-400' },
          ].map(s => (
            <div key={s.label} className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-4 text-center">
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
              <p className="text-xs text-gray-500 mt-1">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-800/60 border border-gray-700/50 rounded-xl p-1 w-fit">
        {([
          { key: 'blacklist', label: 'IP Blacklist', icon: Lock },
          { key: 'playbooks', label: 'Playbooks', icon: BookOpen },
        ] as const).map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors ${
              activeTab === tab.key
                ? 'bg-cyber-500/15 text-cyber-300 border border-cyber-500/20'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <tab.icon className="w-3.5 h-3.5" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Blacklist Tab */}
      {activeTab === 'blacklist' && (
        <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl overflow-hidden">
          {isLoading ? <LoadingSpinner /> : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 bg-gray-900/50">
                  {['IP Address','Status','Reason','Risk','Hits','Added By','Expires',''].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(blacklist ?? []).map(entry => (
                  <tr key={entry.id} className="border-b border-gray-700/30 hover:bg-gray-700/20 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-gray-200">{entry.ip_address}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${
                        entry.is_active
                          ? 'text-red-400 bg-red-500/10 border-red-500/20'
                          : 'text-gray-500 bg-gray-700/50 border-gray-600'
                      }`}>
                        {entry.is_active ? 'Blocked' : 'Released'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400 max-w-xs truncate">{entry.reason}</td>
                    <td className="px-4 py-3">
                      {entry.risk_score != null ? (
                        <span className={`text-xs font-mono font-semibold ${
                          entry.risk_score >= 76 ? 'text-red-400' :
                          entry.risk_score >= 51 ? 'text-orange-400' : 'text-yellow-400'
                        }`}>{entry.risk_score.toFixed(0)}</span>
                      ) : <span className="text-gray-600">—</span>}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">{entry.block_hits}</td>
                    <td className="px-4 py-3 text-xs text-gray-500">{entry.added_by}</td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {entry.expires_at
                        ? format(new Date(entry.expires_at), 'MM/dd HH:mm')
                        : '—'
                      }
                    </td>
                    <td className="px-4 py-3">
                      {entry.is_active && (
                        <button
                          onClick={() => unblockMutation.mutate(entry.ip_address)}
                          className="text-xs px-2 py-1 rounded bg-green-500/10 border border-green-500/20 text-green-400 hover:bg-green-500/20 transition-colors"
                        >
                          Unblock
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {(!blacklist || blacklist.length === 0) && !isLoading && (
            <div className="py-16 text-center text-gray-600">
              <CheckCircle className="w-10 h-10 mx-auto mb-2 opacity-30" />
              <p className="text-sm">No IPs blocked yet</p>
              <p className="text-xs mt-1">IPs with risk score ≥ 85 are auto-blocked</p>
            </div>
          )}
        </div>
      )}

      {/* Playbooks Tab */}
      {activeTab === 'playbooks' && (
        <div className="space-y-3">
          {playbooks?.playbooks
            ? Object.entries(playbooks.playbooks as Record<string, Playbook>).map(([name, pb]) => (
                <PlaybookCard key={name} name={name} pb={pb} />
              ))
            : <LoadingSpinner />
          }
        </div>
      )}

      {showBlockModal && (
        <BlockIPModal
          onClose={() => setShowBlockModal(false)}
          onBlock={data => blockMutation.mutate(data)}
        />
      )}
    </div>
  )
}
