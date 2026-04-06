/**
 * EventViewerPage
 * ================
 * Real-time Windows Event Viewer integration dashboard.
 * Shows live security events pulled from the Windows Event Log and ingested
 * directly into the AI threat detection pipeline.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, CheckCircle, XCircle,
  Play, Square, RefreshCw, Download, Filter,
  Shield, Monitor, Zap, Clock, Eye, ChevronDown,
  ChevronRight, Server, User, Globe, Lock,
} from 'lucide-react'
import { eventViewerApi } from '../services/api'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'

// ─── Types ─────────────────────────────────────────────────────────────────────

interface ServiceStatus {
  running: boolean
  status: string
  poll_interval_s: number
  channels: string[]
  active_channels: string[]
  denied_channels: string[]
  events_ingested: number
  last_record_ids: Record<string, number>
  last_error: string | null
  is_windows: boolean
  platform: string
}

interface RecentEvent {
  record_id: number
  event_id: number
  channel: string
  timestamp: string
  event_type: string
  severity: string
  source_ip: string
  username: string | null
  message: string
}

// ─── Severity helpers ──────────────────────────────────────────────────────────

const severityColor: Record<string, string> = {
  critical: 'bg-red-900/60 text-red-300 border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  low:      'bg-blue-900/60 text-blue-300 border-blue-700',
  info:     'bg-slate-800 text-slate-300 border-slate-600',
}

const severityDot: Record<string, string> = {
  critical: 'bg-red-400',
  high:     'bg-orange-400',
  medium:   'bg-yellow-400',
  low:      'bg-blue-400',
  info:     'bg-slate-400',
}

const severityRowBg: Record<string, string> = {
  critical: 'bg-red-950/20 hover:bg-red-950/40',
  high:     'bg-orange-950/20 hover:bg-orange-950/30',
  medium:   'bg-yellow-950/10 hover:bg-yellow-950/25',
  low:      'hover:bg-slate-700/30',
  info:     'hover:bg-slate-700/20',
}

// ─── Known high-priority event IDs ────────────────────────────────────────────

const CRITICAL_EVENT_IDS = new Set([4740, 4697, 7045, 4719, 4625, 4946, 4947])
const HIGH_EVENT_IDS      = new Set([4720, 4726, 4698, 4688, 4724, 4732, 4672])

function eventIdBadgeClass(eventId: number): string {
  if (CRITICAL_EVENT_IDS.has(eventId)) return 'bg-red-800 text-red-200'
  if (HIGH_EVENT_IDS.has(eventId))     return 'bg-orange-800 text-orange-200'
  return 'bg-slate-700 text-slate-300'
}

// ─── DEFAULT_CHANNELS ─────────────────────────────────────────────────────────

const DEFAULT_CHANNELS = ['Security', 'System', 'Application']
const EXTRA_CHANNELS = [
  'Microsoft-Windows-PowerShell/Operational',
  'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
  'Microsoft-Windows-Windows Defender/Operational',
  'Microsoft-Windows-AppLocker/EXE and DLL',
]

// ─── Component ─────────────────────────────────────────────────────────────────

export default function EventViewerPage() {
  const queryClient = useQueryClient()
  // Security channel requires SeSecurityPrivilege — not included by default
  const [selectedChannels, setSelectedChannels] = useState<string[]>(
    DEFAULT_CHANNELS.filter(ch => ch !== 'Security')
  )
  const [interval, setIntervalSec] = useState(5)
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedEvent, setExpandedEvent] = useState<number | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [showChannelPicker, setShowChannelPicker] = useState(false)
  const [dismissedWarning, setDismissedWarning] = useState(false)
  const autoRefreshRef = useRef(autoRefresh)
  autoRefreshRef.current = autoRefresh

  // ── Status query ──────────────────────────────────────────────────────────
  const { data: statusData, refetch: refetchStatus } = useQuery({
    queryKey: ['event-viewer-status'],
    queryFn: () => eventViewerApi.getStatus(),
    refetchInterval: 3000,
  })

  const status: ServiceStatus | null = statusData?.data ?? null

  // ── Recent events query ───────────────────────────────────────────────────
  const { data: recentData, refetch: refetchRecent } = useQuery({
    queryKey: ['event-viewer-recent'],
    queryFn: () => eventViewerApi.getRecent(200),
    refetchInterval: autoRefresh ? 5000 : false,
  })

  const allEvents: RecentEvent[] = recentData?.data?.events ?? []

  // ── Mutations ─────────────────────────────────────────────────────────────
  const startMutation = useMutation({
    mutationFn: () => eventViewerApi.start(selectedChannels, interval),
    onSuccess: () => {
      toast.success('Event feed started')
      queryClient.invalidateQueries({ queryKey: ['event-viewer-status'] })
      queryClient.invalidateQueries({ queryKey: ['event-viewer-recent'] })
    },
    onError: (e: any) => toast.error(`Start failed: ${e?.response?.data?.detail ?? e.message}`),
  })

  const stopMutation = useMutation({
    mutationFn: () => eventViewerApi.stop(),
    onSuccess: () => {
      toast.success('Event feed stopped')
      queryClient.invalidateQueries({ queryKey: ['event-viewer-status'] })
    },
    onError: (e: any) => toast.error(`Stop failed: ${e?.response?.data?.detail ?? e.message}`),
  })

  const pullMutation = useMutation({
    mutationFn: (channel: string) => eventViewerApi.pullNow(channel, 50),
    onSuccess: (res) => {
      const n = res?.data?.ingested ?? 0
      toast.success(`Pulled & ingested ${n} events from ${res?.data?.channel}`)
      queryClient.invalidateQueries({ queryKey: ['event-viewer-recent'] })
      refetchStatus()
    },
    onError: (e: any) => toast.error(`Pull failed: ${e?.response?.data?.detail ?? e.message}`),
  })

  const resetMutation = useMutation({
    mutationFn: () => eventViewerApi.resetWatermarks(),
    onSuccess: (res) => {
      toast.success(res?.data?.message ?? 'Backfill started — loading 30 days of events…')
      queryClient.invalidateQueries({ queryKey: ['event-viewer-status'] })
      queryClient.invalidateQueries({ queryKey: ['event-viewer-recent'] })
    },
    onError: (e: any) => toast.error(`Reset failed: ${e?.response?.data?.detail ?? e.message}`),
  })

  const purgeMutation = useMutation({
    mutationFn: () => eventViewerApi.purgeSampleData(),
    onSuccess: (res) => {
      toast.success(`${res?.data?.deleted ?? 0} old entries cleared. Ready for real data.`)
      queryClient.invalidateQueries({ queryKey: ['event-viewer-status'] })
      queryClient.invalidateQueries({ queryKey: ['event-viewer-recent'] })
    },
    onError: (e: any) => toast.error(`Purge failed: ${e?.response?.data?.detail ?? e.message}`),
  })

  // ── Filtered events ───────────────────────────────────────────────────────
  const filteredEvents = allEvents
    .filter(ev => {
      if (severityFilter !== 'all' && ev.severity !== severityFilter) return false
      if (searchQuery) {
        const q = searchQuery.toLowerCase()
        return (
          ev.message.toLowerCase().includes(q) ||
          ev.event_type.toLowerCase().includes(q) ||
          ev.source_ip.includes(q) ||
          (ev.username ?? '').toLowerCase().includes(q) ||
          String(ev.event_id).includes(q)
        )
      }
      return true
    })
    .slice()
    .reverse()  // newest first

  // ── Stats ─────────────────────────────────────────────────────────────────
  const stats = {
    total:    allEvents.length,
    critical: allEvents.filter(e => e.severity === 'critical').length,
    high:     allEvents.filter(e => e.severity === 'high').length,
    medium:   allEvents.filter(e => e.severity === 'medium').length,
  }

  const toggleChannel = (ch: string) => {
    setSelectedChannels(prev =>
      prev.includes(ch) ? prev.filter(c => c !== ch) : [...prev, ch]
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Monitor className="w-7 h-7 text-blue-400" />
            Windows Event Viewer
          </h1>
          <p className="text-slate-400 mt-1">
            Real-time security events from Windows Event Log — ingested directly into the AI pipeline
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
              autoRefresh
                ? 'bg-green-900/40 text-green-300 border border-green-700'
                : 'bg-slate-700 text-slate-400 border border-slate-600'
            }`}
          >
            <RefreshCw className={`w-4 h-4 ${autoRefresh ? 'animate-spin' : ''}`} />
            {autoRefresh ? 'Live' : 'Paused'}
          </button>

          {/* Reset watermarks */}
          <button
            onClick={() => resetMutation.mutate()}
            disabled={resetMutation.isPending || !status?.is_windows}
            title="Clear watermarks and backfill last 30 days of events, then switch to live polling"
            className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 border border-slate-600 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${resetMutation.isPending ? 'animate-spin' : ''}`} />
            {resetMutation.isPending ? 'Backfilling…' : 'Load 30 Days'}
          </button>

          {/* Purge old/sample data */}
          <button
            onClick={() => {
              if (window.confirm('Delete ALL existing log entries, alerts and anomalies? This clears old/sample data so the model trains on real Windows events only.')) {
                purgeMutation.mutate()
              }
            }}
            disabled={purgeMutation.isPending}
            title="Remove all old/sample data from the database"
            className="flex items-center gap-2 px-3 py-2 bg-red-900/40 hover:bg-red-800/60 text-red-300 border border-red-700/50 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            <XCircle className={`w-4 h-4 ${purgeMutation.isPending ? 'animate-spin' : ''}`} />
            {purgeMutation.isPending ? 'Clearing…' : 'Clear Old Data'}
          </button>

          {/* Start / Stop */}
          {status?.running ? (
            <button
              onClick={() => stopMutation.mutate()}
              disabled={stopMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
            >
              <Square className="w-4 h-4" />
              Stop Feed
            </button>
          ) : (
            <button
              onClick={() => startMutation.mutate()}
              disabled={startMutation.isPending || !status?.is_windows}
              title={!status?.is_windows ? `Not available on ${status?.platform ?? 'this OS'}` : ''}
              className="flex items-center gap-2 px-4 py-2 bg-green-700 hover:bg-green-600 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className="w-4 h-4" />
              Start Feed
            </button>
          )}
        </div>
      </div>

      {/* Platform warning */}
      {status && !status.is_windows && (
        <div className="flex items-start gap-3 p-4 bg-yellow-900/30 border border-yellow-700 rounded-xl">
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-yellow-300 font-medium">Windows-Only Feature</div>
            <div className="text-yellow-400/80 text-sm mt-1">
              Windows Event Viewer integration is only available when the backend runs on Windows.
              Current platform: <span className="font-mono">{status.platform}</span>
            </div>
          </div>
        </div>
      )}

      {/* Admin rights warning */}
      {!dismissedWarning && status && (status.denied_channels ?? []).length > 0 && (
        <div className="flex items-start gap-3 p-4 bg-yellow-900/20 border border-yellow-700/50 rounded-xl">
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="text-yellow-300 font-medium">
                {(status.denied_channels ?? []).join(', ')} channel{(status.denied_channels ?? []).length > 1 ? 's' : ''} require elevated access
              </span>
              <button
                onClick={() => setDismissedWarning(true)}
                className="text-yellow-600 hover:text-yellow-400 text-lg leading-none ml-4 flex-shrink-0"
                title="Dismiss"
              >×</button>
            </div>
            <div className="text-yellow-400/70 text-sm mt-1">
              {(status.active_channels ?? []).length > 0
                ? <>Active channels: <span className="text-yellow-300">{(status.active_channels ?? []).join(', ')}</span> — events are flowing. Security adds login/lockout events on top.</>
                : 'Other channels are still monitored normally.'
              }
            </div>
            <div className="text-yellow-300 text-sm mt-2 font-medium">
              Easy fix — double-click this file to restart as Admin automatically:
            </div>
            <div className="mt-1">
              <code className="text-green-300 font-mono bg-black/40 border border-green-900/50 px-3 py-1.5 rounded text-xs select-all block">
                C:\Users\User\Desktop\Github\AI Threat Detection System\START_BACKEND_ADMIN.bat
              </code>
            </div>
            <div className="text-yellow-400/50 text-xs mt-2">
              Or stop the current backend and run it from an already-open Admin PowerShell. The .bat file handles elevation automatically.
            </div>
          </div>
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Service Status"
          value={status?.running ? 'Active' : 'Stopped'}
          icon={status?.running ? <CheckCircle className="w-5 h-5 text-green-400" /> : <XCircle className="w-5 h-5 text-slate-400" />}
          sub={status?.status ?? 'Unknown'}
          accent={status?.running ? 'green' : 'slate'}
        />
        <StatCard
          label="Events Ingested"
          value={(status?.events_ingested ?? 0).toLocaleString()}
          icon={<Activity className="w-5 h-5 text-blue-400" />}
          sub="Total since start"
          accent="blue"
        />
        <StatCard
          label="Critical / High"
          value={`${stats.critical} / ${stats.high}`}
          icon={<AlertTriangle className="w-5 h-5 text-red-400" />}
          sub="In last 200 events"
          accent="red"
        />
        <StatCard
          label="Poll Interval"
          value={`${status?.poll_interval_s ?? '—'}s`}
          icon={<Clock className="w-5 h-5 text-purple-400" />}
          sub={
            (status?.denied_channels ?? []).length > 0
              ? `${(status?.active_channels ?? []).length} active · ${(status?.denied_channels ?? []).length} denied`
              : `${(status?.channels ?? []).length} channels`
          }
          accent="purple"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuration Panel */}
        <div className="lg:col-span-1 space-y-4">
          {/* Channel Configuration */}
          <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-4">
            <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-400" />
              Channel Configuration
            </h3>

            <div className="space-y-2 mb-4">
              <div className="text-slate-400 text-xs uppercase tracking-wider mb-2">Core Channels</div>
              {DEFAULT_CHANNELS.map(ch => (
                <label key={ch} className="flex items-center gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={selectedChannels.includes(ch)}
                    onChange={() => toggleChannel(ch)}
                    className="w-4 h-4 accent-blue-500"
                    disabled={status?.running}
                  />
                  <span className={`text-sm font-mono ${
                    selectedChannels.includes(ch) ? 'text-white' : 'text-slate-500'
                  }`}>{ch}</span>
                </label>
              ))}

              <button
                onClick={() => setShowChannelPicker(v => !v)}
                className="flex items-center gap-1 text-slate-400 hover:text-slate-300 text-xs mt-2"
              >
                {showChannelPicker ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                More channels
              </button>

              {showChannelPicker && (
                <div className="space-y-2 pl-2 border-l border-slate-600 mt-2">
                  {EXTRA_CHANNELS.map(ch => (
                    <label key={ch} className="flex items-center gap-3 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedChannels.includes(ch)}
                        onChange={() => toggleChannel(ch)}
                        className="w-4 h-4 accent-blue-500"
                        disabled={status?.running}
                      />
                      <span className={`text-xs font-mono leading-tight ${
                        selectedChannels.includes(ch) ? 'text-white' : 'text-slate-500'
                      }`}>{ch.split('/')[0].replace('Microsoft-Windows-', '')}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            <div className="mb-4">
              <label className="text-slate-400 text-xs mb-1 block">Poll Interval</label>
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min={2} max={30} step={1}
                  value={interval}
                  onChange={e => setIntervalSec(Number(e.target.value))}
                  disabled={status?.running}
                  className="flex-1 accent-blue-500"
                />
                <span className="text-white text-sm w-10 text-right">{interval}s</span>
              </div>
            </div>

            <div className="flex gap-2">
              {!status?.running ? (
                <button
                  onClick={() => startMutation.mutate()}
                  disabled={startMutation.isPending || !status?.is_windows || selectedChannels.length === 0}
                  className="flex-1 flex items-center justify-center gap-2 py-2 bg-green-700 hover:bg-green-600 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                >
                  <Play className="w-4 h-4" />
                  {startMutation.isPending ? 'Starting…' : 'Start'}
                </button>
              ) : (
                <button
                  onClick={() => stopMutation.mutate()}
                  disabled={stopMutation.isPending}
                  className="flex-1 flex items-center justify-center gap-2 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
                >
                  <Square className="w-4 h-4" />
                  Stop
                </button>
              )}
            </div>
          </div>

          {/* Manual Pull */}
          <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-4">
            <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
              <Download className="w-4 h-4 text-purple-400" />
              Manual Pull
            </h3>
            <p className="text-slate-400 text-xs mb-3">
              Immediately pull the 50 most recent events from a channel and ingest them.
            </p>
            <div className="space-y-2">
              {['Security', 'System', 'Application'].map(ch => (
                <button
                  key={ch}
                  onClick={() => pullMutation.mutate(ch)}
                  disabled={!status?.is_windows || pullMutation.isPending}
                  className="w-full flex items-center justify-between px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm transition-colors disabled:opacity-50"
                >
                  <span className="font-mono">{ch}</span>
                  <Zap className="w-4 h-4 text-purple-400" />
                </button>
              ))}
            </div>
          </div>

          {/* Record ID watermarks */}
          {status?.last_record_ids && Object.keys(status.last_record_ids).length > 0 && (
            <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-4">
              <h3 className="text-slate-400 font-medium text-sm mb-2">Watermarks (Last RecordID)</h3>
              <div className="space-y-1">
                {Object.entries(status.last_record_ids).map(([ch, rid]) => (
                  <div key={ch} className="flex justify-between items-center text-xs">
                    <span className="text-slate-400 font-mono truncate max-w-[70%]">
                      {ch.replace('Microsoft-Windows-', 'MW-')}
                    </span>
                    <span className="text-slate-500 font-mono">{rid.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Events Feed */}
        <div className="lg:col-span-2 flex flex-col gap-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search events, IPs, users…"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex items-center gap-1 bg-slate-800 border border-slate-700 rounded-lg p-1">
              {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-3 py-1 rounded text-xs font-medium transition-colors capitalize ${
                    severityFilter === sev
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Events Table */}
          <div className="bg-slate-800/60 border border-slate-700 rounded-xl overflow-hidden flex-1">
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
              <span className="text-white font-medium">
                Live Event Feed
                <span className="text-slate-400 text-sm ml-2">({filteredEvents.length} events)</span>
              </span>
              {status?.running && (
                <span className="flex items-center gap-1.5 text-green-400 text-xs">
                  <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
                  Live
                </span>
              )}
            </div>

            <div className="overflow-y-auto max-h-[600px]">
              {filteredEvents.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center">
                  <Eye className="w-12 h-12 text-slate-600 mb-3" />
                  <div className="text-slate-400 font-medium">No events yet</div>
                  <div className="text-slate-500 text-sm mt-1">
                    {status?.running
                      ? 'Waiting for Windows security events…'
                      : 'Start the feed or pull manually to see events'}
                  </div>
                </div>
              ) : (
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-xs text-slate-400 uppercase tracking-wider border-b border-slate-700/50">
                      <th className="px-4 py-2 w-8"></th>
                      <th className="px-4 py-2">Time</th>
                      <th className="px-4 py-2">Event ID</th>
                      <th className="px-4 py-2">Type</th>
                      <th className="px-4 py-2">Source</th>
                      <th className="px-4 py-2">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/30">
                    {filteredEvents.map((ev) => (
                      <>
                        <tr
                          key={`${ev.record_id}-${ev.timestamp}`}
                          className={`text-sm cursor-pointer transition-colors ${severityRowBg[ev.severity] ?? 'hover:bg-slate-700/20'}`}
                          onClick={() => setExpandedEvent(
                            expandedEvent === ev.record_id ? null : ev.record_id
                          )}
                        >
                          <td className="px-4 py-2.5">
                            {expandedEvent === ev.record_id
                              ? <ChevronDown className="w-3 h-3 text-slate-400" />
                              : <ChevronRight className="w-3 h-3 text-slate-500" />
                            }
                          </td>
                          <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap font-mono text-xs">
                            {formatDistanceToNow(new Date(ev.timestamp), { addSuffix: true })}
                          </td>
                          <td className="px-4 py-2.5">
                            <span className={`font-mono text-xs px-2 py-0.5 rounded ${eventIdBadgeClass(ev.event_id)}`}>
                              {ev.event_id}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-slate-200 max-w-[180px]">
                            <span className="truncate block text-xs">{ev.event_type.replace(/_/g, ' ')}</span>
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-1.5">
                              {ev.source_ip && ev.source_ip !== '127.0.0.1' && (
                                <span className="text-blue-300 font-mono text-xs">{ev.source_ip}</span>
                              )}
                              {ev.username && (
                                <span className="flex items-center gap-1 text-slate-400 text-xs">
                                  <User className="w-3 h-3" />
                                  {ev.username}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className={`flex items-center gap-1.5 text-xs px-2 py-0.5 rounded border ${severityColor[ev.severity] ?? severityColor.info}`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${severityDot[ev.severity] ?? severityDot.info}`} />
                              {ev.severity}
                            </span>
                          </td>
                        </tr>

                        {expandedEvent === ev.record_id && (
                          <tr key={`${ev.record_id}-detail`} className="bg-slate-900/60">
                            <td colSpan={6} className="px-6 py-4">
                              <EventDetail event={ev} />
                            </td>
                          </tr>
                        )}
                      </>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Sub-components ─────────────────────────────────────────────────────────────

function StatCard({
  label, value, icon, sub, accent,
}: {
  label: string
  value: string
  icon: React.ReactNode
  sub: string
  accent: 'green' | 'blue' | 'red' | 'purple' | 'slate'
}) {
  const accents = {
    green:  'border-green-700/50 bg-green-900/20',
    blue:   'border-blue-700/50 bg-blue-900/20',
    red:    'border-red-700/50 bg-red-900/20',
    purple: 'border-purple-700/50 bg-purple-900/20',
    slate:  'border-slate-700 bg-slate-800/60',
  }
  return (
    <div className={`rounded-xl border p-4 ${accents[accent]}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-slate-400 text-sm">{label}</span>
        {icon}
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="text-slate-500 text-xs mt-1">{sub}</div>
    </div>
  )
}

function EventDetail({ event }: { event: RecentEvent }) {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
        <DetailField label="Channel" value={event.channel} icon={<Server className="w-3 h-3" />} />
        <DetailField label="Record ID" value={String(event.record_id)} icon={<Shield className="w-3 h-3" />} mono />
        <DetailField label="Timestamp" value={new Date(event.timestamp).toLocaleString()} icon={<Clock className="w-3 h-3" />} />
        <DetailField
          label="Source IP"
          value={event.source_ip || '—'}
          icon={<Globe className="w-3 h-3" />}
          mono
        />
      </div>

      <div className="bg-slate-900/70 rounded-lg p-3 font-mono text-xs text-slate-300 leading-relaxed border border-slate-700/50">
        {event.message}
      </div>
    </div>
  )
}

function DetailField({
  label, value, icon, mono = false,
}: {
  label: string
  value: string
  icon?: React.ReactNode
  mono?: boolean
}) {
  return (
    <div>
      <div className="flex items-center gap-1 text-slate-500 text-xs mb-1">
        {icon}
        {label}
      </div>
      <div className={`text-slate-200 text-sm ${mono ? 'font-mono' : ''}`}>{value}</div>
    </div>
  )
}
