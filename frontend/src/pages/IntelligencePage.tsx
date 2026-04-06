import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Globe, Search, Shield, AlertTriangle, Wifi, Server } from 'lucide-react'
import { intelligenceApi } from '../services/api'
import { type ThreatIntelResult } from '../types'
import { LoadingSpinner } from '../components/common/LoadingSpinner'

function ReputationBar({ score }: { score: number }) {
  const color = score >= 75 ? 'bg-red-500' : score >= 50 ? 'bg-orange-500' : score >= 25 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-xs font-mono font-semibold w-8 text-right ${
        score >= 75 ? 'text-red-400' : score >= 50 ? 'text-orange-400' : score >= 25 ? 'text-yellow-400' : 'text-green-400'
      }`}>{score.toFixed(0)}</span>
    </div>
  )
}

function TICard({ result }: { result: ThreatIntelResult }) {
  const flagUrl = result.country_code
    ? `https://flagcdn.com/20x15/${result.country_code.toLowerCase()}.png`
    : null

  return (
    <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-5 space-y-4">
      {/* IP Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gray-900 border border-gray-700 flex items-center justify-center">
            <Globe className="w-5 h-5 text-cyber-400" />
          </div>
          <div>
            <p className="text-lg font-mono font-bold text-white">{result.ip_address}</p>
            <p className="text-xs text-gray-500">{result.source} {result.cached ? '· cached' : '· live'}</p>
          </div>
        </div>
        <div className="flex flex-col gap-1 items-end">
          {result.is_known_bad && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/15 border border-red-500/30 text-red-400">
              Known Malicious
            </span>
          )}
          {result.is_tor_exit && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/15 border border-purple-500/30 text-purple-400">
              Tor Exit Node
            </span>
          )}
          {result.is_proxy && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/15 border border-yellow-500/30 text-yellow-400">
              Proxy
            </span>
          )}
          {result.is_datacenter && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/15 border border-blue-500/30 text-blue-400">
              Datacenter
            </span>
          )}
        </div>
      </div>

      {/* Reputation Score */}
      <div>
        <div className="flex justify-between text-xs text-gray-500 mb-1">
          <span>Threat Reputation Score</span>
          <span className="font-semibold text-gray-300">{result.reputation_score.toFixed(0)}/100</span>
        </div>
        <ReputationBar score={result.reputation_score} />
      </div>

      {/* Geo Info */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-gray-900/60 rounded-lg p-3">
          <p className="text-xs text-gray-500 mb-1">Location</p>
          <div className="flex items-center gap-2">
            {flagUrl && <img src={flagUrl} alt={result.country_code} className="rounded-sm" />}
            <p className="text-sm text-gray-200">
              {[result.city, result.country_name].filter(Boolean).join(', ') || '—'}
            </p>
          </div>
          {result.region && <p className="text-xs text-gray-500 mt-0.5">{result.region}</p>}
        </div>
        <div className="bg-gray-900/60 rounded-lg p-3">
          <p className="text-xs text-gray-500 mb-1">Network</p>
          <p className="text-sm text-gray-200 truncate">{result.isp || '—'}</p>
          {result.asn && <p className="text-xs text-gray-500 font-mono mt-0.5">{result.asn}</p>}
        </div>
      </div>

      {/* Coordinates */}
      {(result.latitude || result.longitude) ? (
        <div className="text-xs text-gray-600 font-mono">
          Coords: {result.latitude.toFixed(4)}, {result.longitude.toFixed(4)}
          {result.timezone_name && ` · ${result.timezone_name}`}
        </div>
      ) : null}

      {/* Threat Categories */}
      {result.threat_categories.length > 0 && (
        <div>
          <p className="text-xs text-gray-500 mb-1.5">Threat Categories</p>
          <div className="flex flex-wrap gap-1.5">
            {result.threat_categories.map(cat => (
              <span key={cat} className="text-xs px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-300">
                {cat.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* AbuseIPDB */}
      {result.abuse_confidence > 0 && (
        <div className="flex items-center justify-between text-xs">
          <span className="text-gray-500">AbuseIPDB Confidence</span>
          <span className="text-red-400 font-semibold">{result.abuse_confidence}%</span>
        </div>
      )}
    </div>
  )
}

export function IntelligencePage() {
  const [ipInput, setIpInput] = useState('')
  const [lookupIP, setLookupIP] = useState<string | null>(null)

  const { data: ti, isLoading, error } = useQuery({
    queryKey: ['ti-lookup', lookupIP],
    queryFn: () => intelligenceApi.lookupIP(lookupIP!).then(r => r.data as ThreatIntelResult),
    enabled: !!lookupIP,
  })

  const { data: topThreats, isLoading: topLoading } = useQuery({
    queryKey: ['top-threats'],
    queryFn: () => intelligenceApi.topThreats(20, 30).then(r => r.data),
    refetchInterval: 60_000,
  })

  const handleLookup = () => {
    const ip = ipInput.trim()
    if (!ip) return
    setLookupIP(ip)
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Globe className="w-6 h-6 text-cyan-400" />
          Threat Intelligence
        </h1>
        <p className="text-sm text-gray-400 mt-0.5">GeoIP lookup, IP reputation, and threat categorization</p>
      </div>

      {/* Lookup Bar */}
      <div className="flex gap-3">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={ipInput}
            onChange={e => setIpInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleLookup()}
            placeholder="Enter IP address for TI lookup…"
            className="w-full pl-10 pr-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyber-500"
          />
        </div>
        <button
          onClick={handleLookup}
          className="px-5 py-3 rounded-xl bg-cyber-500/15 border border-cyber-500/30 text-cyber-300 text-sm hover:bg-cyber-500/25 transition-colors font-medium"
        >
          Lookup
        </button>
      </div>

      {/* Lookup Result */}
      {isLoading && <LoadingSpinner />}
      {error && <p className="text-red-400 text-sm">Lookup failed — check the IP address and try again.</p>}
      {ti && !isLoading && <TICard result={ti} />}

      {/* Top Threats */}
      <div>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-orange-400" />
          Top Threat IPs (seen in system)
        </h2>
        {topLoading ? (
          <LoadingSpinner />
        ) : (
          <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 bg-gray-900/50">
                  {['IP Address','Country','Reputation','ISP','Flags',''].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(topThreats ?? []).map((t: { ip: string; country: string; reputation_score: number; isp: string; is_known_bad: boolean; is_tor_exit: boolean }) => (
                  <tr
                    key={t.ip}
                    className="border-b border-gray-700/30 hover:bg-gray-700/20 cursor-pointer transition-colors"
                    onClick={() => { setIpInput(t.ip); setLookupIP(t.ip) }}
                  >
                    <td className="px-4 py-3 font-mono text-gray-200 text-xs">{t.ip}</td>
                    <td className="px-4 py-3 text-xs text-gray-400">{t.country || '—'}</td>
                    <td className="px-4 py-3 w-36">
                      <ReputationBar score={t.reputation_score} />
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500 max-w-xs truncate">{t.isp || '—'}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1">
                        {t.is_known_bad && <span className="text-xs bg-red-500/15 text-red-400 px-1.5 py-0.5 rounded">Bad</span>}
                        {t.is_tor_exit  && <span className="text-xs bg-purple-500/15 text-purple-400 px-1.5 py-0.5 rounded">Tor</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-cyber-500">→</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(!topThreats || topThreats.length === 0) && (
              <div className="py-12 text-center text-gray-600">
                <Globe className="w-8 h-8 mx-auto mb-2 opacity-30" />
                <p className="text-sm">No threat intel data yet — ingest logs with external IPs</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
