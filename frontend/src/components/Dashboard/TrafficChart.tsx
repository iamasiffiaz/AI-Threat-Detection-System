import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts'
import { format } from 'date-fns'

interface TrafficChartProps {
  data: Array<{ timestamp: string; count: number }>
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: { value: number }[]; label?: string }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 shadow-xl">
      <p className="text-xs text-gray-400">{label}</p>
      <p className="text-sm font-semibold text-cyber-300">{payload[0].value.toLocaleString()} events</p>
    </div>
  )
}

export function TrafficChart({ data }: TrafficChartProps) {
  const formatted = data.map(d => ({
    ...d,
    label: (() => {
      try { return format(new Date(d.timestamp), 'HH:mm') } catch { return d.timestamp }
    })(),
  }))

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-5">
      <h3 className="text-sm font-semibold text-gray-200 mb-4">Traffic Volume (Last 24h)</h3>
      {data.length === 0 ? (
        <div className="h-48 flex items-center justify-center text-gray-600 text-sm">
          No traffic data available
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={formatted} margin={{ top: 5, right: 5, bottom: 0, left: -10 }}>
            <defs>
              <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#1ebef2" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#1ebef2" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis
              dataKey="label"
              tick={{ fill: '#6b7280', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              tick={{ fill: '#6b7280', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey="count"
              stroke="#1ebef2"
              strokeWidth={2}
              fill="url(#trafficGradient)"
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
