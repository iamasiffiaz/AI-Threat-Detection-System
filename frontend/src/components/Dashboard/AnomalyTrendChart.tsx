import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine
} from 'recharts'
import { format } from 'date-fns'

interface AnomalyTrendChartProps {
  data: Array<{ timestamp: string; count: number; avg_score: number }>
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 shadow-xl space-y-1">
      <p className="text-xs text-gray-400">{label}</p>
      {payload.map(p => (
        <p key={p.name} className="text-sm font-semibold" style={{ color: p.color }}>
          {p.name === 'avg_score'
            ? `Avg Score: ${(p.value * 100).toFixed(1)}%`
            : `Anomalies: ${p.value}`}
        </p>
      ))}
    </div>
  )
}

export function AnomalyTrendChart({ data }: AnomalyTrendChartProps) {
  const formatted = data.map(d => ({
    ...d,
    label: (() => {
      try { return format(new Date(d.timestamp), 'HH:mm') } catch { return d.timestamp }
    })(),
  }))

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-5">
      <h3 className="text-sm font-semibold text-gray-200 mb-4">Anomaly Trends (24h)</h3>
      {data.length === 0 ? (
        <div className="h-48 flex items-center justify-center text-gray-600 text-sm">
          No anomaly data
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={formatted} margin={{ top: 5, right: 5, bottom: 0, left: -10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis
              dataKey="label"
              tick={{ fill: '#6b7280', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              yAxisId="count"
              tick={{ fill: '#6b7280', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              yAxisId="score"
              orientation="right"
              domain={[0, 1]}
              tick={{ fill: '#6b7280', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip content={<CustomTooltip />} />
            <ReferenceLine yAxisId="score" y={0.6} stroke="#ef4444" strokeDasharray="4 2" strokeOpacity={0.5} />
            <Line
              yAxisId="count"
              type="monotone"
              dataKey="count"
              stroke="#f97316"
              strokeWidth={2}
              dot={false}
              name="count"
            />
            <Line
              yAxisId="score"
              type="monotone"
              dataKey="avg_score"
              stroke="#ef4444"
              strokeWidth={1.5}
              dot={false}
              strokeDasharray="4 2"
              name="avg_score"
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
