import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

interface TopIPsChartProps {
  data: Array<{ ip: string; count: number }>
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: { value: number }[]; label?: string }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 shadow-xl">
      <p className="text-xs text-gray-400 font-mono">{label}</p>
      <p className="text-sm font-semibold text-cyber-300">{payload[0].value.toLocaleString()} events</p>
    </div>
  )
}

export function TopIPsChart({ data }: TopIPsChartProps) {
  const chartData = data.slice(0, 8).map(d => ({ ip: d.ip, count: d.count }))

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700/50 p-5">
      <h3 className="text-sm font-semibold text-gray-200 mb-4">Top Source IPs (24h)</h3>
      {chartData.length === 0 ? (
        <div className="h-48 flex items-center justify-center text-gray-600 text-sm">
          No IP data available
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={chartData} layout="vertical" margin={{ top: 0, right: 10, bottom: 0, left: 10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
            <XAxis
              type="number"
              tick={{ fill: '#6b7280', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              type="category"
              dataKey="ip"
              tick={{ fill: '#9ca3af', fontSize: 10, fontFamily: 'monospace' }}
              tickLine={false}
              axisLine={false}
              width={110}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="count" fill="#1ebef2" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
