import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import type { ThreatDistribution } from '../../lib/types';

interface ThreatMapProps {
  data: ThreatDistribution[];
}

const COLORS = ['#EF4444', '#F59E0B', '#8B5CF6', '#3B82F6', '#10B981', '#6B7280'];

export default function ThreatMap({ data }: ThreatMapProps) {
  if (!data.length) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-500">
        No threat data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={250}>
      <PieChart>
        <Pie
          data={data}
          dataKey="count"
          nameKey="type"
          cx="50%"
          cy="50%"
          outerRadius={80}
          label={({ type, percent }) => `${type.replace(/_/g, ' ')} ${(percent * 100).toFixed(0)}%`}
          labelLine={false}
        >
          {data.map((_, index) => (
            <Cell key={index} fill={COLORS[index % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }}
          formatter={(value: number, name: string) => [value, name.replace(/_/g, ' ')]}
        />
        <Legend formatter={(value: string) => value.replace(/_/g, ' ')} />
      </PieChart>
    </ResponsiveContainer>
  );
}
