import { useQuery } from '@tanstack/react-query';
import { analyticsApi } from '../lib/api';
import EventsTimeline from '../components/charts/EventsTimeline';
import ThreatMap from '../components/charts/ThreatMap';
import type { EventsBucket, ThreatDistribution, TopAgent } from '../lib/types';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function Analytics() {
  const { data: timeline } = useQuery<EventsBucket[]>({ queryKey: ['events-timeline-24'], queryFn: () => analyticsApi.eventsOverTime(24) as Promise<EventsBucket[]> });
  const { data: threats } = useQuery<ThreatDistribution[]>({ queryKey: ['threat-dist'], queryFn: () => analyticsApi.threatDistribution() as Promise<ThreatDistribution[]> });
  const { data: topAgents } = useQuery<TopAgent[]>({ queryKey: ['top-agents'], queryFn: () => analyticsApi.topAgents() as Promise<TopAgent[]> });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">Analytics</h1>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h2 className="text-sm font-medium text-gray-300 mb-4">Events Over Time (24h)</h2>
        <EventsTimeline data={timeline ?? []} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-4">Threat Distribution</h2>
          <ThreatMap data={threats ?? []} />
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-4">Top Agents by Avg Threat Score</h2>
          {topAgents?.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={topAgents} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" tick={{ fill: '#9CA3AF', fontSize: 11 }} domain={[0, 100]} />
                <YAxis dataKey="agent_name" type="category" tick={{ fill: '#9CA3AF', fontSize: 11 }} width={100} />
                <Tooltip contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }} />
                <Bar dataKey="avg_threat_score" fill="#EF4444" name="Avg Threat Score" />
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="text-gray-500 text-sm">No data</div>}
        </div>
      </div>
    </div>
  );
}
