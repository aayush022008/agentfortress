import { useQuery } from '@tanstack/react-query';
import { analyticsApi } from '../lib/api';
import { Shield, Activity, Bell, Ban, Users, TrendingUp } from 'lucide-react';
import EventsTimeline from '../components/charts/EventsTimeline';
import ThreatMap from '../components/charts/ThreatMap';
import type { OverviewStats, EventsBucket, ThreatDistribution, TopAgent } from '../lib/types';
import { useWebSocket } from '../hooks/useWebSocket';
import { useState } from 'react';

function StatCard({ title, value, icon: Icon, color }: { title: string; value: number | string; icon: React.ElementType; color: string }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{title}</p>
          <p className={`text-3xl font-bold mt-1 ${color}`}>{value}</p>
        </div>
        <Icon className={`h-8 w-8 ${color} opacity-80`} />
      </div>
    </div>
  );
}

export default function Overview() {
  const { data: stats } = useQuery<OverviewStats>({ queryKey: ['overview'], queryFn: () => analyticsApi.overview() as Promise<OverviewStats>, refetchInterval: 10000 });
  const { data: timeline } = useQuery<EventsBucket[]>({ queryKey: ['events-timeline'], queryFn: () => analyticsApi.eventsOverTime(24) as Promise<EventsBucket[]>, refetchInterval: 30000 });
  const { data: threats } = useQuery<ThreatDistribution[]>({ queryKey: ['threat-dist'], queryFn: () => analyticsApi.threatDistribution() as Promise<ThreatDistribution[]>, refetchInterval: 60000 });
  const { data: topAgents } = useQuery<TopAgent[]>({ queryKey: ['top-agents'], queryFn: () => analyticsApi.topAgents() as Promise<TopAgent[]>, refetchInterval: 60000 });

  const [liveEvents, setLiveEvents] = useState<string[]>([]);
  useWebSocket({ onEvent: (e) => setLiveEvents(prev => [`${e.event_type} from ${e.agent_name} (score: ${e.threat_score})`, ...prev.slice(0, 9)]) });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Security Overview</h1>
        <p className="text-gray-400 text-sm mt-1">Real-time AI agent security monitoring</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard title="Active Sessions" value={stats?.active_sessions ?? 0} icon={Activity} color="text-green-400" />
        <StatCard title="Total Events" value={stats?.total_events ?? 0} icon={TrendingUp} color="text-blue-400" />
        <StatCard title="Open Alerts" value={stats?.open_alerts ?? 0} icon={Bell} color="text-yellow-400" />
        <StatCard title="Critical Alerts" value={stats?.critical_alerts ?? 0} icon={Shield} color="text-red-400" />
        <StatCard title="Blocked Events" value={stats?.blocked_events ?? 0} icon={Ban} color="text-red-400" />
        <StatCard title="Total Sessions" value={stats?.total_sessions ?? 0} icon={Users} color="text-purple-400" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-4">Events (Last 24 Hours)</h2>
          <EventsTimeline data={timeline ?? []} />
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-4">Threat Distribution</h2>
          <ThreatMap data={threats ?? []} />
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Live feed */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
            <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
            Live Event Feed
          </h2>
          {liveEvents.length === 0 ? (
            <p className="text-gray-500 text-sm">Waiting for events…</p>
          ) : (
            <ul className="space-y-1">
              {liveEvents.map((e, i) => (
                <li key={i} className="text-xs text-gray-400 font-mono truncate">{e}</li>
              ))}
            </ul>
          )}
        </div>

        {/* Top agents by risk */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-3">Top Agents by Risk</h2>
          {!topAgents?.length ? (
            <p className="text-gray-500 text-sm">No agent data yet</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 text-xs">
                  <th className="text-left pb-2">Agent</th>
                  <th className="text-right pb-2">Sessions</th>
                  <th className="text-right pb-2">Avg Threat</th>
                  <th className="text-right pb-2">Violations</th>
                </tr>
              </thead>
              <tbody>
                {topAgents.map((a, i) => (
                  <tr key={i} className="border-t border-gray-800">
                    <td className="py-1.5 text-gray-300 truncate max-w-[120px]">{a.agent_name}</td>
                    <td className="py-1.5 text-right text-gray-400">{a.session_count}</td>
                    <td className={`py-1.5 text-right font-medium ${a.avg_threat_score >= 60 ? 'text-red-400' : a.avg_threat_score >= 30 ? 'text-yellow-400' : 'text-green-400'}`}>{a.avg_threat_score}</td>
                    <td className="py-1.5 text-right text-gray-400">{a.total_violations}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
