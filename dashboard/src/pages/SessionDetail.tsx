import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { sessionsApi } from '../lib/api';
import type { AgentSession, Event } from '../lib/types';
import { formatDistanceToNow } from 'date-fns';

export default function SessionDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { data: session } = useQuery<AgentSession>({
    queryKey: ['session', id],
    queryFn: () => sessionsApi.get(id!) as Promise<AgentSession>,
    enabled: !!id,
  });

  const { data: events = [] } = useQuery<Event[]>({
    queryKey: ['session-events', id],
    queryFn: () => sessionsApi.getEvents(id!) as Promise<Event[]>,
    enabled: !!id,
    refetchInterval: session?.status === 'active' ? 3000 : false,
  });

  const killMutation = useMutation({
    mutationFn: () => sessionsApi.kill(id!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['session', id] }),
  });

  if (!session) return <div className="text-gray-500">Loading…</div>;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <button onClick={() => navigate('/sessions')} className="text-sm text-gray-500 hover:text-gray-300 mb-1">← Sessions</button>
          <h1 className="text-2xl font-bold text-white">{session.agent_name}</h1>
          <p className="text-gray-400 text-xs mt-1 font-mono">{session.id}</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => navigate(`/replay/${session.id}`)}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-500"
          >
            Replay
          </button>
          {session.status === 'active' && (
            <button
              onClick={() => killMutation.mutate()}
              className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm hover:bg-red-500"
            >
              Kill Session
            </button>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Status', value: session.status },
          { label: 'LLM Calls', value: session.total_llm_calls },
          { label: 'Tool Calls', value: session.total_tool_calls },
          { label: 'Max Threat', value: session.max_threat_score },
          { label: 'Events', value: session.total_events },
          { label: 'Violations', value: session.violation_count },
          { label: 'Framework', value: session.framework },
          { label: 'Started', value: formatDistanceToNow(new Date(session.started_at), { addSuffix: true }) },
        ].map(({ label, value }) => (
          <div key={label} className="bg-gray-900 border border-gray-800 rounded-lg p-3">
            <div className="text-xs text-gray-500">{label}</div>
            <div className="text-lg font-bold text-white mt-1">{value}</div>
          </div>
        ))}
      </div>

      {/* Events */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl">
        <div className="px-5 py-4 border-b border-gray-800">
          <h2 className="font-medium text-white">Events ({events.length})</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-800/50 text-xs text-gray-400">
              <tr>
                <th className="text-left px-4 py-2">Type</th>
                <th className="text-left px-4 py-2">Timestamp</th>
                <th className="text-right px-4 py-2">Threat Score</th>
                <th className="text-right px-4 py-2">Latency</th>
                <th className="text-left px-4 py-2">Reasons</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className={`border-t border-gray-800 ${e.blocked ? 'bg-red-500/5' : ''}`}>
                  <td className="px-4 py-2">
                    <span className="font-mono text-xs text-gray-300">{e.event_type}</span>
                    {e.blocked && <span className="ml-2 text-xs bg-red-500/20 text-red-400 px-1 rounded">BLOCKED</span>}
                  </td>
                  <td className="px-4 py-2 text-xs text-gray-500">{new Date(e.timestamp * 1000).toLocaleTimeString()}</td>
                  <td className={`px-4 py-2 text-right font-medium ${e.threat_score >= 75 ? 'text-red-400' : e.threat_score >= 40 ? 'text-yellow-400' : 'text-gray-400'}`}>
                    {e.threat_score}
                  </td>
                  <td className="px-4 py-2 text-right text-gray-400 text-xs">{e.latency_ms != null ? `${e.latency_ms.toFixed(0)}ms` : '-'}</td>
                  <td className="px-4 py-2 text-xs text-gray-400 truncate max-w-xs">{e.threat_reasons.join('; ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
