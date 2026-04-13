import { useQuery } from '@tanstack/react-query';
import { sessionsApi } from '../lib/api';
import { useNavigate } from 'react-router-dom';
import { formatDistanceToNow } from 'date-fns';
import { clsx } from 'clsx';
import type { AgentSession } from '../lib/types';

const statusColors: Record<string, string> = {
  active: 'bg-green-500/20 text-green-400',
  completed: 'bg-gray-500/20 text-gray-400',
  blocked: 'bg-red-500/20 text-red-400',
  killed: 'bg-red-500/20 text-red-400',
  error: 'bg-orange-500/20 text-orange-400',
};

export default function Sessions() {
  const navigate = useNavigate();
  const { data: sessions = [], isLoading } = useQuery<AgentSession[]>({
    queryKey: ['sessions'],
    queryFn: () => sessionsApi.list({ limit: 100 }) as Promise<AgentSession[]>,
    refetchInterval: 5000,
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-white">Agent Sessions</h1>
        <p className="text-gray-400 text-sm mt-1">{sessions.length} sessions</p>
      </div>

      {isLoading ? (
        <div className="text-gray-500">Loading…</div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800/50">
              <tr className="text-gray-400 text-xs">
                <th className="text-left px-4 py-3">Agent</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-right px-4 py-3">Events</th>
                <th className="text-right px-4 py-3">LLM Calls</th>
                <th className="text-right px-4 py-3">Tool Calls</th>
                <th className="text-right px-4 py-3">Max Threat</th>
                <th className="text-right px-4 py-3">Violations</th>
                <th className="text-right px-4 py-3">Started</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr
                  key={s.id}
                  className="border-t border-gray-800 hover:bg-gray-800/30 cursor-pointer"
                  onClick={() => navigate(`/sessions/${s.id}`)}
                >
                  <td className="px-4 py-3">
                    <div className="font-medium text-white">{s.agent_name}</div>
                    <div className="text-xs text-gray-500">{s.framework}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx('text-xs px-2 py-0.5 rounded-full', statusColors[s.status])}>
                      {s.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right text-gray-300">{s.total_events}</td>
                  <td className="px-4 py-3 text-right text-gray-300">{s.total_llm_calls}</td>
                  <td className="px-4 py-3 text-right text-gray-300">{s.total_tool_calls}</td>
                  <td className={clsx('px-4 py-3 text-right font-medium', s.max_threat_score >= 75 ? 'text-red-400' : s.max_threat_score >= 40 ? 'text-yellow-400' : 'text-gray-400')}>
                    {s.max_threat_score}
                  </td>
                  <td className="px-4 py-3 text-right text-gray-300">{s.violation_count}</td>
                  <td className="px-4 py-3 text-right text-xs text-gray-500">
                    {formatDistanceToNow(new Date(s.started_at), { addSuffix: true })}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={(e) => { e.stopPropagation(); navigate(`/replay/${s.id}`); }}
                      className="text-xs text-blue-400 hover:text-blue-300"
                    >
                      Replay
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
