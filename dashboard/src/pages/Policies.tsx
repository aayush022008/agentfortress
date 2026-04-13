import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { policiesApi } from '../lib/api';
import { useNavigate } from 'react-router-dom';
import type { Policy } from '../lib/types';
import { clsx } from 'clsx';

const actionColors: Record<string, string> = {
  BLOCK: 'text-red-400 bg-red-500/10',
  ALERT: 'text-yellow-400 bg-yellow-500/10',
  LOG: 'text-gray-400 bg-gray-500/10',
  RATE_LIMIT: 'text-cyan-400 bg-cyan-500/10',
};

export default function Policies() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { data: policies = [], isLoading } = useQuery<Policy[]>({ queryKey: ['policies'], queryFn: () => policiesApi.list() as Promise<Policy[]> });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      policiesApi.update(id, { is_enabled: enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['policies'] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => policiesApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['policies'] }),
  });

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Policies</h1>
          <p className="text-gray-400 text-sm mt-1">{policies.length} policies configured</p>
        </div>
        <button
          onClick={() => navigate('/policies/new')}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-500"
        >
          + New Policy
        </button>
      </div>

      {isLoading ? (
        <div className="text-gray-500">Loading…</div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800/50 text-xs text-gray-400">
              <tr>
                <th className="text-left px-4 py-3">Name</th>
                <th className="text-left px-4 py-3">Action</th>
                <th className="text-left px-4 py-3">Severity</th>
                <th className="text-right px-4 py-3">Triggers</th>
                <th className="text-center px-4 py-3">Enabled</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id} className="border-t border-gray-800">
                  <td className="px-4 py-3">
                    <div className="font-medium text-white">{p.name}</div>
                    {p.description && <div className="text-xs text-gray-500 truncate max-w-xs">{p.description}</div>}
                    {p.is_builtin && <span className="text-xs text-purple-400">Built-in</span>}
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx('text-xs px-2 py-0.5 rounded font-medium', actionColors[p.action])}>
                      {p.action}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-300 capitalize">{p.severity}</td>
                  <td className="px-4 py-3 text-right text-gray-300">{p.trigger_count}</td>
                  <td className="px-4 py-3 text-center">
                    <button
                      onClick={() => toggleMutation.mutate({ id: p.id, enabled: !p.is_enabled })}
                      className={clsx('w-9 h-5 rounded-full transition-colors', p.is_enabled ? 'bg-green-600' : 'bg-gray-700')}
                    >
                      <span className={clsx('block w-4 h-4 rounded-full bg-white transition-transform mx-0.5', p.is_enabled ? 'translate-x-4' : 'translate-x-0')} />
                    </button>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {!p.is_builtin && (
                      <button
                        onClick={() => deleteMutation.mutate(p.id)}
                        className="text-xs text-red-400 hover:text-red-300"
                      >
                        Delete
                      </button>
                    )}
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
