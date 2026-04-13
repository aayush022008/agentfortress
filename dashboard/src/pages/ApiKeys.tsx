import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiKeysApi } from '../lib/api';
import type { ApiKey } from '../lib/types';
import { formatDistanceToNow } from 'date-fns';

interface CreatedKey extends ApiKey { key?: string; }

export default function ApiKeys() {
  const qc = useQueryClient();
  const [name, setName] = useState('');
  const [newKey, setNewKey] = useState<CreatedKey | null>(null);

  const { data: keys = [] } = useQuery<ApiKey[]>({ queryKey: ['apikeys'], queryFn: () => apiKeysApi.list() as Promise<ApiKey[]> });

  const create = useMutation({
    mutationFn: () => apiKeysApi.create({ name }),
    onSuccess: (data) => { qc.invalidateQueries({ queryKey: ['apikeys'] }); setNewKey(data as CreatedKey); setName(''); },
  });

  const revoke = useMutation({
    mutationFn: (id: string) => apiKeysApi.revoke(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['apikeys'] }),
  });

  return (
    <div className="space-y-5 max-w-3xl">
      <h1 className="text-2xl font-bold text-white">API Keys</h1>

      {newKey?.key && (
        <div className="bg-green-900/30 border border-green-700 rounded-xl p-4">
          <p className="text-green-400 text-sm font-medium mb-2">✓ Key created — copy it now, it won't be shown again</p>
          <code className="text-green-300 text-xs break-all font-mono">{newKey.key}</code>
          <button onClick={() => setNewKey(null)} className="ml-4 text-xs text-green-500 hover:text-green-400">Dismiss</button>
        </div>
      )}

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h2 className="text-sm font-medium text-gray-300 mb-3">Create API Key</h2>
        <div className="flex gap-3">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Key name (e.g. production-agent)" className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm" />
          <button onClick={() => create.mutate()} disabled={!name} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-500 disabled:opacity-50">Create</button>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-800/50 text-xs text-gray-400">
            <tr>
              <th className="text-left px-4 py-3">Name</th>
              <th className="text-left px-4 py-3">Prefix</th>
              <th className="text-left px-4 py-3">Scopes</th>
              <th className="text-left px-4 py-3">Last Used</th>
              <th className="text-left px-4 py-3">Status</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <tr key={k.id} className="border-t border-gray-800">
                <td className="px-4 py-3 text-white">{k.name}</td>
                <td className="px-4 py-3 text-gray-400 font-mono text-xs">{k.key_prefix}…</td>
                <td className="px-4 py-3 text-gray-400 text-xs">{(k.scopes ?? []).join(', ')}</td>
                <td className="px-4 py-3 text-gray-400 text-xs">{k.last_used_at ? formatDistanceToNow(new Date(k.last_used_at), { addSuffix: true }) : 'Never'}</td>
                <td className="px-4 py-3"><span className={`text-xs px-2 py-0.5 rounded-full ${k.is_active ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>{k.is_active ? 'active' : 'revoked'}</span></td>
                <td className="px-4 py-3 text-right">
                  {k.is_active && <button onClick={() => revoke.mutate(k.id)} className="text-xs text-red-400 hover:text-red-300">Revoke</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
