import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { orgsApi } from '../lib/api';
import type { Organization } from '../lib/types';

export default function Organizations() {
  const qc = useQueryClient();
  const [name, setName] = useState('');
  const { data: orgs = [] } = useQuery<Organization[]>({ queryKey: ['orgs'], queryFn: () => orgsApi.list() as Promise<Organization[]> });
  const create = useMutation({
    mutationFn: () => orgsApi.create({ name }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['orgs'] }); setName(''); },
  });

  return (
    <div className="space-y-5 max-w-2xl">
      <h1 className="text-2xl font-bold text-white">Organizations</h1>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h2 className="text-sm font-medium text-gray-300 mb-3">Create Organization</h2>
        <div className="flex gap-3">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Organization name" className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm" />
          <button onClick={() => create.mutate()} disabled={!name} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-500 disabled:opacity-50">Create</button>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-800/50 text-xs text-gray-400">
            <tr>
              <th className="text-left px-4 py-3">Name</th>
              <th className="text-left px-4 py-3">Slug</th>
              <th className="text-left px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody>
            {orgs.map((o) => (
              <tr key={o.id} className="border-t border-gray-800">
                <td className="px-4 py-3 text-white">{o.name}</td>
                <td className="px-4 py-3 text-gray-400 font-mono text-xs">{o.slug}</td>
                <td className="px-4 py-3"><span className={`text-xs px-2 py-0.5 rounded-full ${o.is_active ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'}`}>{o.is_active ? 'active' : 'inactive'}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
