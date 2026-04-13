import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { policiesApi } from '../lib/api';

export default function PolicyEditor() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [action, setAction] = useState('ALERT');
  const [severity, setSeverity] = useState('medium');
  const [conditionType, setConditionType] = useState('threat_score_above');
  const [threshold, setThreshold] = useState(50);
  const [error, setError] = useState('');

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => policiesApi.create(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['policies'] });
      navigate('/policies');
    },
    onError: (e: Error) => setError(e.message),
  });

  const buildCondition = () => {
    if (conditionType === 'threat_score_above') return { type: 'threat_score_above', threshold };
    if (conditionType === 'output_size_above') return { type: 'output_size_above', threshold_bytes: threshold * 1000 };
    if (conditionType === 'pii_detected') return { type: 'pii_detected' };
    if (conditionType === 'rate_limit') return { type: 'rate_limit', max_calls: threshold, window_seconds: 60 };
    return { type: conditionType };
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name) { setError('Name is required'); return; }
    createMutation.mutate({ name, description, action, severity, condition: buildCondition() });
  };

  return (
    <div className="max-w-lg space-y-5">
      <div>
        <button onClick={() => navigate('/policies')} className="text-sm text-gray-500 hover:text-gray-300 mb-2">← Policies</button>
        <h1 className="text-2xl font-bold text-white">New Policy</h1>
      </div>

      <form onSubmit={handleSubmit} className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
        <div>
          <label className="block text-sm text-gray-300 mb-1">Name *</label>
          <input value={name} onChange={(e) => setName(e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm" placeholder="Policy name" />
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Description</label>
          <input value={description} onChange={(e) => setDescription(e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm" placeholder="What does this policy do?" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm text-gray-300 mb-1">Action</label>
            <select value={action} onChange={(e) => setAction(e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm">
              <option>BLOCK</option>
              <option>ALERT</option>
              <option>LOG</option>
              <option>RATE_LIMIT</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-gray-300 mb-1">Severity</label>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm">
              <option>low</option>
              <option>medium</option>
              <option>high</option>
              <option>critical</option>
            </select>
          </div>
        </div>
        <div>
          <label className="block text-sm text-gray-300 mb-1">Condition Type</label>
          <select value={conditionType} onChange={(e) => setConditionType(e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm">
            <option value="threat_score_above">Threat score above threshold</option>
            <option value="output_size_above">Output size above threshold (KB)</option>
            <option value="pii_detected">PII detected in output</option>
            <option value="rate_limit">Rate limit exceeded</option>
          </select>
        </div>
        {conditionType !== 'pii_detected' && (
          <div>
            <label className="block text-sm text-gray-300 mb-1">
              {conditionType === 'threat_score_above' ? 'Threshold (0-100)' :
               conditionType === 'output_size_above' ? 'Max size (KB)' :
               'Max calls per minute'}
            </label>
            <input
              type="number"
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm"
            />
          </div>
        )}
        {error && <p className="text-sm text-red-400">{error}</p>}
        <div className="flex justify-end gap-3 pt-2">
          <button type="button" onClick={() => navigate('/policies')} className="px-4 py-2 bg-gray-700 text-gray-200 rounded-lg text-sm hover:bg-gray-600">Cancel</button>
          <button type="submit" disabled={createMutation.isPending} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-500 disabled:opacity-50">
            {createMutation.isPending ? 'Creating…' : 'Create Policy'}
          </button>
        </div>
      </form>
    </div>
  );
}
