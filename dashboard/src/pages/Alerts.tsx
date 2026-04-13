import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAlerts, useAcknowledgeAlert, useResolveAlert } from '../hooks/useAlerts';
import AlertCard from '../components/alerts/AlertCard';
import type { Severity } from '../lib/types';

const SEVERITIES: Severity[] = ['critical', 'high', 'warning', 'info'];

export default function Alerts() {
  const navigate = useNavigate();
  const [severity, setSeverity] = useState<string>('');
  const [status, setStatus] = useState('open');

  const { data: alerts = [], isLoading } = useAlerts({ severity: severity || undefined, status });
  const ack = useAcknowledgeAlert();
  const resolve = useResolveAlert();

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Alerts</h1>
          <p className="text-gray-400 text-sm mt-1">{alerts.length} alerts</p>
        </div>
        <div className="flex gap-2">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200"
          >
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200"
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="text-gray-500">Loading…</div>
      ) : alerts.length === 0 ? (
        <div className="text-center py-16 text-gray-500">No alerts found</div>
      ) : (
        <div className="space-y-3">
          {alerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              onClick={() => navigate(`/alerts/${alert.id}`)}
              onAcknowledge={() => ack.mutate({ id: alert.id })}
              onResolve={() => resolve.mutate({ id: alert.id })}
            />
          ))}
        </div>
      )}
    </div>
  );
}
