import { useParams, useNavigate } from 'react-router-dom';
import { useAlert, useAcknowledgeAlert, useResolveAlert } from '../hooks/useAlerts';
import { formatDistanceToNow } from 'date-fns';
import { clsx } from 'clsx';

export default function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: alert, isLoading } = useAlert(id!);
  const ack = useAcknowledgeAlert();
  const resolve = useResolveAlert();

  if (isLoading) return <div className="text-gray-500">Loading…</div>;
  if (!alert) return <div className="text-gray-500">Alert not found</div>;

  const severityColor = { critical: 'text-red-400', high: 'text-orange-400', warning: 'text-yellow-400', info: 'text-blue-400' }[alert.severity] ?? 'text-gray-400';

  return (
    <div className="space-y-5 max-w-3xl">
      <div>
        <button onClick={() => navigate('/alerts')} className="text-sm text-gray-500 hover:text-gray-300 mb-2">← Alerts</button>
        <div className="flex items-start justify-between">
          <h1 className="text-xl font-bold text-white">{alert.title}</h1>
          <div className="flex gap-2">
            {alert.status === 'open' && (
              <>
                <button onClick={() => ack.mutate({ id: alert.id })} className="px-3 py-1.5 bg-gray-700 text-gray-200 rounded text-sm hover:bg-gray-600">Acknowledge</button>
                <button onClick={() => resolve.mutate({ id: alert.id })} className="px-3 py-1.5 bg-green-700/50 text-green-300 rounded text-sm hover:bg-green-700">Resolve</button>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {[
          { label: 'Severity', value: <span className={clsx('font-medium capitalize', severityColor)}>{alert.severity}</span> },
          { label: 'Status', value: <span className="capitalize">{alert.status}</span> },
          { label: 'Threat Score', value: <span className={severityColor}>{alert.threat_score}</span> },
          { label: 'Type', value: alert.alert_type.replace(/_/g, ' ') },
          { label: 'Session', value: alert.session_id ? <button onClick={() => navigate(`/sessions/${alert.session_id}`)} className="text-blue-400 hover:underline">{alert.session_id.slice(0, 16)}…</button> : 'N/A' },
          { label: 'Created', value: formatDistanceToNow(new Date(alert.created_at), { addSuffix: true }) },
        ].map(({ label, value }) => (
          <div key={label} className="bg-gray-900 border border-gray-800 rounded-lg p-3">
            <div className="text-xs text-gray-500 mb-1">{label}</div>
            <div className="text-sm text-white">{value}</div>
          </div>
        ))}
      </div>

      {alert.description && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-2">Description</h2>
          <p className="text-sm text-gray-400">{alert.description}</p>
        </div>
      )}

      {Object.keys(alert.context).length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-medium text-gray-300 mb-2">Context</h2>
          <pre className="text-xs text-gray-400 overflow-auto">{JSON.stringify(alert.context, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
