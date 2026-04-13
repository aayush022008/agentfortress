import { clsx } from 'clsx';
import type { Alert } from '../../lib/types';
import { formatDistanceToNow } from 'date-fns';

interface AlertCardProps {
  alert: Alert;
  onClick?: () => void;
  onAcknowledge?: () => void;
  onResolve?: () => void;
}

const severityStyles: Record<string, string> = {
  critical: 'border-l-red-500 bg-red-500/5',
  high: 'border-l-orange-500 bg-orange-500/5',
  warning: 'border-l-yellow-500 bg-yellow-500/5',
  info: 'border-l-blue-500 bg-blue-500/5',
};

const severityBadge: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  warning: 'bg-yellow-500/20 text-yellow-400',
  info: 'bg-blue-500/20 text-blue-400',
};

export default function AlertCard({ alert, onClick, onAcknowledge, onResolve }: AlertCardProps) {
  return (
    <div
      className={clsx(
        'border border-gray-800 border-l-4 rounded-lg p-4 cursor-pointer hover:bg-gray-800/50 transition-colors',
        severityStyles[alert.severity] ?? severityStyles.info,
      )}
      onClick={onClick}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={clsx('text-xs font-medium px-2 py-0.5 rounded-full uppercase', severityBadge[alert.severity])}>
              {alert.severity}
            </span>
            <span className="text-xs text-gray-500">{alert.alert_type.replace(/_/g, ' ')}</span>
          </div>
          <h3 className="text-sm font-medium text-white truncate">{alert.title}</h3>
          {alert.description && (
            <p className="text-xs text-gray-400 mt-1 truncate">{alert.description}</p>
          )}
        </div>
        <div className="text-right shrink-0">
          <div className="text-lg font-bold text-white">{alert.threat_score}</div>
          <div className="text-xs text-gray-500">score</div>
        </div>
      </div>
      <div className="flex items-center justify-between mt-3">
        <span className="text-xs text-gray-500">
          {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
        </span>
        {alert.status === 'open' && (
          <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
            <button
              onClick={onAcknowledge}
              className="text-xs px-2 py-1 rounded bg-gray-700 text-gray-300 hover:bg-gray-600"
            >
              Ack
            </button>
            <button
              onClick={onResolve}
              className="text-xs px-2 py-1 rounded bg-green-700/50 text-green-300 hover:bg-green-700"
            >
              Resolve
            </button>
          </div>
        )}
        {alert.status !== 'open' && (
          <span className="text-xs text-gray-500 capitalize">{alert.status}</span>
        )}
      </div>
    </div>
  );
}
