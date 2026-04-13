import { clsx } from 'clsx';
import type { ReplayEvent } from '../../lib/types';

interface SessionTimelineProps {
  events: ReplayEvent[];
  duration_ms: number;
  currentTimeMs?: number;
  onSeek?: (timeMs: number) => void;
}

const eventColors: Record<string, string> = {
  llm_start: 'bg-blue-500',
  llm_end: 'bg-cyan-500',
  tool_start: 'bg-purple-500',
  tool_end: 'bg-violet-400',
  agent_start: 'bg-green-500',
  agent_end: 'bg-green-400',
  kill_switch: 'bg-red-600',
  policy_violation: 'bg-red-500',
};

export default function SessionTimeline({ events, duration_ms, currentTimeMs = 0, onSeek }: SessionTimelineProps) {
  const totalMs = Math.max(duration_ms, 1);

  return (
    <div className="space-y-3">
      {/* Seek bar */}
      <div
        className="relative h-8 bg-gray-800 rounded cursor-pointer overflow-hidden"
        onClick={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const pct = (e.clientX - rect.left) / rect.width;
          onSeek?.(pct * totalMs);
        }}
      >
        {/* Playhead */}
        <div
          className="absolute top-0 bottom-0 w-0.5 bg-white z-10"
          style={{ left: `${(currentTimeMs / totalMs) * 100}%` }}
        />
        {/* Events as markers */}
        {events.map((event) => {
          const left = (event.relative_time_ms / totalMs) * 100;
          const color = event.blocked ? 'bg-red-500' : (eventColors[event.event_type] ?? 'bg-gray-500');
          return (
            <div
              key={event.event_id}
              className={clsx('absolute top-1 bottom-1 w-1 rounded-sm', color)}
              style={{ left: `${left}%` }}
              title={`${event.event_type} @ ${event.relative_time_ms.toFixed(0)}ms (score: ${event.threat_score})`}
            />
          );
        })}
      </div>

      {/* Event list */}
      <div className="space-y-1 max-h-96 overflow-y-auto">
        {events.map((event) => (
          <div
            key={event.event_id}
            className={clsx(
              'flex items-start gap-3 px-3 py-2 rounded text-sm',
              event.blocked ? 'bg-red-500/10 border border-red-500/20' : 'bg-gray-800/50',
              currentTimeMs >= event.relative_time_ms ? 'opacity-100' : 'opacity-40',
            )}
          >
            <div className={clsx('mt-1 w-2 h-2 rounded-full shrink-0', eventColors[event.event_type] ?? 'bg-gray-500')} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-gray-500">{event.relative_time_ms.toFixed(0)}ms</span>
                <span className="text-xs text-gray-300">{event.event_type}</span>
                {event.blocked && (
                  <span className="text-xs bg-red-500/20 text-red-400 px-1 rounded">BLOCKED</span>
                )}
                {event.threat_score > 0 && (
                  <span className={clsx('text-xs px-1 rounded', event.threat_score >= 75 ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400')}>
                    {event.threat_score}
                  </span>
                )}
              </div>
              {event.threat_reasons.length > 0 && (
                <p className="text-xs text-red-400 mt-0.5 truncate">{event.threat_reasons[0]}</p>
              )}
            </div>
            {event.latency_ms != null && (
              <span className="text-xs text-gray-500 shrink-0">{event.latency_ms.toFixed(0)}ms</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
