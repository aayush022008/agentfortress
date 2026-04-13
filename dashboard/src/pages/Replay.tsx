import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { replayApi } from '../lib/api';
import type { SessionReplay } from '../lib/types';
import SessionTimeline from '../components/sessions/SessionTimeline';

export default function Replay() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();
  const [currentTimeMs, setCurrentTimeMs] = useState(0);

  const { data: replay, isLoading } = useQuery<SessionReplay>({
    queryKey: ['replay', sessionId],
    queryFn: () => replayApi.get(sessionId!) as Promise<SessionReplay>,
    enabled: !!sessionId,
  });

  if (isLoading) return <div className="text-gray-500">Loading replay…</div>;
  if (!replay) return <div className="text-gray-500">Session not found</div>;

  // Filter events up to current time
  const visibleEvents = replay.events.filter(e => e.relative_time_ms <= currentTimeMs);
  const currentEvent = visibleEvents[visibleEvents.length - 1];

  return (
    <div className="space-y-5">
      <div>
        <button onClick={() => navigate(`/sessions/${sessionId}`)} className="text-sm text-gray-500 hover:text-gray-300 mb-2">← Session</button>
        <h1 className="text-2xl font-bold text-white">Session Replay</h1>
        <p className="text-gray-400 text-sm">{replay.agent_name} — {replay.total_events} events over {replay.duration_ms.toFixed(0)}ms</p>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-4">
        <button onClick={() => setCurrentTimeMs(0)} className="px-3 py-1.5 bg-gray-700 rounded text-sm text-gray-200 hover:bg-gray-600">⏮ Reset</button>
        <button onClick={() => setCurrentTimeMs(replay.duration_ms)} className="px-3 py-1.5 bg-blue-600 rounded text-sm text-white hover:bg-blue-500">⏭ End</button>
        <span className="text-sm text-gray-400">{currentTimeMs.toFixed(0)}ms / {replay.duration_ms.toFixed(0)}ms</span>
        {currentEvent && (
          <span className="text-sm text-gray-300">▶ {currentEvent.event_type}</span>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl p-5">
          <SessionTimeline
            events={replay.events}
            duration_ms={replay.duration_ms}
            currentTimeMs={currentTimeMs}
            onSeek={setCurrentTimeMs}
          />
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <h2 className="font-medium text-white text-sm">Summary</h2>
          {[
            { label: 'Status', value: replay.status },
            { label: 'Duration', value: `${replay.duration_ms.toFixed(0)}ms` },
            { label: 'Total Events', value: replay.total_events },
            { label: 'LLM Calls', value: replay.total_llm_calls },
            { label: 'Tool Calls', value: replay.total_tool_calls },
            { label: 'Max Threat', value: replay.max_threat_score },
            { label: 'Had Violations', value: replay.had_violations ? '🔴 Yes' : '🟢 No' },
          ].map(({ label, value }) => (
            <div key={label} className="flex justify-between text-sm">
              <span className="text-gray-500">{label}</span>
              <span className="text-white">{value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
