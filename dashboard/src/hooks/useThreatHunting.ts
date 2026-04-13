import { useState, useCallback } from 'react';

interface Hunt {
  hunt_id: string;
  name: string;
  query: string;
  description?: string;
  schedule?: string;
  run_count: number;
  last_run_at?: number;
}

interface HuntResult {
  result_id: string;
  hunt_id: string;
  total_matches: number;
  matches: Record<string, unknown>[];
  execution_time_ms: number;
  ran_at: number;
}

interface UseThreatHuntingReturn {
  hunts: Hunt[];
  loading: boolean;
  runningHuntId: string | null;
  lastResult: HuntResult | null;
  error: string | null;
  loadHunts: () => Promise<void>;
  runHunt: (huntId: string) => Promise<void>;
  runQuery: (query: string) => Promise<HuntResult>;
  saveHunt: (name: string, query: string, schedule?: string) => Promise<Hunt>;
  deleteHunt: (huntId: string) => Promise<void>;
}

export const useThreatHunting = (): UseThreatHuntingReturn => {
  const [hunts, setHunts] = useState<Hunt[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [runningHuntId, setRunningHuntId] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<HuntResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadHunts = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      const res = await fetch('/api/threat-hunting/hunts');
      const data = await res.json();
      setHunts(data.hunts || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load hunts');
    } finally {
      setLoading(false);
    }
  }, []);

  const runHunt = useCallback(async (huntId: string): Promise<void> => {
    setRunningHuntId(huntId);
    try {
      const res = await fetch(`/api/threat-hunting/hunts/${huntId}/run`, { method: 'POST' });
      const data = await res.json();
      // Poll for result
      const resultRes = await fetch(`/api/threat-hunting/results/${data.result_id}`);
      const result: HuntResult = await resultRes.json();
      setLastResult(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Hunt failed');
    } finally {
      setRunningHuntId(null);
    }
  }, []);

  const runQuery = useCallback(async (query: string): Promise<HuntResult> => {
    const res = await fetch('/api/threat-hunting/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query }),
    });
    const data: HuntResult = await res.json();
    setLastResult(data);
    return data;
  }, []);

  const saveHunt = useCallback(async (name: string, query: string, schedule?: string): Promise<Hunt> => {
    const res = await fetch('/api/threat-hunting/hunts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, query, schedule }),
    });
    const hunt: Hunt = await res.json();
    setHunts(prev => [...prev, hunt]);
    return hunt;
  }, []);

  const deleteHunt = useCallback(async (huntId: string): Promise<void> => {
    await fetch(`/api/threat-hunting/hunts/${huntId}`, { method: 'DELETE' });
    setHunts(prev => prev.filter(h => h.hunt_id !== huntId));
  }, []);

  return { hunts, loading, runningHuntId, lastResult, error, loadHunts, runHunt, runQuery, saveHunt, deleteHunt };
};
