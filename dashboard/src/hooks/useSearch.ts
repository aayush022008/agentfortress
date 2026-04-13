import { useState, useCallback } from 'react';

interface SearchResult {
  id: string;
  type: string;
  score: number;
  fields: Record<string, unknown>;
  highlights: Record<string, string[]>;
}

interface SearchState {
  results: SearchResult[];
  total: number;
  loading: boolean;
  error: string | null;
  query: string;
}

interface UseSearchReturn extends SearchState {
  search: (query: string, options?: SearchOptions) => Promise<void>;
  clear: () => void;
}

interface SearchOptions {
  index?: string;
  limit?: number;
  offset?: number;
  startTime?: number;
  endTime?: number;
}

export const useSearch = (): UseSearchReturn => {
  const [state, setState] = useState<SearchState>({
    results: [],
    total: 0,
    loading: false,
    error: null,
    query: '',
  });

  const search = useCallback(async (query: string, options: SearchOptions = {}): Promise<void> => {
    setState(prev => ({ ...prev, loading: true, error: null, query }));
    try {
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query,
          limit: options.limit || 50,
          offset: options.offset || 0,
          index: options.index || null,
          start_time: options.startTime,
          end_time: options.endTime,
          highlight: true,
        }),
      });
      if (!response.ok) throw new Error(`Search failed: HTTP ${response.status}`);
      const data = await response.json();
      setState(prev => ({
        ...prev,
        results: data.results || [],
        total: data.total || 0,
        loading: false,
      }));
    } catch (err) {
      setState(prev => ({
        ...prev,
        loading: false,
        error: err instanceof Error ? err.message : 'Search failed',
      }));
    }
  }, []);

  const clear = useCallback((): void => {
    setState({ results: [], total: 0, loading: false, error: null, query: '' });
  }, []);

  return { ...state, search, clear };
};
