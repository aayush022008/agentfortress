import React, { useState } from 'react';

interface QueryResult {
  id: string;
  [key: string]: unknown;
}

interface HuntQueryResult {
  results: QueryResult[];
  total: number;
  execution_time_ms: number;
}

const ThreatHunting: React.FC = () => {
  const [query, setQuery] = useState<string>('SELECT * FROM events WHERE tool_name = \'bash\'');
  const [results, setResults] = useState<HuntQueryResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [savedHunts, setSavedHunts] = useState<Array<{ hunt_id: string; name: string; query: string }>>([]);

  const runQuery = async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/threat-hunting/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data: HuntQueryResult = await response.json();
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Query failed');
    } finally {
      setLoading(false);
    }
  };

  const saveHunt = async (): Promise<void> => {
    const name = window.prompt('Hunt name:');
    if (!name) return;
    try {
      const response = await fetch('/api/threat-hunting/hunts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, query }),
      });
      const data = await response.json();
      setSavedHunts(prev => [...prev, data]);
    } catch (err) {
      setError('Failed to save hunt');
    }
  };

  const exampleQueries = [
    "SELECT * FROM events WHERE tool_name = 'bash' AND session_duration > 300",
    "SELECT * FROM alerts WHERE severity = 'critical'",
    "SELECT * FROM events WHERE tool_name LIKE '%http%'",
    "SELECT * FROM sessions WHERE events_count > 50",
  ];

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Threat Hunting</h1>
      <p style={{ color: '#6b7280', marginBottom: 24 }}>
        Run SQL-like queries across events, alerts, and sessions to hunt for threats.
      </p>

      {/* Query Builder */}
      <div style={{ background: '#1f2937', borderRadius: 8, padding: 16, marginBottom: 16 }}>
        <div style={{ marginBottom: 8, color: '#9ca3af', fontSize: 12 }}>HUNT QUERY</div>
        <textarea
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{
            width: '100%', minHeight: 100, background: '#111827', color: '#f9fafb',
            border: '1px solid #374151', borderRadius: 4, padding: 12,
            fontFamily: 'monospace', fontSize: 14, resize: 'vertical',
          }}
          placeholder="SELECT * FROM events WHERE ..."
        />
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <button
            onClick={runQuery}
            disabled={loading}
            style={{
              background: '#3b82f6', color: 'white', border: 'none',
              borderRadius: 6, padding: '8px 20px', cursor: 'pointer',
              fontWeight: 600, opacity: loading ? 0.7 : 1,
            }}
          >
            {loading ? '▶ Running...' : '▶ Run Hunt'}
          </button>
          <button
            onClick={saveHunt}
            style={{
              background: '#374151', color: 'white', border: 'none',
              borderRadius: 6, padding: '8px 16px', cursor: 'pointer',
            }}
          >
            💾 Save Hunt
          </button>
        </div>
      </div>

      {/* Example Queries */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 12, color: '#6b7280', marginBottom: 8 }}>EXAMPLE QUERIES</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {exampleQueries.map((q, i) => (
            <button
              key={i}
              onClick={() => setQuery(q)}
              style={{
                background: '#1f2937', color: '#93c5fd', border: '1px solid #374151',
                borderRadius: 20, padding: '4px 12px', cursor: 'pointer', fontSize: 12,
              }}
            >
              {q.slice(0, 50)}...
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{ background: '#450a0a', border: '1px solid #b91c1c', borderRadius: 6, padding: 12, marginBottom: 16, color: '#fca5a5' }}>
          ⚠ {error}
        </div>
      )}

      {/* Results */}
      {results && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ color: '#9ca3af' }}>
              {results.total} results ({results.execution_time_ms}ms)
            </span>
          </div>
          {results.results.length === 0 ? (
            <div style={{ textAlign: 'center', color: '#6b7280', padding: 48 }}>
              No results found
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ background: '#1f2937', borderBottom: '1px solid #374151' }}>
                    {Object.keys(results.results[0]).map(k => (
                      <th key={k} style={{ padding: '10px 12px', textAlign: 'left', color: '#9ca3af', fontWeight: 600 }}>
                        {k}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {results.results.map((row, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid #1f2937', color: '#f3f4f6' }}>
                      {Object.values(row).map((v, j) => (
                        <td key={j} style={{ padding: '8px 12px', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {String(v)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ThreatHunting;
