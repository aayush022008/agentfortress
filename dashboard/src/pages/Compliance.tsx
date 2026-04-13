import React, { useEffect, useState } from 'react';

interface ComplianceFramework {
  id: string;
  name: string;
  compliant: boolean;
  score: number;
  findings: number;
  lastChecked?: string;
}

const FRAMEWORK_COLORS: Record<string, string> = {
  gdpr: '#3b82f6',
  hipaa: '#10b981',
  soc2: '#8b5cf6',
  eu_ai_act: '#f59e0b',
};

const Compliance: React.FC = () => {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [running, setRunning] = useState<boolean>(false);

  useEffect(() => {
    fetchStatus();
  }, []);

  const fetchStatus = async (): Promise<void> => {
    try {
      const response = await fetch('/api/compliance/status');
      const data = await response.json();
      const fws = Object.entries(data.frameworks || {}).map(([id, info]: [string, unknown]) => {
        const fw = info as { compliant: boolean; score: number; findings: number };
        return { id, name: id.toUpperCase().replace('_', ' '), ...fw };
      });
      setFrameworks(fws);
    } catch {
      // Show empty state
    } finally {
      setLoading(false);
    }
  };

  const runChecks = async (): Promise<void> => {
    setRunning(true);
    try {
      await fetch('/api/compliance/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ frameworks: ['gdpr', 'hipaa', 'soc2', 'eu_ai_act'] }),
      });
      await fetchStatus();
    } finally {
      setRunning(false);
    }
  };

  const ScoreGauge: React.FC<{ score: number; color: string }> = ({ score, color }) => (
    <div style={{ position: 'relative', width: 80, height: 80 }}>
      <svg width={80} height={80} viewBox="0 0 80 80">
        <circle cx={40} cy={40} r={32} fill="none" stroke="#374151" strokeWidth={8} />
        <circle
          cx={40} cy={40} r={32} fill="none"
          stroke={score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444'}
          strokeWidth={8}
          strokeDasharray={`${(score / 100) * 201} 201`}
          strokeLinecap="round"
          transform="rotate(-90 40 40)"
        />
      </svg>
      <div style={{
        position: 'absolute', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        fontSize: 14, fontWeight: 700, color: '#f9fafb',
      }}>
        {score.toFixed(0)}%
      </div>
    </div>
  );

  if (loading) return <div style={{ padding: 24, color: '#9ca3af' }}>Loading compliance status...</div>;

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700 }}>Compliance</h1>
          <p style={{ color: '#6b7280' }}>Track compliance across GDPR, HIPAA, SOC 2, and EU AI Act</p>
        </div>
        <button
          onClick={runChecks}
          disabled={running}
          style={{
            background: '#3b82f6', color: 'white', border: 'none',
            borderRadius: 6, padding: '10px 20px', cursor: 'pointer', fontWeight: 600,
          }}
        >
          {running ? '⟳ Running...' : '▶ Run Checks'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16 }}>
        {frameworks.map(fw => (
          <div
            key={fw.id}
            style={{
              background: '#1f2937', borderRadius: 12, padding: 20,
              border: `1px solid ${fw.compliant ? '#065f46' : '#7f1d1d'}`,
              cursor: 'pointer',
            }}
            onClick={() => window.location.href = `/compliance/${fw.id}`}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div>
                <div style={{
                  display: 'inline-block', background: FRAMEWORK_COLORS[fw.id] || '#6b7280',
                  color: 'white', borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 700, marginBottom: 8,
                }}>
                  {fw.name}
                </div>
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  color: fw.compliant ? '#10b981' : '#ef4444', fontSize: 14,
                }}>
                  {fw.compliant ? '✓ Compliant' : '✗ Non-Compliant'}
                </div>
              </div>
              <ScoreGauge score={fw.score} color={FRAMEWORK_COLORS[fw.id] || '#6b7280'} />
            </div>
            <div style={{ color: '#9ca3af', fontSize: 13 }}>
              {fw.findings} finding{fw.findings !== 1 ? 's' : ''}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Compliance;
