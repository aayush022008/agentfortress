import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

const Login: React.FC = () => {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [showMFA, setShowMFA] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await login(email, password);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Login failed';
      if (msg.includes('MFA')) {
        setShowMFA(true);
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#111827' }}>
      <div style={{ background: '#1f2937', borderRadius: 12, padding: 40, width: 400, boxShadow: '0 20px 60px rgba(0,0,0,0.5)' }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontSize: 32, marginBottom: 8 }}>🛡️</div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f9fafb' }}>AgentShield</h1>
          <p style={{ color: '#6b7280', fontSize: 14 }}>AI Security Platform</p>
        </div>
        {error && (
          <div style={{ background: '#450a0a', border: '1px solid #b91c1c', borderRadius: 6, padding: 12, marginBottom: 16, color: '#fca5a5', fontSize: 14 }}>
            {error}
          </div>
        )}
        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', color: '#9ca3af', fontSize: 13, marginBottom: 6 }}>Email</label>
            <input
              type="email" value={email} onChange={e => setEmail(e.target.value)} required
              style={{ width: '100%', background: '#111827', border: '1px solid #374151', borderRadius: 6, padding: '10px 12px', color: '#f9fafb', fontSize: 14 }}
            />
          </div>
          <div style={{ marginBottom: showMFA ? 16 : 24 }}>
            <label style={{ display: 'block', color: '#9ca3af', fontSize: 13, marginBottom: 6 }}>Password</label>
            <input
              type="password" value={password} onChange={e => setPassword(e.target.value)} required
              style={{ width: '100%', background: '#111827', border: '1px solid #374151', borderRadius: 6, padding: '10px 12px', color: '#f9fafb', fontSize: 14 }}
            />
          </div>
          {showMFA && (
            <div style={{ marginBottom: 24 }}>
              <label style={{ display: 'block', color: '#9ca3af', fontSize: 13, marginBottom: 6 }}>Authenticator Code</label>
              <input
                type="text" value={mfaCode} onChange={e => setMfaCode(e.target.value)} maxLength={6} placeholder="000000"
                style={{ width: '100%', background: '#111827', border: '1px solid #374151', borderRadius: 6, padding: '10px 12px', color: '#f9fafb', fontSize: 18, letterSpacing: 8, textAlign: 'center' }}
              />
            </div>
          )}
          <button
            type="submit" disabled={loading}
            style={{ width: '100%', background: '#3b82f6', color: 'white', border: 'none', borderRadius: 8, padding: '12px', fontSize: 15, fontWeight: 600, cursor: 'pointer' }}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        <div style={{ textAlign: 'center', marginTop: 20 }}>
          <a href="/auth/sso" style={{ color: '#3b82f6', fontSize: 13, textDecoration: 'none' }}>Sign in with SSO →</a>
        </div>
      </div>
    </div>
  );
};

export default Login;
