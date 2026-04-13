// API client for AgentShield server

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const API_KEY = import.meta.env.VITE_API_KEY || 'admin-secret-change-me';

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
      ...options.headers,
    },
  });
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`API error ${response.status}: ${error}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}

// Sessions
export const sessionsApi = {
  list: (params?: { status?: string; limit?: number; offset?: number }) => {
    const qs = new URLSearchParams();
    if (params?.status) qs.set('status', params.status);
    if (params?.limit) qs.set('limit', String(params.limit));
    if (params?.offset) qs.set('offset', String(params.offset));
    return request(`/api/sessions/?${qs}`);
  },
  get: (id: string) => request(`/api/sessions/${id}`),
  getEvents: (id: string, limit = 100) => request(`/api/sessions/${id}/events?limit=${limit}`),
  kill: (id: string) => request(`/api/sessions/${id}/kill`, { method: 'POST' }),
};

// Alerts
export const alertsApi = {
  list: (params?: { severity?: string; status?: string; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.status) qs.set('status', params.status);
    if (params?.limit) qs.set('limit', String(params.limit));
    return request(`/api/alerts/?${qs}`);
  },
  get: (id: string) => request(`/api/alerts/${id}`),
  stats: () => request('/api/alerts/stats'),
  acknowledge: (id: string, by = 'user') =>
    request(`/api/alerts/${id}/acknowledge`, {
      method: 'POST',
      body: JSON.stringify({ acknowledged_by: by }),
    }),
  resolve: (id: string, by = 'user') =>
    request(`/api/alerts/${id}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ resolved_by: by }),
    }),
  markFalsePositive: (id: string) =>
    request(`/api/alerts/${id}/false-positive`, { method: 'POST' }),
};

// Policies
export const policiesApi = {
  list: () => request('/api/policies/'),
  get: (id: string) => request(`/api/policies/${id}`),
  create: (data: Record<string, unknown>) =>
    request('/api/policies/', { method: 'POST', body: JSON.stringify(data) }),
  update: (id: string, data: Record<string, unknown>) =>
    request(`/api/policies/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  delete: (id: string) => request(`/api/policies/${id}`, { method: 'DELETE' }),
};

// Analytics
export const analyticsApi = {
  overview: () => request('/api/analytics/overview'),
  eventsOverTime: (hours = 24) => request(`/api/analytics/events-over-time?hours=${hours}`),
  threatDistribution: () => request('/api/analytics/threat-distribution'),
  topAgents: (limit = 10) => request(`/api/analytics/top-agents?limit=${limit}`),
  alertTrends: (days = 7) => request(`/api/analytics/alert-trends?days=${days}`),
};

// Organizations
export const orgsApi = {
  list: () => request('/api/organizations/'),
  create: (data: { name: string; slug?: string }) =>
    request('/api/organizations/', { method: 'POST', body: JSON.stringify(data) }),
  get: (id: string) => request(`/api/organizations/${id}`),
};

// API Keys
export const apiKeysApi = {
  list: () => request('/api/apikeys/'),
  create: (data: { name: string; scopes?: string[] }) =>
    request('/api/apikeys/', { method: 'POST', body: JSON.stringify(data) }),
  revoke: (id: string) => request(`/api/apikeys/${id}`, { method: 'DELETE' }),
};

// Replay
export const replayApi = {
  get: (sessionId: string) => request(`/api/replay/${sessionId}`),
};
