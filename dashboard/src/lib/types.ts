// TypeScript types for AgentShield Dashboard

export type Severity = 'info' | 'warning' | 'high' | 'critical';
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive';
export type SessionStatus = 'active' | 'completed' | 'blocked' | 'error' | 'killed';
export type PolicyAction = 'BLOCK' | 'ALERT' | 'LOG' | 'RATE_LIMIT';

export interface AgentSession {
  id: string;
  agent_name: string;
  status: SessionStatus;
  started_at: string;
  ended_at: string | null;
  environment: string;
  framework: string;
  total_events: number;
  total_llm_calls: number;
  total_tool_calls: number;
  max_threat_score: number;
  violation_count: number;
  risk_score: number;
}

export interface Event {
  id: string;
  session_id: string;
  event_type: string;
  agent_name: string;
  timestamp: number;
  data: Record<string, unknown>;
  threat_score: number;
  threat_reasons: string[];
  blocked: boolean;
  latency_ms: number | null;
}

export interface Alert {
  id: string;
  session_id: string | null;
  title: string;
  description: string;
  severity: Severity;
  alert_type: string;
  status: AlertStatus;
  threat_score: number;
  created_at: string;
  updated_at: string;
  context: Record<string, unknown>;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  action: PolicyAction;
  severity: Severity;
  condition: PolicyCondition;
  is_enabled: boolean;
  is_builtin: boolean;
  trigger_count: number;
  created_at: string;
  updated_at: string;
  last_triggered_at: string | null;
}

export interface PolicyCondition {
  type: string;
  threshold?: number;
  threshold_bytes?: number;
  event_types?: string[];
  max_calls?: number;
  window_seconds?: number;
  conditions?: PolicyCondition[];
  [key: string]: unknown;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  is_active: boolean;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  created_at: string;
  is_active: boolean;
}

export interface OverviewStats {
  total_sessions: number;
  active_sessions: number;
  total_events: number;
  total_alerts: number;
  open_alerts: number;
  critical_alerts: number;
  blocked_events: number;
}

export interface EventsBucket {
  time: string;
  events: number;
  threats: number;
  blocked: number;
}

export interface ThreatDistribution {
  type: string;
  count: number;
}

export interface TopAgent {
  agent_name: string;
  session_count: number;
  avg_threat_score: number;
  total_violations: number;
}

export interface ReplayEvent {
  event_id: string;
  event_type: string;
  agent_name: string;
  timestamp: number;
  relative_time_ms: number;
  data: Record<string, unknown>;
  threat_score: number;
  threat_reasons: string[];
  blocked: boolean;
  latency_ms: number | null;
}

export interface SessionReplay {
  session_id: string;
  agent_name: string;
  status: SessionStatus;
  start_time: number;
  end_time: number;
  duration_ms: number;
  total_events: number;
  total_llm_calls: number;
  total_tool_calls: number;
  max_threat_score: number;
  had_violations: boolean;
  events: ReplayEvent[];
}

export interface WebSocketEvent {
  type: 'event' | 'kill_switch' | 'keepalive';
  event_id?: string;
  session_id?: string;
  event_type?: string;
  agent_name?: string;
  timestamp?: number;
  threat_score?: number;
  blocked?: boolean;
}
