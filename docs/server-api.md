# AgentShield Server API Reference

Base URL: `http://localhost:8000`
Authentication: `X-API-Key: your-api-key`

## Events

### POST /api/events/batch
Ingest a batch of events from the SDK.

**Request:**
```json
{
  "events": [
    {
      "event_id": "uuid",
      "session_id": "session-uuid",
      "event_type": "llm_start",
      "agent_name": "my-agent",
      "timestamp": 1704067200.0,
      "data": {"prompt": "..."},
      "threat_score": 0,
      "threat_reasons": [],
      "blocked": false
    }
  ]
}
```

**Response:** `{"processed": 1}`

## Sessions

### GET /api/sessions/
List sessions. Query params: `status`, `limit`, `offset`

### GET /api/sessions/{id}
Get session details.

### GET /api/sessions/{id}/events
Get all events for a session.

### POST /api/sessions/{id}/kill
Activate kill switch for a session.

## Alerts

### GET /api/alerts/
List alerts. Query params: `severity`, `status`, `alert_type`, `session_id`

### POST /api/alerts/{id}/acknowledge
Acknowledge an alert.

### POST /api/alerts/{id}/resolve
Resolve an alert.

### POST /api/alerts/{id}/false-positive
Mark alert as false positive.

## Policies

### GET /api/policies/
List all policies.

### POST /api/policies/
Create a policy.

### PATCH /api/policies/{id}
Update a policy (can enable/disable built-ins).

### DELETE /api/policies/{id}
Delete a custom policy.

## Analytics

### GET /api/analytics/overview
Returns: `{total_sessions, active_sessions, total_events, open_alerts, critical_alerts, blocked_events}`

### GET /api/analytics/events-over-time?hours=24
Returns hourly event buckets.

### GET /api/analytics/threat-distribution
Returns threat type distribution.

### GET /api/analytics/top-agents?limit=10
Returns top agents by risk score.

## Replay

### GET /api/replay/{session_id}
Returns full session replay with all events and computed statistics.

## WebSocket

### WS /ws/events
Real-time event stream. Connect to receive live events as they are ingested.

Messages:
```json
{"type": "event", "event_id": "...", "session_id": "...", "threat_score": 0}
{"type": "kill_switch", "session_id": "..."}
{"type": "keepalive"}
```

Send `ping` to receive `pong`.
