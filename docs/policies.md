# Policy Configuration Guide

## Default Policies

AgentShield ships with several built-in policies that are active by default.

## Creating Custom Policies

### Via SDK (PolicyBuilder)

```python
from agentshield.policies.custom import PolicyBuilder

# Block file system access
policy = (
    PolicyBuilder("no-fs-access")
    .named("Block File System Access")
    .when_tool_called("read_file", "write_file", "delete_file", "list_dir")
    .then_block()
    .with_severity("high")
    .build()
)
shield._policy_engine.add_policy(policy)
```

### Via API

```bash
curl -X POST http://localhost:8000/api/policies/ \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block High Threat Prompts",
    "action": "BLOCK",
    "severity": "critical",
    "condition": {
      "type": "threat_score_above",
      "threshold": 70
    }
  }'
```

## Condition Types

### `threat_score_above`
Triggers when the threat score exceeds the threshold.
```json
{"type": "threat_score_above", "threshold": 60}
```

### `output_size_above`
Triggers when output exceeds the byte limit.
```json
{"type": "output_size_above", "threshold_bytes": 50000}
```

### `pii_detected`
Triggers when PII is found in output.
```json
{"type": "pii_detected"}
```

### `rate_limit`
Triggers when call rate exceeds the limit.
```json
{"type": "rate_limit", "max_calls": 20, "window_seconds": 60}
```

### `and` / `or`
Combine conditions with logical operators.
```json
{
  "type": "and",
  "conditions": [
    {"type": "threat_score_above", "threshold": 50},
    {"type": "event_type", "event_types": ["llm_start"]}
  ]
}
```

## Policy Actions

| Action | Behavior |
|--------|----------|
| `BLOCK` | Raises `PolicyBlockException`, stops execution |
| `ALERT` | Creates an alert, logs the event, execution continues |
| `LOG` | Logs the event only, no alert |
| `RATE_LIMIT` | Slows down or blocks based on rate |

## Tool Allowlisting (Scope Enforcement)

```python
config = AgentShieldConfig(
    api_key="key",
    allowed_tools=["search_web", "read_document", "write_summary"],
    # Any other tool call will be BLOCKED
)
```
