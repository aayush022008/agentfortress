# Threat Hunting Guide

## Query Syntax

AgentShield supports SQL-like hunt queries:

```sql
SELECT * FROM events WHERE tool_name = 'bash'
SELECT * FROM alerts WHERE severity = 'critical'
SELECT * FROM events WHERE tool_name LIKE '%http%' AND session_duration > 300
```

## Saved Hunts

```bash
agentshield hunt save "Bash Executions" "SELECT * FROM events WHERE tool_name = 'bash'"
agentshield hunt list
agentshield hunt run <hunt-id>
```

## Scheduled Hunts

Assign a schedule to auto-run hunts:
- `@hourly` — every hour
- `@daily` — every day
- `every_4h` — every 4 hours

## IOC Management

```bash
agentshield intel add-pattern --name "AttackerIP" --pattern "1.2.3.4" --type string --severity high
agentshield intel search "1.2.3.4"
```
