# RBAC Configuration Guide

AgentShield uses Role-Based Access Control (RBAC) to manage platform access.

## Built-in Roles

| Role | Description | Key Permissions |
|------|-------------|-----------------|
| Admin | Full access | `*` |
| Security Analyst | Investigate alerts | `alerts:read`, `sessions:read`, `forensics:read` |
| Threat Hunter | Run threat hunts | `hunt:read`, `hunt:write`, `intel:read` |
| Viewer | Read-only | `alerts:read`, `dashboard:read` |
| API User | Programmatic access | `events:write`, `sessions:read` |

## Custom Roles

```bash
agentshield rbac create-role "DevOps" --permissions "sessions:read,events:read,export:read"
```

## Assigning Roles

```bash
agentshield users assign-role --user alice@corp.com --role analyst
```

## Wildcard Permissions

- `alerts:*` — all alert permissions
- `*` — all permissions (admin only)

## API

```
POST /api/rbac/roles
GET  /api/rbac/roles
POST /api/rbac/assignments
POST /api/rbac/check
```
