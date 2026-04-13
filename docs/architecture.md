# Architecture Deep Dive

## Component Interactions

```
┌─────────────────────────────────────────────────────────────┐
│                   Your AI Agent                              │
│                                                             │
│  ┌────────────┐    agentshield.protect()    ┌────────────┐ │
│  │   Agent    │ ──────────────────────────► │  Wrapper   │ │
│  │  (any fw)  │                             │            │ │
│  └────────────┘                             └─────┬──────┘ │
│                                                   │         │
│                          ┌─────────────────────────▼──────┐ │
│                          │         Interceptor            │ │
│                          │  - Captures every LLM call     │ │
│                          │  - Captures every tool call    │ │
│                          │  - Analyzes with threat intel  │ │
│                          └────┬───────────┬───────────────┘ │
│                               │           │                  │
│                    ┌──────────▼──┐  ┌─────▼────────┐       │
│                    │Policy Engine│  │Audit Logger  │       │
│                    │ (BLOCK/ALERT│  │(JSONL file)  │       │
│                    │  /LOG/RATE) │  └──────────────┘       │
│                    └──────┬──────┘                          │
└───────────────────────────┼─────────────────────────────────┘
                            │ HTTP (batched)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  AgentShield Server (FastAPI)                │
│                                                             │
│  POST /api/events/batch ──► ThreatDetectionService         │
│                                     │                       │
│                             AlertManager                    │
│                             PolicyEnforcer                  │
│                             AnomalyEngine                   │
│                                     │                       │
│                             ┌───────▼────────┐              │
│                             │   PostgreSQL   │              │
│                             │  (events,      │              │
│                             │   sessions,    │              │
│                             │   alerts,      │              │
│                             │   policies)    │              │
│                             └───────┬────────┘              │
│                                     │ WebSocket             │
└─────────────────────────────────────┼─────────────────────  ┘
                                      │
                            ┌─────────▼──────────┐
                            │  React Dashboard   │
                            │  (SOC UI)          │
                            └────────────────────┘
```

## SDK Design

The SDK follows a layered architecture:

1. **Wrapper Layer** — Framework-specific adapters (LangChain, CrewAI, AutoGen, OpenAI)
2. **Interceptor Layer** — Framework-agnostic event capture and analysis
3. **Policy Layer** — Rules engine with configurable actions
4. **Anomaly Layer** — Statistical and behavioral analysis
5. **Transport Layer** — HTTP (online) or SQLite (offline) event shipping
6. **Audit Layer** — Tamper-evident JSONL audit log

## Event Flow

1. Agent calls `run("task")`
2. Wrapper intercepts the call
3. Interceptor calls `capture_llm_start()` with the prompt
4. Prompt is analyzed against threat intel patterns
5. Policy engine evaluates the threat score
6. If BLOCK: raises `PolicyBlockException`, execution stops
7. If ALERT/LOG: event is dispatched and execution continues
8. Event is sent to transport (HTTP batch or local SQLite)
9. Server-side re-analysis adds additional signals
10. Alerts are created for significant threats
11. WebSocket broadcasts alert to dashboard

## Database Schema

```
organizations (1) ──── (n) api_keys
organizations (1) ──── (n) agent_sessions
organizations (1) ──── (n) policies
organizations (1) ──── (n) alerts

agent_sessions (1) ──── (n) events
agent_sessions (1) ──── (n) alerts
```
