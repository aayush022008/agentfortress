# AgentShield 🛡️

> The CrowdStrike for AI Agents — Real-time security monitoring, threat detection, and runtime protection for LLM-powered agents.

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Free & Open Source](https://img.shields.io/badge/Free-Open%20Source-brightgreen.svg)
[![PyPI - SDK](https://img.shields.io/pypi/v/agentshield-python?label=agentshield-python)](https://pypi.org/project/agentshield-python/)
[![PyPI - CLI](https://img.shields.io/pypi/v/agentshield-monitor?label=agentshield-monitor)](https://pypi.org/project/agentshield-monitor/)

> 🆓 **100% Free & Open Source** — All features available to everyone. No paid plans, no paywalls, no credit card required. Ever.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                        AGENTSHIELD ARCHITECTURE                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   Your AI Agents                 AgentShield Platform                        ║
║   ──────────────                 ───────────────────                         ║
║                                                                              ║
║  ┌─────────────┐                ┌──────────────────────────────────────┐    ║
║  │  LangChain  │──┐             │           FastAPI Server             │    ║
║  └─────────────┘  │             │                                      │    ║
║  ┌─────────────┐  │  SDK        │  ┌──────────┐  ┌─────────────────┐  │    ║
║  │   CrewAI    │──┼──────────►  │  │ Threat   │  │  Alert Manager  │  │    ║
║  └─────────────┘  │  (events)   │  │Detection │  │                 │  │    ║
║  ┌─────────────┐  │             │  └──────────┘  └─────────────────┘  │    ║
║  │   AutoGen   │──┤             │  ┌──────────┐  ┌─────────────────┐  │    ║
║  └─────────────┘  │             │  │ Policy   │  │  Anomaly Engine │  │    ║
║  ┌─────────────┐  │             │  │Enforcer  │  │                 │  │    ║
║  │  OpenAI SDK │──┘             │  └──────────┘  └─────────────────┘  │    ║
║  └─────────────┘                │                                      │    ║
║                                 │  ┌──────────────────────────────┐   │    ║
║                                 │  │     PostgreSQL / SQLite       │   │    ║
║                                 │  └──────────────────────────────┘   │    ║
║                                 └─────────────────┬────────────────────┘    ║
║                                                   │ WebSocket                ║
║                                                   ▼                          ║
║                                 ┌──────────────────────────────────────┐    ║
║                                 │       React SOC Dashboard            │    ║
║                                 │  • Real-time event feed              │    ║
║                                 │  • Alert management                  │    ║
║                                 │  • Session replay                    │    ║
║                                 │  • Policy editor                     │    ║
║                                 │  • Analytics & trends                │    ║
║                                 └──────────────────────────────────────┘    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## What is AgentShield?

AgentShield provides comprehensive security observability and runtime protection for AI agents. As autonomous AI systems gain access to sensitive tools and data, the attack surface grows dramatically. AgentShield acts as a security layer between your agents and the world.

## Key Features

- **🔍 Universal Agent Monitoring** — Instrument LangChain, CrewAI, AutoGen, OpenAI Agents SDK, or any custom agent with one line of code
- **🚨 Real-time Threat Detection** — Detect prompt injection, PII leakage, data exfiltration, and scope creep as they happen
- **📋 Policy Enforcement** — Define security policies that BLOCK, ALERT, LOG, or RATE_LIMIT suspicious behavior
- **🎬 Session Replay** — Full timeline replay of every agent action for incident investigation
- **📊 SOC Dashboard** — Real-time security operations center with alerts, analytics, and session management
- **🔑 Kill Switch** — Instantly terminate any running agent session
- **🧠 Threat Intelligence** — Built-in library of 200+ known prompt injection, jailbreak, and exfiltration patterns
- **🏢 Multi-tenant** — Organization-based access control with API key management

## Quick Start

### 1. Install the SDK

```bash
pip install agentshield-sdk
```

### 2. Protect your agent

```python
import agentshield

# Zero-config protection
agentshield.init(api_key="your-api-key", server_url="http://localhost:8000")

# Wrap your agent
protected_agent = agentshield.protect(your_agent)

# Run it — AgentShield monitors everything
result = protected_agent.run("Your task here")
```

### 3. Start the platform

```bash
# Using Docker Compose
cd infra && docker-compose up -d

# Dashboard available at http://localhost:3000
# API available at http://localhost:8000
# API docs at http://localhost:8000/docs
```

## Installation

### SDK

```bash
pip install agentshield-sdk
```

### Server (Development)

```bash
cd server
pip install -r requirements.txt
uvicorn main:app --reload
```

### Dashboard

```bash
cd dashboard
npm install
npm run dev
```

### CLI

```bash
pip install agentshield-cli
agentshield init
```

## Architecture

| Component | Technology | Purpose |
|-----------|-----------|---------|
| SDK | Python | Agent instrumentation & local detection |
| Server | FastAPI + SQLAlchemy | Event ingestion, threat analysis, API |
| Dashboard | React + Vite + TailwindCSS | SOC UI, real-time monitoring |
| CLI | Click | Developer tooling |
| Threat Intel | JSON patterns + Python engine | Known attack pattern matching |
| Infra | Docker + Kubernetes | Deployment |

## Detection Capabilities

| Threat | Detection Method | Default Action |
|--------|-----------------|----------------|
| Prompt Injection | Pattern matching + ML scoring | ALERT |
| PII Leakage | Regex + NER patterns | BLOCK |
| Data Exfiltration | Size analysis + base64 detection | BLOCK |
| Jailbreak Attempts | Pattern library matching | ALERT |
| Scope Creep | Resource access monitoring | ALERT |
| Anomalous Behavior | Statistical baseline deviation | ALERT |
| Rapid API Calls | Rate pattern analysis | RATE_LIMIT |

## Documentation

- [Quick Start Guide](docs/quickstart.md)
- [SDK Reference](docs/sdk-reference.md)
- [Server API Reference](docs/server-api.md)
- [Policy Configuration](docs/policies.md)
- [Threat Model](docs/threat-model.md)
- [Deployment Guide](docs/deployment.md)
- [Architecture Deep Dive](docs/architecture.md)

## License

MIT — see [LICENSE](LICENSE)
