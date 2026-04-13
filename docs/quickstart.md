# Quick Start Guide

Get AgentShield running in 5 minutes.

## 1. Install the SDK

```bash
pip install agentshield-sdk
```

## 2. Start the platform

```bash
# Clone the repo
git clone https://github.com/agentshield/agentshield
cd agentshield/infra

# Start with Docker Compose
docker-compose -f docker-compose.dev.yml up -d
```

This starts:
- **API Server**: http://localhost:8000
- **Dashboard**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs

## 3. Get an API key

```bash
curl -X POST http://localhost:8000/api/apikeys/ \
  -H "X-API-Key: admin-secret-change-me" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-first-key"}'
```

## 4. Protect your first agent

```python
import agentshield

# Initialize (use your API key from step 3)
agentshield.init(
    api_key="as_your_key_here",
    server_url="http://localhost:8000",
)

# Example with a mock agent
class MyAgent:
    def run(self, task: str) -> str:
        return f"Completed: {task}"

agent = MyAgent()
protected = agentshield.protect(agent, "my-agent")

# Run it — AgentShield monitors everything
result = protected.run("Summarize the Q3 earnings report")
print(result)
```

## 5. View the dashboard

Open http://localhost:3000 in your browser. You should see:
- Your agent session in the Sessions view
- Events being captured in real-time
- Any threats detected shown as alerts

## What's monitored by default

| Feature | Default |
|---------|---------|
| Prompt injection detection | ✅ Enabled |
| PII in outputs | ✅ Enabled |
| Data exfiltration | ✅ Enabled |
| Rate limiting | ✅ Enabled (100 LLM/min) |
| Jailbreak detection | ✅ Enabled |
| Audit logging | ✅ Enabled |

## LangChain integration

```python
from langchain.agents import create_openai_tools_agent, AgentExecutor
from agentshield.wrappers.langchain import LangChainWrapper
import agentshield

agentshield.init(api_key="your-key")

# Create your LangChain agent normally
agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)

# Wrap it
protected = agentshield.protect(executor, "langchain-agent")
result = protected.run({"input": "What's the weather?"})
```

## Kill switch

```python
import agentshield
import threading

shield = agentshield.get_instance()
protected_agent = agentshield.protect(agent)

# In another thread, kill the agent
def emergency_stop():
    protected_agent.kill()
    # or: shield.kill(session_id)
```

## Offline mode

If you don't have a server, AgentShield works offline with local logging:

```python
agentshield.init(offline_mode=True)
protected = agentshield.protect(agent)
# Events are stored in agentshield-local.db
```
