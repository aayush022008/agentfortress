# AgentFortress Quick Start Guide

Get AgentFortress running in under 5 minutes.

## Installation

```bash
pip install agentfortress
```

## Zero-Config Protection (Local Mode)

No server needed. Just wrap your agent:

```python
import agentfortress

# Initialize in local mode (no server required)
shield = agentfortress.init()

# Scan any input before passing to your agent
result = shield.scan(user_input)
if result.action == "block":
    return "Request blocked: potential security threat detected"

# Your agent runs normally
response = your_agent.run(user_input)
```

## LangChain Integration

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from agentfortress.wrappers.langchain import LangChainShield

# Create your agent normally
llm = ChatOpenAI(model="gpt-4")
agent_executor = AgentExecutor(agent=agent, tools=tools)

# Wrap with AgentFortress
shield = LangChainShield(agent_executor, shield_config={
    "block_prompt_injection": True,
    "block_pii_leakage": True,
    "alert_on_scope_creep": True,
})

# Use exactly as before — protection is automatic
result = shield.invoke({"input": user_message})
```

## CrewAI Integration

```python
from crewai import Crew, Agent, Task
from agentfortress.wrappers.crewai import CrewAIShield

crew = Crew(agents=[...], tasks=[...])
protected_crew = CrewAIShield(crew)
result = protected_crew.kickoff()
```

## AutoGen Integration

```python
import autogen
from agentfortress.wrappers.autogen import AutoGenShield

assistant = autogen.AssistantAgent(name="assistant", llm_config={...})
shield = AutoGenShield(assistant)
```

## Connect to AgentFortress Server

For the full SOC dashboard, threat hunting, and team features:

```bash
# Start the server
cd infra && docker-compose up -d

# Connect your SDK
shield = agentfortress.init(
    api_key="your-api-key",
    server_url="http://localhost:8000"
)
```

Dashboard: http://localhost:3000
API Docs: http://localhost:8000/docs

## Custom Policies

```python
from agentfortress.policies.engine import PolicyEngine
from agentfortress.policies.rules import PolicyRule, PolicyAction

engine = PolicyEngine()
engine.add_rule(PolicyRule(
    name="block-rm-rf",
    pattern=r"rm\s+-rf",
    action=PolicyAction.BLOCK,
    severity="critical",
    description="Block destructive file operations"
))
```

## Next Steps

- [SDK Reference](sdk-reference.md) — Full API documentation
- [Policy Configuration](policies.md) — Writing custom security rules
- [Threat Model](threat-model.md) — What AgentFortress protects against
- [Deployment Guide](deployment.md) — Production deployment
