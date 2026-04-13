# SDK API Reference

## Initialization

### `agentshield.init()`

Initialize the global AgentShield instance.

```python
agentshield.init(
    api_key: str = "",
    server_url: str = "http://localhost:8000",
    org_id: str = "",
    environment: str = "development",
    offline_mode: bool = False,
    enable_blocking: bool = True,
    enable_pii_detection: bool = True,
    enable_prompt_injection: bool = True,
    enable_anomaly_detection: bool = True,
    allowed_tools: list[str] = [],
    max_output_bytes: int = 100_000,
    audit_log_path: str = "agentshield-audit.log",
)
```

### `agentshield.protect(agent, agent_name=None)`

Wrap an agent with AgentShield protection. Auto-detects the framework.

```python
protected = agentshield.protect(agent)
protected = agentshield.protect(agent, agent_name="my-research-agent")
```

## AgentShield Class

### `AgentShield(config: AgentShieldConfig)`

Create an AgentShield instance with custom config.

```python
from agentshield.core import AgentShield, AgentShieldConfig

config = AgentShieldConfig(
    api_key="key",
    server_url="http://localhost:8000",
    allowed_tools=["search", "read_file", "write_file"],
)
shield = AgentShield(config)
protected = shield.protect(agent)
```

### Methods

- `protect(agent, agent_name=None)` — Wrap an agent
- `kill(session_id=None)` — Activate kill switch
- `get_session_id()` — Get current session ID
- `flush()` — Flush pending events
- `shutdown()` — Graceful shutdown

## Policy Management

### Built-in Policies

| Policy ID | Description | Default Action |
|-----------|-------------|----------------|
| `builtin-prompt-injection-block` | Block prompt injection (score ≥ 75) | BLOCK |
| `builtin-prompt-injection-alert` | Alert on injection (score ≥ 40) | ALERT |
| `builtin-pii-block` | Block PII leakage (score ≥ 70) | BLOCK |
| `builtin-pii-alert` | Alert on PII (score ≥ 40) | ALERT |
| `builtin-data-exfil-size` | Block oversized outputs | BLOCK |
| `builtin-rate-limit-llm` | Rate limit LLM calls | RATE_LIMIT |
| `builtin-rate-limit-tools` | Rate limit tool calls | RATE_LIMIT |
| `builtin-scope-creep` | Block out-of-scope tools | BLOCK |

### Custom Policies with PolicyBuilder

```python
from agentshield.policies.custom import PolicyBuilder
from agentshield.core import AgentShield, AgentShieldConfig

config = AgentShieldConfig(...)
shield = AgentShield(config)

policy = (
    PolicyBuilder("no-web-access")
    .named("Block Web Access Tools")
    .description("Prevent agent from accessing external web resources")
    .when_tool_called("web_search", "fetch_url", "http_request")
    .then_block()
    .with_severity("high")
    .build()
)

shield._policy_engine.add_policy(policy)
```

## Interceptor

### Direct Interceptor Usage

For custom integrations, use the Interceptor directly:

```python
from agentshield.interceptor import Interceptor

interceptor = shield._interceptor

# Capture LLM call start
event = interceptor.capture_llm_start(
    session_id="my-session",
    agent_name="my-agent",
    prompt="The user's input",
    model="gpt-4",
)

# After LLM returns
interceptor.capture_llm_end(
    session_id="my-session",
    agent_name="my-agent",
    output="The model's response",
    input_tokens=100,
    output_tokens=50,
    latency_ms=1200.0,
)

# Tool calls
interceptor.capture_tool_start(
    session_id="my-session",
    agent_name="my-agent",
    tool_name="search_web",
    tool_args={"query": "latest AI news"},
)
```

## Audit Logger

### Reading the Audit Log

```python
from agentshield.audit.logger import AuditLogger

logger = AuditLogger(log_path="agentshield-audit.log")
entries = logger.get_entries(session_id="my-session", limit=50)

# Verify chain integrity
is_valid, message = logger.verify_chain()
print(f"Audit log integrity: {is_valid} — {message}")
```

## Session Replay

```python
from agentshield.audit.replay import SessionReplayer
from agentshield.transport.local import LocalTransport

# Load events from local transport
transport = LocalTransport(config)
events = transport.get_events(session_id="my-session")

# Build replay
replayer = SessionReplayer()
replay = replayer.build_replay(events)

print(f"Session duration: {replay.duration_ms}ms")
print(f"Max threat score: {replay.max_threat_score}")
print(f"Had violations: {replay.had_violations}")

# Export to JSON
replayer.export_json(replay, "replay.json")
```
