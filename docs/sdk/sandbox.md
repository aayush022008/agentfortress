# Sandboxing Guide

## Basic Usage

```python
from agentshield.sandbox import SandboxConfig, SandboxExecutor

config = SandboxConfig(max_memory_mb=256, max_duration_seconds=60, enable_network=False)
executor = SandboxExecutor(config)
result = await executor.run_script("agent.py")
print(result.peak_memory_mb, result.duration_seconds)
```

## Network Policy

```python
from agentshield.sandbox import NetworkPolicy, NetworkEnforcer

policy = NetworkPolicy(mode="allowlist", allowed_hosts=["api.openai.com"], allowed_ports=[443])
with NetworkEnforcer(policy):
    # Only openai.com:443 allowed
    agent.run()
```
