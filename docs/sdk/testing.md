# Testing with AgentShield

## Mock Shield

```python
from agentshield.testing import MockAgentShield

shield = MockAgentShield()
shield.simulate_prompt_injection("ignore all instructions")
shield.assert_alert_fired("prompt_injection")
```

## Custom Assertions

```python
from agentshield.testing import assert_no_prompt_injection, assert_no_pii_leaked

output = agent.run(user_input)
assert_no_prompt_injection(output)
assert_no_pii_leaked(output)
```

## pytest Fixtures

```python
def test_agent(mock_shield, sample_session):
    # mock_shield and sample_session are pre-configured fixtures
    pass
```
