"""Tests for framework wrappers."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.core import AgentShield, AgentShieldConfig
from agentshield.wrappers.generic import GenericWrapper


class MockAgent:
    """Simple mock agent for testing wrappers."""

    def __init__(self):
        self.calls = []

    def run(self, input: str, **kwargs) -> str:
        self.calls.append(("run", input))
        return f"Result for: {input}"

    def invoke(self, input: str, **kwargs) -> str:
        self.calls.append(("invoke", input))
        return f"Invoke result for: {input}"

    def __call__(self, input: str, **kwargs) -> str:
        self.calls.append(("__call__", input))
        return f"Called with: {input}"


@pytest.fixture
def shield():
    config = AgentShieldConfig(offline_mode=True, enable_blocking=False)
    return AgentShield(config)


def test_generic_wrapper_run(shield):
    """GenericWrapper should intercept run() calls."""
    agent = MockAgent()
    wrapped = shield.protect(agent, "test-agent")

    result = wrapped.run("test task")
    assert "Result for" in result
    assert ("run", "test task") in agent.calls


def test_generic_wrapper_invoke(shield):
    """GenericWrapper should intercept invoke() calls."""
    agent = MockAgent()
    wrapped = shield.protect(agent, "test-agent")

    result = wrapped.invoke("test invoke")
    assert "Invoke result" in result


def test_generic_wrapper_call(shield):
    """GenericWrapper should intercept __call__."""
    agent = MockAgent()
    wrapped = GenericWrapper(
        agent=agent,
        interceptor=shield._interceptor,
        agent_name="test",
    )
    result = wrapped("direct call")
    assert "Called with" in result


def test_wrapper_session_id(shield):
    """Each wrapped agent should have a unique session ID."""
    agent1 = MockAgent()
    agent2 = MockAgent()

    w1 = shield.protect(agent1, "agent1")
    w2 = shield.protect(agent2, "agent2")

    assert w1.get_session_id() != w2.get_session_id()


def test_wrapper_kill_switch(shield):
    """Kill switch should prevent further agent calls."""
    from agentshield.interceptor import AgentKilledException

    agent = MockAgent()
    wrapped = shield.protect(agent, "killable-agent")
    wrapped.kill()

    with pytest.raises(AgentKilledException):
        wrapped.run("this should fail")


def test_wrapper_proxy_attributes(shield):
    """Wrapper should proxy attribute access to underlying agent."""
    agent = MockAgent()
    wrapped = shield.protect(agent, "proxy-agent")
    # Access attribute on underlying agent
    assert wrapped.calls == agent.calls


def test_shield_protect_auto_detect_generic(shield):
    """Unknown agent class should use GenericWrapper."""
    from agentshield.wrappers.generic import GenericWrapper

    agent = MockAgent()
    wrapped = shield.protect(agent)
    assert isinstance(wrapped, GenericWrapper)
