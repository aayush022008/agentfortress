"""Tests for AgentShield interceptor."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.core import AgentShield, AgentShieldConfig
from agentshield.interceptor import Interceptor, EventType, AgentKilledException, PolicyBlockException


@pytest.fixture
def shield():
    config = AgentShieldConfig(offline_mode=True, enable_blocking=True, enable_pii_detection=True)
    return AgentShield(config)


@pytest.fixture
def interceptor(shield):
    return shield._interceptor


def test_capture_llm_start_safe(interceptor):
    """Normal prompt should be captured without blocking."""
    event = interceptor.capture_llm_start(
        session_id="test-session",
        agent_name="test-agent",
        prompt="Summarize this document.",
    )
    assert event.event_type == EventType.LLM_START
    assert event.session_id == "test-session"
    assert not event.blocked


def test_capture_llm_end(interceptor):
    """LLM end event should be captured with output data."""
    event = interceptor.capture_llm_end(
        session_id="test-session",
        agent_name="test-agent",
        output="Here is the summary.",
        input_tokens=10,
        output_tokens=5,
        latency_ms=150.0,
    )
    assert event.event_type == EventType.LLM_END
    assert event.latency_ms == 150.0
    assert event.data["output_tokens"] == 5


def test_capture_tool_start(interceptor):
    """Tool start should be captured."""
    event = interceptor.capture_tool_start(
        session_id="test-session",
        agent_name="test-agent",
        tool_name="search",
        tool_args={"query": "weather today"},
    )
    assert event.event_type == EventType.TOOL_START
    assert event.data["tool_name"] == "search"


def test_kill_switch(interceptor):
    """Kill switch should raise AgentKilledException on subsequent calls."""
    interceptor.kill_session("dead-session")

    with pytest.raises(AgentKilledException):
        interceptor.capture_llm_start(
            session_id="dead-session",
            agent_name="test-agent",
            prompt="This should not run.",
        )


def test_tool_whitelist_blocks_unlisted_tool(interceptor):
    """Tool call to unlisted tool should be blocked when whitelist is set."""
    interceptor._config.allowed_tools = ["search", "read_file"]

    with pytest.raises(PolicyBlockException) as exc_info:
        interceptor.capture_tool_start(
            session_id="test-session",
            agent_name="test-agent",
            tool_name="execute_shell",
            tool_args={"cmd": "ls"},
        )

    assert "not in allowed tools" in str(exc_info.value)
    interceptor._config.allowed_tools = []  # Reset


def test_memory_capture(interceptor):
    """Memory read/write should be captured."""
    r = interceptor.capture_memory_read("s1", "agent", "key1", "value1")
    assert r.event_type == EventType.MEMORY_READ

    w = interceptor.capture_memory_write("s1", "agent", "key1", "new-value")
    assert w.event_type == EventType.MEMORY_WRITE


def test_session_stats_tracking(interceptor):
    """Session stats should be tracked across calls."""
    sid = "stats-test"
    interceptor.capture_llm_start(sid, "agent", "prompt1")
    interceptor.capture_llm_start(sid, "agent", "prompt2")
    interceptor.capture_tool_start(sid, "agent", "tool1", {})

    stats = interceptor._get_session_stats(sid)
    assert stats["llm_calls"] == 2
    assert stats["tool_calls"] == 1
