"""Tests for AgentShield policy engine."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.core import AgentShieldConfig
from agentshield.policies.engine import PolicyEngine, Policy, PolicyAction
from agentshield.policies.custom import PolicyBuilder
from agentshield.interceptor import InterceptorEvent, EventType


@pytest.fixture
def config():
    return AgentShieldConfig(
        offline_mode=True,
        enable_blocking=True,
        enable_pii_detection=True,
    )


@pytest.fixture
def engine(config):
    return PolicyEngine(config)


def _make_event(event_type=EventType.LLM_START, threat_score=0, data=None, blocked=False):
    e = InterceptorEvent()
    e.event_type = event_type
    e.threat_score = threat_score
    e.data = data or {}
    e.blocked = blocked
    e.session_id = "test"
    e.agent_name = "test-agent"
    e.threat_reasons = []
    return e


def test_safe_event_allows(engine):
    event = _make_event(threat_score=0)
    action = engine.evaluate(event)
    assert action == PolicyAction.ALLOW.value


def test_high_threat_score_triggers_block(engine):
    event = _make_event(event_type=EventType.LLM_START, threat_score=80)
    action = engine.evaluate(event)
    assert action == PolicyAction.BLOCK.value


def test_medium_threat_triggers_alert(engine):
    event = _make_event(event_type=EventType.LLM_START, threat_score=55)
    action = engine.evaluate(event)
    assert action in (PolicyAction.ALERT.value, PolicyAction.BLOCK.value)


def test_large_output_blocks(engine):
    event = _make_event(
        event_type=EventType.LLM_END,
        data={"output_size_bytes": 200_000},
    )
    action = engine.evaluate(event)
    assert action == PolicyAction.BLOCK.value


def test_add_custom_policy(engine):
    policy = Policy(
        policy_id="custom-1",
        name="Test Policy",
        description="Test",
        condition={"type": "threat_score_above", "threshold": 10},
        action=PolicyAction.LOG,
    )
    engine.add_policy(policy)
    policies = engine.get_policies()
    assert any(p.policy_id == "custom-1" for p in policies)


def test_remove_policy(engine):
    policy = Policy(
        policy_id="remove-me",
        name="Remove Me",
        description="",
        condition={"type": "threat_score_above", "threshold": 99},
        action=PolicyAction.LOG,
    )
    engine.add_policy(policy)
    removed = engine.remove_policy("remove-me")
    assert removed is True
    policies = engine.get_policies()
    assert not any(p.policy_id == "remove-me" for p in policies)


def test_disable_policy(engine):
    policy = Policy(
        policy_id="disable-test",
        name="Disable Test",
        description="",
        condition={"type": "threat_score_above", "threshold": 0},
        action=PolicyAction.BLOCK,
    )
    engine.add_policy(policy)
    engine.disable_policy("disable-test")

    event = _make_event(threat_score=0)
    # With policy disabled, should not block on score 0
    # (other policies may still trigger, but not this one)
    policies = engine.get_policies()
    disabled_policy = next(p for p in policies if p.policy_id == "disable-test")
    assert not disabled_policy.enabled


def test_policy_builder():
    policy = (
        PolicyBuilder("builder-test")
        .named("Builder Test Policy")
        .description("Built with PolicyBuilder")
        .when_threat_score_above(70)
        .then_block()
        .with_severity("critical")
        .build()
    )
    assert policy.policy_id == "builder-test"
    assert policy.name == "Builder Test Policy"
    assert policy.action == PolicyAction.BLOCK
    assert policy.severity == "critical"
    assert policy.condition == {"type": "threat_score_above", "threshold": 70}


def test_rate_limit_condition(engine):
    event = _make_event(event_type=EventType.LLM_START)

    rate_policy = Policy(
        policy_id="rate-test",
        name="Rate Test",
        description="",
        condition={"type": "rate_limit", "max_calls": 2, "window_seconds": 60},
        action=PolicyAction.RATE_LIMIT,
    )
    engine.add_policy(rate_policy)

    # First two calls should not trigger
    for _ in range(2):
        engine.evaluate(event)

    # Third call should trigger rate limit
    action = engine.evaluate(event)
    assert action == PolicyAction.RATE_LIMIT.value
