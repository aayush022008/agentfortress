"""Tests for anomaly detection."""

import pytest
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.anomaly.detector import AnomalyDetector, SessionMetrics
from agentshield.anomaly.patterns import check_behavioral_patterns
from agentshield.interceptor import InterceptorEvent, EventType


def _make_event(session_id, event_type, threat_score=0, data=None):
    e = InterceptorEvent()
    e.session_id = session_id
    e.event_type = event_type
    e.threat_score = threat_score
    e.data = data or {}
    e.latency_ms = None
    e.agent_name = "agent"
    return e


@pytest.fixture
def detector():
    return AnomalyDetector()


def test_normal_activity_no_anomaly(detector):
    """Normal activity should not trigger anomalies."""
    for _ in range(5):
        event = _make_event("normal-session", EventType.LLM_START)
        result = detector.record_event(event)
    # 5 calls in 1 minute is fine
    assert result is None or result.score < 0.5


def test_rapid_calls_triggers_anomaly(detector):
    """Rapid LLM calls should trigger rate anomaly."""
    sid = "rapid-session"
    # Simulate 35 calls rapidly (above threshold of 30/min)
    now = time.time()
    session = detector._get_session(sid)
    session.llm_call_times = [now - i * 0.1 for i in range(35)]

    event = _make_event(sid, EventType.LLM_START)
    result = detector.record_event(event)
    assert result is not None
    assert result.is_anomalous


def test_large_output_triggers_anomaly(detector):
    """Very large outputs should trigger anomaly via behavioral signals."""
    sid = "large-output-session"
    # Feed baseline outputs into the session by recording events
    session = detector._get_session(sid)
    # Manually populate enough samples for z-score to work
    session.output_sizes = [100, 200, 150, 180, 120]

    # Now record an event with a huge output — z-score should be extremely high
    event = _make_event(sid, EventType.LLM_END, data={"output_size_bytes": 500_000})
    result = detector.record_event(event)
    # Either anomaly is detected, or the risk score is high
    risk = detector.get_session_risk_score(sid)
    assert result is not None or risk >= 20


def test_rising_threat_scores(detector):
    """Rising threat scores should trigger anomaly."""
    sid = "rising-threats"
    session = detector._get_session(sid)
    session.threat_scores = [10, 20, 35, 50, 65]  # Avg > 40

    event = _make_event(sid, EventType.LLM_START, threat_score=65)
    result = detector.record_event(event)
    assert result is not None
    assert result.is_anomalous


def test_risk_score_calculation(detector):
    """Risk score should be 0-100."""
    sid = "risk-session"
    score = detector.get_session_risk_score(sid)
    assert 0 <= score <= 100


def test_behavioral_pattern_data_hoarding():
    """Data hoarding pattern should detect large outputs."""
    metrics = SessionMetrics(session_id="test")
    metrics.output_sizes = [100_000] * 10  # 100KB each, 10 outputs = 1MB total

    patterns = check_behavioral_patterns(metrics)
    pattern_ids = [p.pattern_id for p in patterns]
    assert "bp-003" in pattern_ids  # Data hoarding pattern


def test_behavioral_pattern_rapid_tool_switching():
    """Rapid tool switching should be detected."""
    metrics = SessionMetrics(session_id="test")
    # 8 different tools in last 10 calls
    metrics.tool_names_called = [f"tool_{i}" for i in range(10)]

    patterns = check_behavioral_patterns(metrics)
    pattern_ids = [p.pattern_id for p in patterns]
    assert "bp-001" in pattern_ids


def test_session_clear(detector):
    """Session metrics should be clearable."""
    sid = "clear-test"
    detector._get_session(sid)
    assert sid in detector._sessions

    detector.clear_session(sid)
    assert sid not in detector._sessions
