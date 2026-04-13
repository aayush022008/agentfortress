"""
Anomaly detection engine for AgentShield.

Uses statistical baselines and rule-based heuristics to detect
abnormal agent behavior that may indicate compromise or attack.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""

    is_anomalous: bool
    score: float  # 0.0 to 1.0
    reasons: list[str]
    session_id: str
    metric_name: str = ""


@dataclass
class SessionMetrics:
    """Running metrics for a single agent session."""

    session_id: str
    llm_call_times: list[float] = field(default_factory=list)
    tool_call_times: list[float] = field(default_factory=list)
    llm_call_latencies: list[float] = field(default_factory=list)
    output_sizes: list[int] = field(default_factory=list)
    tool_names_called: list[str] = field(default_factory=list)
    threat_scores: list[int] = field(default_factory=list)
    error_times: list[float] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)


class AnomalyDetector:
    """
    Detects anomalous behavior in AI agent sessions.

    Uses:
    - Rate analysis: Detects unusually rapid API calls
    - Output size analysis: Detects unusually large outputs
    - Error spike detection: Detects error bursts (may indicate probing)
    - Tool diversity detection: Detects unusual tool call patterns
    - Threat score trends: Rising threat scores indicate escalating attack
    """

    # Baseline thresholds
    MAX_LLM_CALLS_PER_MINUTE = 30
    MAX_TOOL_CALLS_PER_MINUTE = 60
    MAX_OUTPUT_SIZE_BYTES = 50_000
    LARGE_OUTPUT_THRESHOLD = 10_000
    ERROR_SPIKE_THRESHOLD = 5  # errors per minute
    THREAT_SCORE_TREND_THRESHOLD = 40  # avg threat score above which to alert
    Z_SCORE_ANOMALY_THRESHOLD = 3.0

    def __init__(self) -> None:
        self._sessions: dict[str, SessionMetrics] = {}

    def _get_session(self, session_id: str) -> SessionMetrics:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionMetrics(session_id=session_id)
        return self._sessions[session_id]

    def record_event(self, event: Any) -> Optional[AnomalyResult]:
        """
        Record an event and check for anomalies.

        Args:
            event: InterceptorEvent

        Returns:
            AnomalyResult if anomaly detected, None otherwise
        """
        session = self._get_session(event.session_id)
        now = time.time()

        from ..interceptor import EventType

        if event.event_type in (EventType.LLM_START, EventType.LLM_END):
            session.llm_call_times.append(now)
            if event.latency_ms is not None:
                session.llm_call_latencies.append(event.latency_ms)

        elif event.event_type in (EventType.TOOL_START, EventType.TOOL_END):
            session.tool_call_times.append(now)
            tool_name = event.data.get("tool_name", "")
            if tool_name:
                session.tool_names_called.append(tool_name)

        elif event.event_type in (EventType.LLM_ERROR, EventType.TOOL_ERROR, EventType.AGENT_ERROR):
            session.error_times.append(now)

        if event.data.get("output_size_bytes"):
            session.output_sizes.append(event.data["output_size_bytes"])

        if event.threat_score > 0:
            session.threat_scores.append(event.threat_score)

        # Run anomaly checks
        anomaly = self._check_anomalies(session, now)
        return anomaly

    def _check_anomalies(
        self,
        session: SessionMetrics,
        now: float,
    ) -> Optional[AnomalyResult]:
        """Run all anomaly checks and return result if anomaly found."""
        reasons: list[str] = []
        max_score = 0.0

        # Check LLM call rate
        llm_rate = self._calls_per_minute(session.llm_call_times, now)
        if llm_rate > self.MAX_LLM_CALLS_PER_MINUTE:
            score = min(1.0, llm_rate / (self.MAX_LLM_CALLS_PER_MINUTE * 2))
            reasons.append(f"Abnormal LLM call rate: {llm_rate:.1f}/min (max {self.MAX_LLM_CALLS_PER_MINUTE})")
            max_score = max(max_score, score)

        # Check tool call rate
        tool_rate = self._calls_per_minute(session.tool_call_times, now)
        if tool_rate > self.MAX_TOOL_CALLS_PER_MINUTE:
            score = min(1.0, tool_rate / (self.MAX_TOOL_CALLS_PER_MINUTE * 2))
            reasons.append(f"Abnormal tool call rate: {tool_rate:.1f}/min (max {self.MAX_TOOL_CALLS_PER_MINUTE})")
            max_score = max(max_score, score)

        # Check error spike
        error_rate = self._calls_per_minute(session.error_times, now)
        if error_rate > self.ERROR_SPIKE_THRESHOLD:
            score = min(1.0, error_rate / (self.ERROR_SPIKE_THRESHOLD * 3))
            reasons.append(f"Error spike detected: {error_rate:.1f} errors/min")
            max_score = max(max_score, score)

        # Check output size anomaly
        if len(session.output_sizes) >= 3:
            size_anomaly = self._detect_size_anomaly(session.output_sizes)
            if size_anomaly > 0:
                reasons.append(f"Anomalous output size detected (z-score: {size_anomaly:.1f})")
                max_score = max(max_score, min(1.0, size_anomaly / 5.0))

        # Check rising threat scores
        if len(session.threat_scores) >= 3:
            avg_threat = sum(session.threat_scores[-5:]) / min(5, len(session.threat_scores))
            if avg_threat >= self.THREAT_SCORE_TREND_THRESHOLD:
                score = min(1.0, avg_threat / 100.0)
                reasons.append(f"Rising threat score trend: avg={avg_threat:.0f}")
                max_score = max(max_score, score)

        if reasons:
            return AnomalyResult(
                is_anomalous=True,
                score=max_score,
                reasons=reasons,
                session_id=session.session_id,
            )
        return None

    def _calls_per_minute(self, timestamps: list[float], now: float) -> float:
        """Calculate call rate per minute over a 1-minute sliding window."""
        cutoff = now - 60.0
        recent = [t for t in timestamps if t > cutoff]
        return len(recent)

    def _detect_size_anomaly(self, sizes: list[int]) -> float:
        """Detect output size anomaly using z-score. Returns z-score of last value."""
        if len(sizes) < 3:
            return 0.0
        mean = sum(sizes) / len(sizes)
        variance = sum((s - mean) ** 2 for s in sizes) / len(sizes)
        std = math.sqrt(variance) if variance > 0 else 1
        last = sizes[-1]
        z_score = abs(last - mean) / std
        return z_score if z_score > self.Z_SCORE_ANOMALY_THRESHOLD else 0.0

    def get_session_risk_score(self, session_id: str) -> int:
        """
        Get a 0-100 risk score for a session based on accumulated signals.

        Args:
            session_id: Session to evaluate

        Returns:
            Risk score from 0 (safe) to 100 (critical)
        """
        session = self._sessions.get(session_id)
        if not session:
            return 0

        score = 0
        now = time.time()

        # LLM call rate contribution
        llm_rate = self._calls_per_minute(session.llm_call_times, now)
        if llm_rate > self.MAX_LLM_CALLS_PER_MINUTE:
            score += 20

        # Threat score contribution
        if session.threat_scores:
            avg_threat = sum(session.threat_scores) / len(session.threat_scores)
            score += int(avg_threat * 0.5)

        # Error rate contribution
        error_rate = self._calls_per_minute(session.error_times, now)
        if error_rate > self.ERROR_SPIKE_THRESHOLD:
            score += 15

        # Large output contribution
        if session.output_sizes and max(session.output_sizes) > self.MAX_OUTPUT_SIZE_BYTES:
            score += 20

        return min(100, score)

    def clear_session(self, session_id: str) -> None:
        """Clear metrics for a session (e.g., when session ends)."""
        self._sessions.pop(session_id, None)
