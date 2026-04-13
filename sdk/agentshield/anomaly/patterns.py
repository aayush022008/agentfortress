"""
Known attack pattern signatures for AgentShield anomaly detection.

These patterns represent behavioral signatures at the agent level
(not text-level — those are in threat-intel/patterns/).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Any


@dataclass
class BehavioralPattern:
    """A behavioral pattern that indicates potential attack."""
    pattern_id: str
    name: str
    description: str
    severity: str
    detector: Callable[[Any], bool]


def _detect_rapid_tool_switching(session_metrics: Any) -> bool:
    """Detect rapid switching between many different tools — may indicate probing."""
    if len(session_metrics.tool_names_called) < 10:
        return False
    unique_tools = len(set(session_metrics.tool_names_called[-10:]))
    return unique_tools >= 8  # 8+ different tools in last 10 calls


def _detect_repeated_failures(session_metrics: Any) -> bool:
    """Detect agent repeatedly triggering errors — may indicate fuzzing."""
    import time
    now = time.time()
    recent_errors = [t for t in session_metrics.error_times if t > now - 120]
    return len(recent_errors) > 10


def _detect_data_hoarding(session_metrics: Any) -> bool:
    """Detect accumulation of large outputs — potential data exfiltration staging."""
    if len(session_metrics.output_sizes) < 5:
        return False
    total = sum(session_metrics.output_sizes[-10:])
    return total > 500_000  # 500KB in last 10 outputs


def _detect_escalating_threats(session_metrics: Any) -> bool:
    """Detect a clear upward trend in threat scores."""
    scores = session_metrics.threat_scores
    if len(scores) < 5:
        return False
    # Check if last 5 scores are strictly increasing
    last_5 = scores[-5:]
    return all(last_5[i] < last_5[i+1] for i in range(len(last_5) - 1)) and last_5[-1] > 50


BEHAVIORAL_PATTERNS: list[BehavioralPattern] = [
    BehavioralPattern(
        pattern_id="bp-001",
        name="Rapid Tool Probing",
        description="Agent is rapidly switching between many different tools, indicating probing behavior",
        severity="high",
        detector=_detect_rapid_tool_switching,
    ),
    BehavioralPattern(
        pattern_id="bp-002",
        name="Repeated Failure Pattern",
        description="Agent is repeatedly triggering errors, possibly fuzzing or testing boundaries",
        severity="medium",
        detector=_detect_repeated_failures,
    ),
    BehavioralPattern(
        pattern_id="bp-003",
        name="Data Hoarding",
        description="Agent is accumulating unusually large amounts of data output",
        severity="high",
        detector=_detect_data_hoarding,
    ),
    BehavioralPattern(
        pattern_id="bp-004",
        name="Escalating Threat Pattern",
        description="Threat scores are steadily increasing — attack may be escalating",
        severity="critical",
        detector=_detect_escalating_threats,
    ),
]


def check_behavioral_patterns(session_metrics: Any) -> list[BehavioralPattern]:
    """
    Check a session's metrics against all behavioral patterns.

    Args:
        session_metrics: SessionMetrics object

    Returns:
        List of triggered BehavioralPattern objects
    """
    triggered = []
    for pattern in BEHAVIORAL_PATTERNS:
        try:
            if pattern.detector(session_metrics):
                triggered.append(pattern)
        except Exception:
            pass
    return triggered
