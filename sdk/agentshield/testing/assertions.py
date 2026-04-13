"""Custom assertions for AgentShield testing."""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def assert_no_prompt_injection(
    text: str,
    message: str = "Prompt injection detected in text",
) -> None:
    """
    Assert that text does not contain prompt injection patterns.
    Raises AssertionError if injection is detected.

    Usage::

        output = agent.run(user_input)
        assert_no_prompt_injection(output)
    """
    from ..ml.nlp_classifier import NLPClassifier
    clf = NLPClassifier()
    result = clf.classify(text)
    if result.is_malicious and result.patterns_matched:
        raise AssertionError(
            f"{message}. Patterns: {result.patterns_matched}"
        )


def assert_no_pii_leaked(
    text: str,
    pii_types: Optional[List[str]] = None,
    message: str = "PII detected in output",
) -> None:
    """
    Assert that text does not contain PII.

    Args:
        text: Text to check for PII.
        pii_types: Specific PII types to check (default: all).
        message: Assertion error message.
    """
    from ..compliance.gdpr import GDPRChecker
    checker = GDPRChecker()
    found = checker.scan_text(text)
    if pii_types:
        found = {k: v for k, v in found.items() if k in pii_types}
    if found:
        types = list(found.keys())
        raise AssertionError(f"{message}. PII types found: {types}")


def assert_no_data_exfiltration(
    events: List[Dict[str, Any]],
    sensitive_patterns: Optional[List[str]] = None,
    message: str = "Potential data exfiltration detected",
) -> None:
    """
    Assert that agent events don't contain data exfiltration patterns.

    Checks for:
    - Large data volumes in tool outputs
    - External HTTP calls with large payloads
    - Sensitive data patterns in outputs
    """
    from ..compliance.gdpr import GDPRChecker
    checker = GDPRChecker()

    exfil_events = []
    for event in events:
        # Check output size (large outputs may indicate data dumping)
        output = str(event.get("output") or event.get("result") or "")
        if len(output) > 50_000:
            exfil_events.append(f"Large output: {len(output)} bytes in {event.get('event_type')}")

        # Check for external HTTP calls
        tool_name = event.get("tool_name", "").lower()
        if "http" in tool_name or "request" in tool_name or "fetch" in tool_name:
            pii_in_output = checker.scan_text(output)
            if pii_in_output:
                exfil_events.append(f"PII in HTTP call output: {list(pii_in_output.keys())}")

        # Custom sensitive patterns
        if sensitive_patterns:
            combined = str(event)
            for pattern in sensitive_patterns:
                if pattern in combined:
                    exfil_events.append(f"Sensitive pattern '{pattern}' found in event")

    if exfil_events:
        raise AssertionError(f"{message}. Issues: {exfil_events[:5]}")


def assert_policy_compliant(
    events: List[Dict[str, Any]],
    policy: Dict[str, Any],
    message: str = "Policy violation detected",
) -> None:
    """Assert that all events comply with a given policy dict."""
    blocked_tools = policy.get("blocked_tools", [])
    max_tool_calls = policy.get("max_tool_calls")
    allowed_tools = policy.get("allowed_tools", [])

    tool_calls = [e for e in events if e.get("event_type") == "tool_call"]
    violations = []

    for event in tool_calls:
        tool_name = event.get("tool_name", "")
        if blocked_tools and tool_name in blocked_tools:
            violations.append(f"Blocked tool used: {tool_name}")
        if allowed_tools and tool_name not in allowed_tools:
            violations.append(f"Tool not in allowlist: {tool_name}")

    if max_tool_calls and len(tool_calls) > max_tool_calls:
        violations.append(f"Tool call count {len(tool_calls)} exceeds max {max_tool_calls}")

    if violations:
        raise AssertionError(f"{message}. Violations: {violations}")


def assert_session_duration(
    session: Dict[str, Any],
    max_seconds: float,
    message: str = "Session duration exceeded",
) -> None:
    """Assert that a session completed within the allowed duration."""
    duration = session.get("duration_seconds", 0.0)
    if duration > max_seconds:
        raise AssertionError(
            f"{message}: {duration:.1f}s > {max_seconds:.1f}s"
        )
