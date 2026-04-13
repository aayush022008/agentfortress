"""
Custom policy rule builder for AgentShield.

Provides a fluent DSL for building custom security policies without
needing to directly construct Policy objects.
"""

from __future__ import annotations

from typing import Any

from .engine import Policy, PolicyAction


class PolicyBuilder:
    """
    Fluent DSL builder for creating custom security policies.

    Example:
        policy = (
            PolicyBuilder("no-file-access")
            .named("Block File System Access")
            .description("Prevent agent from accessing the file system")
            .when_tool_called("read_file", "write_file", "delete_file")
            .then_block()
            .with_severity("critical")
            .build()
        )
    """

    def __init__(self, policy_id: str) -> None:
        self._policy_id = policy_id
        self._name = policy_id
        self._description = ""
        self._condition: dict[str, Any] = {"type": "always"}
        self._action = PolicyAction.ALERT
        self._severity = "medium"
        self._enabled = True

    def named(self, name: str) -> "PolicyBuilder":
        """Set the human-readable name."""
        self._name = name
        return self

    def description(self, desc: str) -> "PolicyBuilder":
        """Set the description."""
        self._description = desc
        return self

    def when_threat_score_above(self, threshold: int) -> "PolicyBuilder":
        """Trigger when threat score exceeds threshold."""
        self._condition = {"type": "threat_score_above", "threshold": threshold}
        return self

    def when_tool_called(self, *tool_names: str) -> "PolicyBuilder":
        """Trigger when any of the specified tools are called."""
        self._condition = {
            "type": "or",
            "conditions": [
                {"type": "tool_name_is", "tool_name": t}
                for t in tool_names
            ],
        }
        return self

    def when_output_exceeds_bytes(self, bytes_limit: int) -> "PolicyBuilder":
        """Trigger when output size exceeds the given byte limit."""
        self._condition = {"type": "output_size_above", "threshold_bytes": bytes_limit}
        return self

    def when_rate_exceeded(self, max_calls: int, window_seconds: int = 60) -> "PolicyBuilder":
        """Trigger when call rate exceeds the given limit."""
        self._condition = {
            "type": "rate_limit",
            "max_calls": max_calls,
            "window_seconds": window_seconds,
        }
        return self

    def when_pii_detected(self) -> "PolicyBuilder":
        """Trigger when PII is detected in output."""
        self._condition = {"type": "pii_detected"}
        return self

    def and_also(self, other_condition: dict[str, Any]) -> "PolicyBuilder":
        """Add an additional AND condition."""
        self._condition = {
            "type": "and",
            "conditions": [self._condition, other_condition],
        }
        return self

    def or_also(self, other_condition: dict[str, Any]) -> "PolicyBuilder":
        """Add an additional OR condition."""
        self._condition = {
            "type": "or",
            "conditions": [self._condition, other_condition],
        }
        return self

    def then_block(self) -> "PolicyBuilder":
        """Set action to BLOCK."""
        self._action = PolicyAction.BLOCK
        return self

    def then_alert(self) -> "PolicyBuilder":
        """Set action to ALERT."""
        self._action = PolicyAction.ALERT
        return self

    def then_log(self) -> "PolicyBuilder":
        """Set action to LOG."""
        self._action = PolicyAction.LOG
        return self

    def then_rate_limit(self) -> "PolicyBuilder":
        """Set action to RATE_LIMIT."""
        self._action = PolicyAction.RATE_LIMIT
        return self

    def with_severity(self, severity: str) -> "PolicyBuilder":
        """Set severity level (low/medium/high/critical)."""
        self._severity = severity
        return self

    def disabled(self) -> "PolicyBuilder":
        """Create the policy in disabled state."""
        self._enabled = False
        return self

    def build(self) -> Policy:
        """Build and return the Policy object."""
        return Policy(
            policy_id=self._policy_id,
            name=self._name,
            description=self._description,
            condition=self._condition,
            action=self._action,
            enabled=self._enabled,
            severity=self._severity,
        )
