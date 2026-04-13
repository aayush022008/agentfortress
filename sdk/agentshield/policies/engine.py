"""
Policy enforcement engine for AgentShield.

Evaluates intercepted events against configured security policies
and returns the appropriate action (BLOCK, ALERT, LOG, RATE_LIMIT, ALLOW).
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class PolicyAction(str, Enum):
    """Actions a policy can trigger."""
    ALLOW = "ALLOW"
    LOG = "LOG"
    ALERT = "ALERT"
    RATE_LIMIT = "RATE_LIMIT"
    BLOCK = "BLOCK"


@dataclass
class Policy:
    """
    A security policy rule.

    Attributes:
        policy_id: Unique identifier
        name: Human-readable name
        description: What this policy detects/enforces
        condition: Dict describing the condition to match
        action: Action to take when condition is met
        enabled: Whether the policy is active
        severity: Severity level for generated alerts
    """

    policy_id: str
    name: str
    description: str
    condition: dict[str, Any]
    action: PolicyAction
    enabled: bool = True
    severity: str = "medium"


class PolicyEngine:
    """
    Evaluates events against security policies.

    Maintains built-in default policies and supports custom user-defined policies.
    Implements rate limiting tracking for RATE_LIMIT actions.
    """

    def __init__(self, config: Any) -> None:
        self._config = config
        self._policies: list[Policy] = []
        self._rate_limit_tracker: dict[str, list[float]] = defaultdict(list)
        self._load_default_policies()

    def _load_default_policies(self) -> None:
        """Load the built-in default security policies."""
        from .rules import get_default_policies
        self._policies = get_default_policies(self._config)

    def evaluate(self, event: Any) -> str:
        """
        Evaluate an event against all active policies.

        Args:
            event: InterceptorEvent to evaluate

        Returns:
            The most severe action triggered (BLOCK > ALERT > RATE_LIMIT > LOG > ALLOW)
        """
        if not self._config.enable_blocking:
            return PolicyAction.ALLOW.value

        triggered_actions: list[PolicyAction] = []

        for policy in self._policies:
            if not policy.enabled:
                continue
            if self._matches_condition(event, policy.condition):
                triggered_actions.append(policy.action)
                logger.debug(
                    f"Policy '{policy.name}' triggered: action={policy.action.value} "
                    f"| event_type={event.event_type.value}"
                )

        if not triggered_actions:
            return PolicyAction.ALLOW.value

        # Return most severe action
        action_priority = [
            PolicyAction.BLOCK,
            PolicyAction.RATE_LIMIT,
            PolicyAction.ALERT,
            PolicyAction.LOG,
            PolicyAction.ALLOW,
        ]
        for action in action_priority:
            if action in triggered_actions:
                return action.value

        return PolicyAction.ALLOW.value

    def _matches_condition(self, event: Any, condition: dict[str, Any]) -> bool:
        """Check if an event matches a policy condition."""
        condition_type = condition.get("type")

        if condition_type == "threat_score_above":
            threshold = condition.get("threshold", 50)
            return event.threat_score >= threshold

        elif condition_type == "event_type":
            event_types = condition.get("event_types", [])
            return event.event_type.value in event_types

        elif condition_type == "pii_detected":
            return (
                event.threat_score > 0
                and any("pii" in r.lower() or "email" in r.lower() or "ssn" in r.lower()
                        for r in event.threat_reasons)
            )

        elif condition_type == "output_size_above":
            threshold = condition.get("threshold_bytes", 100000)
            output_size = event.data.get("output_size_bytes", 0) or event.data.get("result_size_bytes", 0)
            return output_size >= threshold

        elif condition_type == "rate_limit":
            key = f"{event.session_id}:{event.event_type.value}"
            max_calls = condition.get("max_calls", 10)
            window_seconds = condition.get("window_seconds", 60)
            return self._check_rate_limit(key, max_calls, window_seconds)

        elif condition_type == "tool_not_in_whitelist":
            allowed = condition.get("allowed_tools", [])
            if not allowed:
                return False
            tool_name = event.data.get("tool_name", "")
            return bool(tool_name) and tool_name not in allowed

        elif condition_type == "and":
            sub_conditions = condition.get("conditions", [])
            return all(self._matches_condition(event, c) for c in sub_conditions)

        elif condition_type == "or":
            sub_conditions = condition.get("conditions", [])
            return any(self._matches_condition(event, c) for c in sub_conditions)

        return False

    def _check_rate_limit(
        self,
        key: str,
        max_calls: int,
        window_seconds: float,
    ) -> bool:
        """Check if rate limit has been exceeded."""
        now = time.time()
        calls = self._rate_limit_tracker[key]
        # Remove calls outside the window
        cutoff = now - window_seconds
        self._rate_limit_tracker[key] = [t for t in calls if t > cutoff]
        self._rate_limit_tracker[key].append(now)
        return len(self._rate_limit_tracker[key]) > max_calls

    def add_policy(self, policy: Policy) -> None:
        """Add a custom policy."""
        self._policies.append(policy)
        logger.info(f"Added policy: {policy.name}")

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID."""
        before = len(self._policies)
        self._policies = [p for p in self._policies if p.policy_id != policy_id]
        return len(self._policies) < before

    def get_policies(self) -> list[Policy]:
        """Return all active policies."""
        return list(self._policies)

    def enable_policy(self, policy_id: str) -> bool:
        """Enable a policy."""
        for p in self._policies:
            if p.policy_id == policy_id:
                p.enabled = True
                return True
        return False

    def disable_policy(self, policy_id: str) -> bool:
        """Disable a policy."""
        for p in self._policies:
            if p.policy_id == policy_id:
                p.enabled = False
                return True
        return False
