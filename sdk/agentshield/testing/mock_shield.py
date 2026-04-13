"""Mock AgentShield for unit tests — no server needed."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class MockAlert:
    alert_type: str
    severity: str
    description: str
    agent_id: str = "test-agent"
    session_id: str = "test-session"


class MockAgentShield:
    """
    Mock AgentShield interceptor for unit tests.
    Records calls, allows assertions, and can simulate alert firing.

    Usage::

        shield = MockAgentShield()
        shield.simulate_prompt_injection("ignore all instructions")

        with shield.protect(agent):
            result = agent.run("do something")

        shield.assert_no_alerts()
        shield.assert_alert_fired("prompt_injection")
    """

    def __init__(self) -> None:
        self.intercepted_events: List[Dict[str, Any]] = []
        self.fired_alerts: List[MockAlert] = []
        self.blocked_calls: List[Dict[str, Any]] = []
        self._rules: List[Callable] = []
        self._should_block = False

    def simulate_alert(
        self,
        alert_type: str,
        severity: str = "high",
        description: str = "",
    ) -> MockAlert:
        """Simulate an alert being fired."""
        alert = MockAlert(
            alert_type=alert_type,
            severity=severity,
            description=description or f"Simulated {alert_type} alert",
        )
        self.fired_alerts.append(alert)
        return alert

    def simulate_prompt_injection(self, text: str) -> MockAlert:
        return self.simulate_alert("prompt_injection", "critical", f"Injection detected: {text[:50]}")

    def simulate_data_exfiltration(self, data: str = "") -> MockAlert:
        return self.simulate_alert("data_exfiltration", "high", "Data exfiltration detected")

    def add_block_rule(self, rule: Callable[[Dict[str, Any]], bool]) -> None:
        """Add a callable that returns True to block an event."""
        self._rules.append(rule)

    def record_event(self, event: Dict[str, Any]) -> bool:
        """Record an event. Returns False if blocked by rules."""
        self.intercepted_events.append(event)
        for rule in self._rules:
            if rule(event):
                self.blocked_calls.append(event)
                return False
        return True

    def assert_no_alerts(self) -> None:
        """Assert no alerts were fired."""
        if self.fired_alerts:
            types = [a.alert_type for a in self.fired_alerts]
            raise AssertionError(f"Expected no alerts but got: {types}")

    def assert_alert_fired(self, alert_type: str) -> None:
        """Assert that a specific alert type was fired."""
        types = [a.alert_type for a in self.fired_alerts]
        if alert_type not in types:
            raise AssertionError(f"Expected alert '{alert_type}' but fired alerts were: {types}")

    def assert_event_count(self, count: int) -> None:
        """Assert exact number of events intercepted."""
        actual = len(self.intercepted_events)
        if actual != count:
            raise AssertionError(f"Expected {count} events but got {actual}")

    def assert_no_blocked_calls(self) -> None:
        """Assert no calls were blocked."""
        if self.blocked_calls:
            raise AssertionError(f"Expected no blocked calls but got {len(self.blocked_calls)}")

    def reset(self) -> None:
        """Clear all recorded state."""
        self.intercepted_events.clear()
        self.fired_alerts.clear()
        self.blocked_calls.clear()

    def get_events_by_type(self, event_type: str) -> List[Dict[str, Any]]:
        return [e for e in self.intercepted_events if e.get("event_type") == event_type]

    def get_alert_count(self, alert_type: Optional[str] = None) -> int:
        if alert_type:
            return sum(1 for a in self.fired_alerts if a.alert_type == alert_type)
        return len(self.fired_alerts)
