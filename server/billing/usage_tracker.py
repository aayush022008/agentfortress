"""Usage tracker — track events/month, agents, API calls per org."""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class UsageSummary:
    org_id: str
    period_start: float
    period_end: float
    events: int = 0
    agents: int = 0
    api_calls: int = 0
    sessions: int = 0


class UsageTracker:
    """
    Tracks usage metrics per org per billing period.
    Production implementation should use Redis for atomic increments.

    Usage::

        tracker = UsageTracker()
        tracker.record_event(org_id="org-123")
        tracker.record_api_call(org_id="org-123", endpoint="/api/events")
        summary = tracker.get_summary("org-123")
    """

    def __init__(self) -> None:
        self._counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._period_start: Dict[str, float] = {}

    def record_event(self, org_id: str, count: int = 1) -> None:
        self._ensure_period(org_id)
        self._counters[org_id]["events"] += count

    def record_api_call(
        self, org_id: str, endpoint: str = "", count: int = 1
    ) -> None:
        self._ensure_period(org_id)
        self._counters[org_id]["api_calls"] += count

    def record_agent(self, org_id: str) -> None:
        self._ensure_period(org_id)
        agents = self._counters[org_id].get("agent_ids", set())
        # Can't do set in defaultdict(int) easily, use a counter
        self._counters[org_id]["agents"] += 1

    def record_session(self, org_id: str) -> None:
        self._ensure_period(org_id)
        self._counters[org_id]["sessions"] += 1

    def get_summary(self, org_id: str) -> UsageSummary:
        self._ensure_period(org_id)
        period_start = self._period_start.get(org_id, time.time())
        counters = self._counters[org_id]
        return UsageSummary(
            org_id=org_id,
            period_start=period_start,
            period_end=period_start + 30 * 86400,
            events=counters.get("events", 0),
            agents=counters.get("agents", 0),
            api_calls=counters.get("api_calls", 0),
            sessions=counters.get("sessions", 0),
        )

    def reset_period(self, org_id: str) -> None:
        """Reset counters for the start of a new billing period."""
        self._counters[org_id] = defaultdict(int)
        self._period_start[org_id] = time.time()

    def check_limit(
        self, org_id: str, metric: str, limit: int
    ) -> tuple[bool, int]:
        """
        Check if a metric is within the plan limit.
        Returns (within_limit, current_value).
        """
        self._ensure_period(org_id)
        value = self._counters[org_id].get(metric, 0)
        return value < limit, value

    # ------------------------------------------------------------------

    def _ensure_period(self, org_id: str) -> None:
        if org_id not in self._period_start:
            self._period_start[org_id] = time.time()
