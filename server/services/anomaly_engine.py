"""Anomaly engine service — ML-lite anomaly scoring."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any


class AnomalyEngine:
    """Server-side anomaly scoring with session baselines."""

    def __init__(self) -> None:
        self._session_call_times: dict[str, list[float]] = defaultdict(list)

    def score_event(self, event: Any) -> int:
        """Return 0-100 anomaly score for an event."""
        score = 0
        session_id = event.session_id
        now = time.time()

        # Track call frequency
        if event.event_type in ("llm_start", "tool_start"):
            calls = self._session_call_times[session_id]
            calls.append(now)
            # Keep last 5 minutes
            self._session_call_times[session_id] = [t for t in calls if t > now - 300]
            rate = len([t for t in calls if t > now - 60])
            if rate > 50:
                score += 40
            elif rate > 20:
                score += 15

        # Large output anomaly
        output_size = event.data.get("output_size_bytes", 0)
        if output_size > 100_000:
            score += 40
        elif output_size > 10_000:
            score += 10

        return min(100, score)
