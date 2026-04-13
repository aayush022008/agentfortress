"""Async alert processing worker — dedup, escalation, notification dispatch."""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AlertDedup:
    """Deduplication state for alerts."""
    alert_type: str
    agent_id: Optional[str]
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    count: int = 1
    suppressed_count: int = 0


class AlertWorker:
    """
    Background worker for async alert processing.
    - Deduplicates repeated alerts (same type+agent within window)
    - Escalates repeated alerts to higher severity
    - Dispatches notifications to configured integrations

    Usage::

        worker = AlertWorker()
        await worker.start()
        await worker.process(alert)
        await worker.stop()
    """

    DEDUP_WINDOW = 300  # 5 minutes
    ESCALATION_THRESHOLD = 3  # escalate after 3 occurrences

    def __init__(self) -> None:
        self._queue: asyncio.Queue = asyncio.Queue()
        self._dedup: Dict[str, AlertDedup] = {}
        self._handlers: List[Any] = []  # integration handlers
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def add_handler(self, handler: Any) -> None:
        """Add an integration handler (e.g., SlackIntegration)."""
        self._handlers.append(handler)

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        self._running = False
        await self._queue.put(None)
        if self._task:
            await self._task

    async def process(self, alert: Dict[str, Any]) -> None:
        """Queue an alert for processing."""
        await self._queue.put(alert)

    # ------------------------------------------------------------------

    async def _run(self) -> None:
        while True:
            alert = await self._queue.get()
            if alert is None:
                self._queue.task_done()
                break
            try:
                await self._handle_alert(alert)
            except Exception as e:
                logger.error("AlertWorker error: %s", e)
            finally:
                self._queue.task_done()

    async def _handle_alert(self, alert: Dict[str, Any]) -> None:
        dedup_key = f"{alert.get('alert_type', '')}:{alert.get('agent_id', '')}"
        now = time.time()

        # Cleanup expired dedup entries
        expired = [k for k, v in self._dedup.items() if now - v.last_seen > self.DEDUP_WINDOW]
        for k in expired:
            del self._dedup[k]

        if dedup_key in self._dedup:
            entry = self._dedup[dedup_key]
            entry.last_seen = now
            entry.count += 1

            # Suppress if within dedup window and not first occurrence
            if entry.count > 1:
                entry.suppressed_count += 1
                logger.debug("Alert suppressed (dedup): %s (count=%d)", dedup_key, entry.count)

                # Escalate on repeated alerts
                if entry.count == self.ESCALATION_THRESHOLD:
                    await self._escalate(alert, entry)
                return
        else:
            self._dedup[dedup_key] = AlertDedup(
                alert_type=alert.get("alert_type", ""),
                agent_id=alert.get("agent_id"),
            )

        await self._dispatch(alert)

    async def _escalate(self, alert: Dict[str, Any], entry: AlertDedup) -> None:
        """Escalate repeated alert to higher severity."""
        sev_order = ["info", "low", "medium", "high", "critical"]
        current_sev = alert.get("severity", "medium").lower()
        idx = sev_order.index(current_sev) if current_sev in sev_order else 2
        escalated_sev = sev_order[min(idx + 1, len(sev_order) - 1)]

        escalated = dict(alert)
        escalated["severity"] = escalated_sev
        escalated["title"] = f"[ESCALATED] {alert.get('title', '')}"
        escalated["description"] = (
            f"Alert repeated {entry.count}x in {self.DEDUP_WINDOW}s. "
            + alert.get("description", "")
        )
        logger.warning("Alert escalated: %s → %s", current_sev, escalated_sev)
        await self._dispatch(escalated)

    async def _dispatch(self, alert: Dict[str, Any]) -> None:
        """Send alert to all registered integration handlers."""
        for handler in self._handlers:
            try:
                if hasattr(handler, "post_alert"):
                    await asyncio.to_thread(handler.post_alert, alert)
                elif hasattr(handler, "trigger"):
                    await asyncio.to_thread(handler.trigger, alert)
                elif hasattr(handler, "send_alert"):
                    await asyncio.to_thread(handler.send_alert, alert)
                elif callable(handler):
                    result = handler(alert)
                    if asyncio.iscoroutine(result):
                        await result
            except Exception as e:
                logger.error("Alert dispatch error (%s): %s", type(handler).__name__, e)
