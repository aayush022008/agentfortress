"""Scheduled threat hunt execution worker."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class HuntWorker:
    """
    Executes scheduled threat hunts at configured intervals.
    Parses cron-like schedules and runs hunts against recent events.
    """

    def __init__(
        self,
        hunter_service: Any,
        event_fetcher: Any,  # callable that returns recent events
        check_interval: int = 60,
    ) -> None:
        self._hunter = hunter_service
        self._event_fetcher = event_fetcher
        self._check_interval = check_interval
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._run_log: List[Dict[str, Any]] = []

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        while self._running:
            await self._check_scheduled_hunts()
            await asyncio.sleep(self._check_interval)

    async def _check_scheduled_hunts(self) -> None:
        hunts = self._hunter.list_hunts(enabled_only=True)
        now = time.time()
        for hunt in hunts:
            if not hunt.schedule:
                continue
            if self._should_run(hunt, now):
                try:
                    events = await self._event_fetcher()
                    result = self._hunter.run_hunt(hunt.hunt_id, events)
                    if result and result.total_matches > 0:
                        logger.warning(
                            "Hunt '%s' found %d matches", hunt.name, result.total_matches
                        )
                    self._run_log.append({
                        "hunt_id": hunt.hunt_id,
                        "ran_at": now,
                        "matches": result.total_matches if result else 0,
                    })
                except Exception as e:
                    logger.error("Hunt execution error '%s': %s", hunt.name, e)

    def _should_run(self, hunt: Any, now: float) -> bool:
        """Determine if a hunt should run now based on its schedule."""
        if not hunt.last_run_at:
            return True

        schedule = hunt.schedule
        # Simple interval parsing: "@hourly", "@daily", "every_Nh"
        if schedule == "@hourly" and now - hunt.last_run_at > 3600:
            return True
        if schedule == "@daily" and now - hunt.last_run_at > 86400:
            return True
        if schedule.startswith("every_") and schedule.endswith("h"):
            try:
                hours = int(schedule[6:-1])
                return now - hunt.last_run_at > hours * 3600
            except ValueError:
                pass
        return False

    def get_run_log(self) -> List[Dict[str, Any]]:
        return list(self._run_log[-100:])
