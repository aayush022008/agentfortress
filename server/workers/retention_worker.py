"""Data retention and cleanup worker."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)


class RetentionWorker:
    """Runs retention policy enforcement on a schedule."""

    def __init__(
        self,
        retention_service: Any,
        interval_seconds: int = 3600,
    ) -> None:
        self._svc = retention_service
        self._interval = interval_seconds
        self._task: Optional[asyncio.Task] = None
        self._running = False

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

    async def run_once(self) -> dict:
        return await self._svc.enforce_all()

    async def _run(self) -> None:
        while self._running:
            try:
                results = await self._svc.enforce_all()
                logger.info("Retention enforcement complete: %s", results)
            except Exception as e:
                logger.error("RetentionWorker error: %s", e)
            await asyncio.sleep(self._interval)
