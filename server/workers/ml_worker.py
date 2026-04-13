"""Async ML scoring pipeline worker."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class MLWorker:
    """
    Background ML scoring worker.
    Queues sessions for async anomaly detection.

    Usage::

        worker = MLWorker(ml_service)
        worker.on_anomaly(lambda session, score: alert(score))
        await worker.start()
        await worker.score(session)
        await worker.stop()
    """

    def __init__(self, ml_service: Any, threshold: float = 0.7) -> None:
        self._ml = ml_service
        self._threshold = threshold
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._callbacks: List[Callable] = []
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self.scored_count = 0
        self.anomaly_count = 0

    def on_anomaly(self, callback: Callable[[Dict[str, Any], float], None]) -> None:
        """Register callback for anomaly detections."""
        self._callbacks.append(callback)

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        self._running = False
        await self._queue.put(None)
        if self._task:
            await self._task

    async def score(self, session: Dict[str, Any]) -> None:
        """Queue a session for scoring."""
        try:
            self._queue.put_nowait(session)
        except asyncio.QueueFull:
            logger.warning("MLWorker queue full, dropping session %s", session.get("session_id"))

    async def _run(self) -> None:
        while True:
            session = await self._queue.get()
            if session is None:
                self._queue.task_done()
                break
            try:
                result = await self._ml.score_session(session)
                self.scored_count += 1
                score = result.get("combined_score", 0.0)
                if score >= self._threshold:
                    self.anomaly_count += 1
                    for cb in self._callbacks:
                        try:
                            r = cb(session, score)
                            if asyncio.iscoroutine(r):
                                await r
                        except Exception as e:
                            logger.error("MLWorker callback error: %s", e)
            except Exception as e:
                logger.error("MLWorker scoring error: %s", e)
            finally:
                self._queue.task_done()
