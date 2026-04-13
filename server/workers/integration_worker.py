"""Async integration notification dispatch worker."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class IntegrationWorker:
    """Dispatches notifications to integrations asynchronously."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._integrations: Dict[str, Any] = {}
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self.dispatched_count = 0
        self.error_count = 0

    def register_integration(self, name: str, handler: Any) -> None:
        self._integrations[name] = handler

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        self._running = False
        await self._queue.put(None)
        if self._task:
            await self._task

    async def dispatch(self, event: Dict[str, Any], targets: Optional[List[str]] = None) -> None:
        """Queue an event for dispatch to all (or specified) integrations."""
        await self._queue.put({"event": event, "targets": targets})

    async def _run(self) -> None:
        while True:
            item = await self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            try:
                event = item["event"]
                targets = item.get("targets") or list(self._integrations.keys())
                for name in targets:
                    handler = self._integrations.get(name)
                    if not handler:
                        continue
                    try:
                        if hasattr(handler, "post_alert"):
                            await asyncio.to_thread(handler.post_alert, event)
                        elif hasattr(handler, "send_event"):
                            await asyncio.to_thread(handler.send_event, event)
                        elif hasattr(handler, "trigger"):
                            await asyncio.to_thread(handler.trigger, event)
                        self.dispatched_count += 1
                    except Exception as e:
                        self.error_count += 1
                        logger.error("Integration dispatch error (%s): %s", name, e)
            except Exception as e:
                logger.error("IntegrationWorker error: %s", e)
            finally:
                self._queue.task_done()
