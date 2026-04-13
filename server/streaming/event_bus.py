"""Internal pub/sub event bus."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


class EventBus:
    """
    In-process async pub/sub event bus.

    Usage::

        bus = EventBus()
        bus.subscribe("alert.created", handle_alert)
        await bus.publish("alert.created", alert_data)
    """

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callable]] = {}

    def subscribe(
        self,
        topic: str,
        handler: Callable[..., Coroutine[Any, Any, None]],
    ) -> None:
        """Subscribe to a topic."""
        self._subscribers.setdefault(topic, []).append(handler)

    def unsubscribe(self, topic: str, handler: Callable) -> bool:
        """Unsubscribe from a topic. Returns True if removed."""
        handlers = self._subscribers.get(topic, [])
        try:
            handlers.remove(handler)
            return True
        except ValueError:
            return False

    async def publish(self, topic: str, payload: Any) -> int:
        """
        Publish an event to all subscribers of *topic*.
        Returns number of handlers called.
        Also publishes to wildcard subscribers (e.g., 'alert.*' matches 'alert.created').
        """
        handlers = list(self._subscribers.get(topic, []))

        # Check wildcard subscribers
        for pattern, pattern_handlers in self._subscribers.items():
            if "*" in pattern:
                import fnmatch
                if fnmatch.fnmatch(topic, pattern) and pattern != topic:
                    handlers.extend(pattern_handlers)

        if not handlers:
            return 0

        tasks = []
        for handler in handlers:
            try:
                tasks.append(asyncio.ensure_future(handler(payload)))
            except Exception as e:
                logger.error("EventBus dispatch error on topic %s: %s", topic, e)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    logger.error("EventBus handler error on topic %s: %s", topic, r)

        return len(handlers)

    def publish_sync(self, topic: str, payload: Any) -> None:
        """Fire-and-forget version for non-async contexts."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self.publish(topic, payload))
            else:
                loop.run_until_complete(self.publish(topic, payload))
        except Exception as e:
            logger.error("EventBus sync publish error: %s", e)

    def list_topics(self) -> List[str]:
        return list(self._subscribers.keys())

    def subscriber_count(self, topic: str) -> int:
        return len(self._subscribers.get(topic, []))


# Global event bus instance
global_bus = EventBus()
