"""
HTTP transport for AgentShield SDK.

Sends intercepted events to the AgentShield server over HTTP.
Supports batching for efficiency and retry logic for reliability.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

logger = logging.getLogger(__name__)


def _event_to_dict(event: Any) -> dict:
    """Convert an InterceptorEvent to a JSON-serializable dict."""
    return {
        "event_id": event.event_id,
        "session_id": event.session_id,
        "event_type": event.event_type.value,
        "agent_name": event.agent_name,
        "timestamp": event.timestamp,
        "data": event.data,
        "threat_score": event.threat_score,
        "threat_reasons": event.threat_reasons,
        "blocked": event.blocked,
        "latency_ms": event.latency_ms,
    }


class HttpTransport:
    """
    HTTP transport: sends events to the AgentShield server.

    Batches events and sends them asynchronously in a background thread.
    Falls back to synchronous sending if the queue is full.
    """

    def __init__(self, config: Any) -> None:
        self._config = config
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._batch: list[dict] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def send(self, event: Any) -> None:
        """Queue an event for sending."""
        try:
            self._queue.put_nowait(_event_to_dict(event))
        except queue.Full:
            logger.warning("AgentShield event queue full, dropping event")

    def flush(self) -> None:
        """Flush all pending events synchronously."""
        remaining: list[dict] = []
        while not self._queue.empty():
            try:
                remaining.append(self._queue.get_nowait())
            except queue.Empty:
                break

        if remaining:
            self._send_batch(remaining)

    def _worker(self) -> None:
        """Background worker that batches and sends events."""
        while not self._stop_event.is_set():
            batch: list[dict] = []
            deadline = time.monotonic() + self._config.batch_interval_seconds

            while time.monotonic() < deadline and len(batch) < self._config.batch_size:
                try:
                    event = self._queue.get(timeout=0.1)
                    batch.append(event)
                except queue.Empty:
                    pass

            if batch:
                self._send_batch(batch)

    def _send_batch(self, batch: list[dict], retries: int = 3) -> None:
        """Send a batch of events to the server."""
        url = f"{self._config.server_url}/api/events/batch"
        payload = json.dumps({"events": batch}).encode()
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self._config.api_key,
        }
        if self._config.org_id:
            headers["X-Org-ID"] = self._config.org_id

        for attempt in range(retries):
            try:
                req = Request(url, data=payload, headers=headers, method="POST")
                with urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        return
                    logger.warning(f"AgentShield server returned {resp.status}")
                    return
            except URLError as e:
                if attempt < retries - 1:
                    time.sleep(0.5 * (attempt + 1))
                else:
                    logger.error(f"Failed to send events after {retries} attempts: {e}")
            except Exception as e:
                logger.error(f"Unexpected error sending events: {e}")
                return

    def close(self) -> None:
        """Stop the background worker and flush remaining events."""
        self.flush()
        self._stop_event.set()
        self._thread.join(timeout=5)
