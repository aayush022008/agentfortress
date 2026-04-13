"""Server-Sent Events (SSE) as WebSocket alternative."""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/api/stream", tags=["streaming"])


async def event_stream(
    queue: asyncio.Queue,
    heartbeat_interval: float = 30.0,
) -> AsyncGenerator[str, None]:
    """
    Async generator that yields SSE-formatted events from a queue.
    Sends heartbeat comments to keep connections alive.
    """
    last_heartbeat = time.time()
    while True:
        try:
            try:
                data = await asyncio.wait_for(queue.get(), timeout=1.0)
                if data is None:
                    break
                yield f"data: {json.dumps(data, default=str)}\n\n"
            except asyncio.TimeoutError:
                pass

            # Heartbeat
            if time.time() - last_heartbeat > heartbeat_interval:
                yield ": heartbeat\n\n"
                last_heartbeat = time.time()
        except asyncio.CancelledError:
            break
        except Exception:
            break


@router.get("/events")
async def sse_events(
    request: Request,
    org_id: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
) -> StreamingResponse:
    """
    Server-Sent Events stream for real-time alert/event notifications.
    Clients subscribe to this endpoint and receive events as they occur.
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)

    async def generator():
        yield ": connected\n\n"
        async for chunk in event_stream(queue):
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
