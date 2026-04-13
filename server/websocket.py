"""
WebSocket handler for real-time dashboard updates.

Broadcasts agent events to all connected dashboard clients.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)
router = APIRouter()

# Connected WebSocket clients
_clients: set[WebSocket] = set()
_lock = asyncio.Lock()


@router.websocket("/events")
async def websocket_events(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time event streaming."""
    await websocket.accept()
    async with _lock:
        _clients.add(websocket)
    logger.info(f"WebSocket client connected. Total: {len(_clients)}")

    try:
        # Keep connection alive and handle ping/pong
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send keepalive
                await websocket.send_text(json.dumps({"type": "keepalive"}))
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug(f"WebSocket error: {e}")
    finally:
        async with _lock:
            _clients.discard(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(_clients)}")


async def broadcast_event(data: dict[str, Any]) -> None:
    """Broadcast an event to all connected WebSocket clients."""
    if not _clients:
        return

    message = json.dumps(data)
    disconnected: set[WebSocket] = set()

    async with _lock:
        clients_snapshot = set(_clients)

    for client in clients_snapshot:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.add(client)

    if disconnected:
        async with _lock:
            _clients.difference_update(disconnected)
