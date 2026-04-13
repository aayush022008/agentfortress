"""Multi-room WebSocket manager — per-org, per-session rooms."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Multi-room WebSocket manager.

    Supports rooms by org_id, session_id, or broadcast to all.

    Usage::

        manager = WebSocketManager()

        # In FastAPI endpoint:
        @app.websocket("/ws/{org_id}")
        async def ws_endpoint(websocket: WebSocket, org_id: str):
            conn_id = await manager.connect(websocket, org_id=org_id)
            try:
                async for msg in manager.receive(conn_id):
                    pass
            finally:
                await manager.disconnect(conn_id)

        # Broadcast from anywhere:
        await manager.broadcast_to_org(org_id, {"type": "alert", "data": alert})
    """

    def __init__(self) -> None:
        # conn_id → WebSocket
        self._connections: Dict[str, WebSocket] = {}
        # conn_id → metadata
        self._metadata: Dict[str, Dict[str, Any]] = {}
        # org_id → set of conn_ids
        self._org_rooms: Dict[str, Set[str]] = defaultdict(set)
        # session_id → set of conn_ids
        self._session_rooms: Dict[str, Set[str]] = defaultdict(set)

    async def connect(
        self,
        websocket: WebSocket,
        org_id: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> str:
        """Accept and register a WebSocket connection. Returns conn_id."""
        await websocket.accept()
        import uuid
        conn_id = str(uuid.uuid4())
        self._connections[conn_id] = websocket
        self._metadata[conn_id] = {
            "org_id": org_id,
            "session_id": session_id,
            "user_id": user_id,
            "connected_at": time.time(),
        }
        if org_id:
            self._org_rooms[org_id].add(conn_id)
        if session_id:
            self._session_rooms[session_id].add(conn_id)
        return conn_id

    async def disconnect(self, conn_id: str) -> None:
        """Disconnect and clean up a connection."""
        meta = self._metadata.pop(conn_id, {})
        self._connections.pop(conn_id, None)
        if meta.get("org_id"):
            self._org_rooms[meta["org_id"]].discard(conn_id)
        if meta.get("session_id"):
            self._session_rooms[meta["session_id"]].discard(conn_id)

    async def send(self, conn_id: str, message: Dict[str, Any]) -> bool:
        """Send a message to a specific connection."""
        ws = self._connections.get(conn_id)
        if not ws:
            return False
        try:
            await ws.send_json(message)
            return True
        except Exception:
            await self.disconnect(conn_id)
            return False

    async def broadcast(self, message: Dict[str, Any]) -> int:
        """Broadcast to all connected clients. Returns count sent."""
        conn_ids = list(self._connections.keys())
        return await self._send_to_many(conn_ids, message)

    async def broadcast_to_org(self, org_id: str, message: Dict[str, Any]) -> int:
        """Broadcast to all connections in an org room."""
        conn_ids = list(self._org_rooms.get(org_id, set()))
        return await self._send_to_many(conn_ids, message)

    async def broadcast_to_session(
        self, session_id: str, message: Dict[str, Any]
    ) -> int:
        """Broadcast to all connections watching a session."""
        conn_ids = list(self._session_rooms.get(session_id, set()))
        return await self._send_to_many(conn_ids, message)

    def connection_count(self) -> int:
        return len(self._connections)

    def org_connection_count(self, org_id: str) -> int:
        return len(self._org_rooms.get(org_id, set()))

    async def receive(self, conn_id: str):
        """Async generator yielding messages from a connection."""
        ws = self._connections.get(conn_id)
        if not ws:
            return
        try:
            while True:
                data = await ws.receive_text()
                yield json.loads(data)
        except Exception:
            pass

    async def _send_to_many(
        self, conn_ids: List[str], message: Dict[str, Any]
    ) -> int:
        tasks = [self.send(cid, message) for cid in conn_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(1 for r in results if r is True)
