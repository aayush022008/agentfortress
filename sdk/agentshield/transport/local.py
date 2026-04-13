"""
Local transport for AgentShield SDK (offline mode).

Writes events to a local SQLite database when no server is available.
Allows offline operation and later replay/sync to server.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

LOCAL_DB_PATH = "agentshield-local.db"


def _event_to_dict(event: Any) -> dict:
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


class LocalTransport:
    """
    Local SQLite transport for offline operation.

    Stores all events in a local SQLite database file.
    Provides methods for querying and exporting stored events.
    """

    def __init__(self, config: Any) -> None:
        self._config = config
        db_path = getattr(config, "local_db_path", LOCAL_DB_PATH)
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database schema."""
        with self._lock:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    agent_name TEXT,
                    timestamp REAL NOT NULL,
                    data TEXT,
                    threat_score INTEGER DEFAULT 0,
                    threat_reasons TEXT,
                    blocked INTEGER DEFAULT 0,
                    latency_ms REAL,
                    synced INTEGER DEFAULT 0
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_session ON events(session_id)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)"
            )
            self._conn.commit()

    def send(self, event: Any) -> None:
        """Store an event in the local database."""
        d = _event_to_dict(event)
        with self._lock:
            if self._conn is None:
                return
            try:
                self._conn.execute(
                    """INSERT OR REPLACE INTO events
                    (event_id, session_id, event_type, agent_name, timestamp,
                     data, threat_score, threat_reasons, blocked, latency_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        d["event_id"],
                        d["session_id"],
                        d["event_type"],
                        d["agent_name"],
                        d["timestamp"],
                        json.dumps(d["data"]),
                        d["threat_score"],
                        json.dumps(d["threat_reasons"]),
                        1 if d["blocked"] else 0,
                        d["latency_ms"],
                    ),
                )
                self._conn.commit()
            except sqlite3.Error as e:
                logger.error(f"LocalTransport DB error: {e}")

    def flush(self) -> None:
        """No-op for local transport (writes are synchronous)."""
        pass

    def get_events(
        self,
        session_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        since_timestamp: Optional[float] = None,
    ) -> list[dict]:
        """
        Query stored events.

        Args:
            session_id: Filter by session ID
            limit: Maximum number of events to return
            offset: Pagination offset
            since_timestamp: Only return events after this timestamp

        Returns:
            List of event dicts
        """
        with self._lock:
            if self._conn is None:
                return []
            query = "SELECT * FROM events WHERE 1=1"
            params: list[Any] = []
            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)
            if since_timestamp:
                query += " AND timestamp > ?"
                params.append(since_timestamp)
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = self._conn.execute(query, params)
            rows = cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            result = []
            for row in rows:
                d = dict(zip(cols, row))
                d["data"] = json.loads(d["data"] or "{}")
                d["threat_reasons"] = json.loads(d["threat_reasons"] or "[]")
                result.append(d)
            return result

    def get_unsynced_events(self, limit: int = 100) -> list[dict]:
        """Get events that haven't been synced to the server."""
        with self._lock:
            if self._conn is None:
                return []
            cursor = self._conn.execute(
                "SELECT * FROM events WHERE synced = 0 ORDER BY timestamp ASC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            result = []
            for row in rows:
                d = dict(zip(cols, row))
                d["data"] = json.loads(d["data"] or "{}")
                d["threat_reasons"] = json.loads(d["threat_reasons"] or "[]")
                result.append(d)
            return result

    def mark_synced(self, event_ids: list[str]) -> None:
        """Mark events as synced to the server."""
        if not event_ids:
            return
        with self._lock:
            if self._conn is None:
                return
            placeholders = ",".join("?" * len(event_ids))
            self._conn.execute(
                f"UPDATE events SET synced = 1 WHERE event_id IN ({placeholders})",
                event_ids,
            )
            self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
