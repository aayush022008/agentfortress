"""Server-side session management."""
from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ServerSession:
    session_id: str
    user_id: str
    org_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_active_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    valid: bool = True

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def refresh(self, ttl: int = 3600) -> None:
        self.last_active_at = time.time()
        self.expires_at = time.time() + ttl

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "org_id": self.org_id,
            "created_at": self.created_at,
            "last_active_at": self.last_active_at,
            "expires_at": self.expires_at,
        }


class SessionManager:
    """
    Server-side session management.
    Sessions are stored in memory (production: use Redis).
    """

    SESSION_TTL = 3600  # 1 hour

    def __init__(self) -> None:
        self._sessions: Dict[str, ServerSession] = {}

    def create(
        self,
        user_id: str,
        org_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> ServerSession:
        session = ServerSession(
            session_id=secrets.token_hex(32),
            user_id=user_id,
            org_id=org_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=time.time() + (ttl or self.SESSION_TTL),
        )
        self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> Optional[ServerSession]:
        session = self._sessions.get(session_id)
        if session and session.is_expired:
            del self._sessions[session_id]
            return None
        return session

    def validate(self, session_id: str) -> Optional[ServerSession]:
        """Validate session and refresh activity timestamp."""
        session = self.get(session_id)
        if session:
            session.last_active_at = time.time()
        return session

    def invalidate(self, session_id: str) -> bool:
        session = self._sessions.pop(session_id, None)
        return session is not None

    def invalidate_user_sessions(self, user_id: str) -> int:
        """Invalidate all sessions for a user. Returns count."""
        to_remove = [sid for sid, s in self._sessions.items() if s.user_id == user_id]
        for sid in to_remove:
            del self._sessions[sid]
        return len(to_remove)

    def list_user_sessions(self, user_id: str) -> List[ServerSession]:
        return [s for s in self._sessions.values() if s.user_id == user_id and not s.is_expired]

    def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns count removed."""
        expired = [sid for sid, s in self._sessions.items() if s.is_expired]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)

    def active_count(self) -> int:
        return sum(1 for s in self._sessions.values() if not s.is_expired)
