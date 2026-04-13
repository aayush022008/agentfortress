"""
Honeytoken manager — inject fake credentials into agent context and alert when accessed.
"""
from __future__ import annotations

import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Honeytoken:
    """A fake credential or secret injected as a trap."""

    token_id: str
    token_type: str  # api_key | password | jwt | aws_key | github_token
    value: str
    description: str
    created_at: float = field(default_factory=time.time)
    accessed: bool = False
    access_count: int = 0
    last_accessed_at: Optional[float] = None
    access_log: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "token_type": self.token_type,
            "value": self.value,
            "description": self.description,
            "accessed": self.accessed,
            "access_count": self.access_count,
        }


# Fake credential templates that look real to an agent
_GENERATORS = {
    "api_key": lambda: f"sk-{''.join(os.urandom(24).hex()[:48])}",
    "aws_access_key": lambda: f"AKIA{''.join(os.urandom(8).hex().upper()[:16])}",
    "aws_secret_key": lambda: os.urandom(20).hex() + os.urandom(20).hex(),
    "github_token": lambda: f"ghp_{''.join(os.urandom(18).hex()[:36])}",
    "stripe_key": lambda: f"sk_live_{''.join(os.urandom(18).hex()[:36])}",
    "jwt": lambda: (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        + os.urandom(32).hex()
        + "."
        + os.urandom(32).hex()
    ),
    "password": lambda: (
        "P@ssw0rd!"
        + os.urandom(4).hex().upper()
    ),
    "database_url": lambda: f"postgresql://admin:{os.urandom(8).hex()}@db.internal:5432/production",
}


class HoneytokenManager:
    """
    Manages honeytokens — fake credentials injected into agent context.

    When an agent accesses or attempts to use a honeytoken, an alert fires.

    Usage::

        mgr = HoneytokenManager()
        mgr.on_access(lambda ht, ctx: alert(f"Honeytoken accessed: {ht.token_type}"))

        # Create tokens
        api_key = mgr.create("api_key")
        aws_key = mgr.create("aws_access_key")

        # Inject into agent prompt/context
        context = mgr.inject_into_text("Here are your credentials:\n" + mgr.context_block())

        # Check if any token was used
        findings = mgr.scan_text(agent_output)
    """

    def __init__(self) -> None:
        self._tokens: Dict[str, Honeytoken] = {}
        self._callbacks: List[Callable[[Honeytoken, Dict[str, Any]], None]] = []

    def on_access(self, callback: Callable[[Honeytoken, Dict[str, Any]], None]) -> None:
        """Register a callback called whenever a honeytoken is detected in use."""
        self._callbacks.append(callback)

    def create(
        self,
        token_type: str = "api_key",
        description: str = "",
    ) -> Honeytoken:
        """Create and register a new honeytoken."""
        if token_type not in _GENERATORS:
            raise ValueError(f"Unknown token type: {token_type}. Available: {list(_GENERATORS)}")
        value = _GENERATORS[token_type]()
        ht = Honeytoken(
            token_id=str(uuid.uuid4()),
            token_type=token_type,
            value=value,
            description=description or f"Fake {token_type} honeytoken",
        )
        self._tokens[ht.token_id] = ht
        # Also index by value for fast lookup
        self._value_index: Dict[str, str] = getattr(self, "_value_index", {})
        self._value_index[value] = ht.token_id
        return ht

    def create_all(self) -> List[Honeytoken]:
        """Create one honeytoken of each known type."""
        return [self.create(t) for t in _GENERATORS]

    def context_block(self) -> str:
        """
        Return a text block containing all active honeytokens,
        formatted as if they were real credentials.
        """
        lines = []
        for ht in self._tokens.values():
            if ht.token_type == "api_key":
                lines.append(f"OPENAI_API_KEY={ht.value}")
            elif ht.token_type == "aws_access_key":
                lines.append(f"AWS_ACCESS_KEY_ID={ht.value}")
            elif ht.token_type == "aws_secret_key":
                lines.append(f"AWS_SECRET_ACCESS_KEY={ht.value}")
            elif ht.token_type == "github_token":
                lines.append(f"GITHUB_TOKEN={ht.value}")
            elif ht.token_type == "stripe_key":
                lines.append(f"STRIPE_SECRET_KEY={ht.value}")
            else:
                lines.append(f"{ht.token_type.upper()}={ht.value}")
        return "\n".join(lines)

    def scan_text(self, text: str) -> List[Honeytoken]:
        """
        Scan text for any honeytoken values.
        Returns list of accessed honeytokens and fires callbacks.
        """
        index = getattr(self, "_value_index", {})
        found: List[Honeytoken] = []
        for value, token_id in index.items():
            if value in text:
                ht = self._tokens[token_id]
                ht.accessed = True
                ht.access_count += 1
                ht.last_accessed_at = time.time()
                ht.access_log.append({"detected_in": text[:200], "at": time.time()})
                found.append(ht)
                self._fire_callbacks(ht, {"detected_in_text": True})
        return found

    def list_tokens(self) -> List[Honeytoken]:
        return list(self._tokens.values())

    def get_accessed(self) -> List[Honeytoken]:
        return [ht for ht in self._tokens.values() if ht.accessed]

    # ------------------------------------------------------------------

    def _fire_callbacks(self, ht: Honeytoken, ctx: Dict[str, Any]) -> None:
        for cb in self._callbacks:
            try:
                cb(ht, ctx)
            except Exception:
                pass
