"""Scoped API key authentication with expiry and IP restrictions."""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class APIKey:
    """An API key with scope, expiry, and IP restrictions."""

    key_id: str
    key_hash: str
    """SHA-256 hash of the actual key — never store plaintext."""

    name: str
    owner_id: str
    org_id: Optional[str] = None
    scopes: List[str] = field(default_factory=list)
    allowed_ips: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    last_used_at: Optional[float] = None
    enabled: bool = True
    use_count: int = 0

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def to_dict(self) -> Dict:
        return {
            "key_id": self.key_id,
            "name": self.name,
            "owner_id": self.owner_id,
            "org_id": self.org_id,
            "scopes": self.scopes,
            "allowed_ips": self.allowed_ips,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "enabled": self.enabled,
            "use_count": self.use_count,
        }


class APIKeyAuthService:
    """
    Scoped API key authentication.

    Keys are stored as SHA-256 hashes. The actual key is only returned once
    at creation time.

    Usage::

        svc = APIKeyAuthService()
        key, api_key = svc.create_key("Production Key", owner_id="user-123", scopes=["events:write"])
        # Share `key` with the client; store api_key.key_hash

        auth_result = svc.authenticate("as_xxxxxxxxxxxxxxx", client_ip="1.2.3.4")
    """

    KEY_PREFIX = "as_"

    def __init__(self) -> None:
        self._keys: Dict[str, APIKey] = {}  # key_id → APIKey
        self._hash_index: Dict[str, str] = {}  # key_hash → key_id

    def create_key(
        self,
        name: str,
        owner_id: str,
        org_id: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        allowed_ips: Optional[List[str]] = None,
        ttl_days: Optional[int] = None,
    ) -> tuple[str, APIKey]:
        """
        Create a new API key.
        Returns (raw_key, APIKey) — raw_key is shown only once.
        """
        raw = self.KEY_PREFIX + secrets.token_hex(32)
        key_hash = self._hash(raw)

        api_key = APIKey(
            key_id=str(uuid.uuid4()),
            key_hash=key_hash,
            name=name,
            owner_id=owner_id,
            org_id=org_id,
            scopes=scopes or [],
            allowed_ips=allowed_ips or [],
            expires_at=time.time() + ttl_days * 86400 if ttl_days else None,
        )
        self._keys[api_key.key_id] = api_key
        self._hash_index[key_hash] = api_key.key_id
        return raw, api_key

    def authenticate(
        self,
        raw_key: str,
        client_ip: Optional[str] = None,
        required_scope: Optional[str] = None,
    ) -> Optional[APIKey]:
        """
        Authenticate a raw API key.
        Returns APIKey if valid, None otherwise.
        """
        key_hash = self._hash(raw_key)
        key_id = self._hash_index.get(key_hash)
        if not key_id:
            return None

        api_key = self._keys.get(key_id)
        if not api_key:
            return None
        if not api_key.enabled:
            return None
        if api_key.is_expired:
            return None

        # IP restriction check
        if api_key.allowed_ips and client_ip:
            if not self._ip_allowed(client_ip, api_key.allowed_ips):
                return None

        # Scope check
        if required_scope and not self._has_scope(api_key, required_scope):
            return None

        api_key.last_used_at = time.time()
        api_key.use_count += 1
        return api_key

    def revoke_key(self, key_id: str) -> bool:
        api_key = self._keys.get(key_id)
        if not api_key:
            return False
        self._hash_index.pop(api_key.key_hash, None)
        del self._keys[key_id]
        return True

    def list_keys(self, owner_id: Optional[str] = None, org_id: Optional[str] = None) -> List[APIKey]:
        keys = list(self._keys.values())
        if owner_id:
            keys = [k for k in keys if k.owner_id == owner_id]
        if org_id:
            keys = [k for k in keys if k.org_id == org_id]
        return keys

    # ------------------------------------------------------------------

    @staticmethod
    def _hash(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    @staticmethod
    def _ip_allowed(client_ip: str, allowed: List[str]) -> bool:
        try:
            addr = ipaddress.ip_address(client_ip)
            for entry in allowed:
                try:
                    if "/" in entry:
                        if addr in ipaddress.ip_network(entry, strict=False):
                            return True
                    elif addr == ipaddress.ip_address(entry):
                        return True
                except ValueError:
                    if client_ip == entry:
                        return True
        except ValueError:
            pass
        return False

    @staticmethod
    def _has_scope(api_key: APIKey, required: str) -> bool:
        import fnmatch
        for scope in api_key.scopes:
            if scope == "*" or fnmatch.fnmatch(required, scope):
                return True
        return False
