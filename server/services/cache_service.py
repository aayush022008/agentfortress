"""Redis caching layer."""
from __future__ import annotations

import json
from typing import Any, Optional


class CacheService:
    """
    Redis caching layer with JSON serialization and TTL support.

    Falls back to an in-memory dict if Redis is not configured.
    """

    def __init__(self, redis_url: Optional[str] = None, default_ttl: int = 300) -> None:
        self._redis_url = redis_url
        self._default_ttl = default_ttl
        self._redis = None
        self._local: dict = {}

    async def setup(self) -> None:
        if not self._redis_url:
            return
        try:
            import redis.asyncio as aioredis
            self._redis = await aioredis.from_url(self._redis_url, decode_responses=True)
        except ImportError:
            pass

    async def get(self, key: str) -> Optional[Any]:
        """Get a cached value. Returns None on cache miss."""
        if self._redis:
            val = await self._redis.get(key)
            if val is not None:
                return json.loads(val)
        else:
            entry = self._local.get(key)
            if entry:
                import time
                if entry["expires_at"] > time.time():
                    return entry["value"]
                del self._local[key]
        return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a cached value with optional TTL (seconds)."""
        ttl = ttl or self._default_ttl
        if self._redis:
            await self._redis.setex(key, ttl, json.dumps(value, default=str))
        else:
            import time
            self._local[key] = {"value": value, "expires_at": time.time() + ttl}

    async def delete(self, key: str) -> None:
        """Delete a cached value."""
        if self._redis:
            await self._redis.delete(key)
        else:
            self._local.pop(key, None)

    async def exists(self, key: str) -> bool:
        if self._redis:
            return bool(await self._redis.exists(key))
        return key in self._local

    async def flush_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern."""
        if self._redis:
            keys = await self._redis.keys(pattern)
            if keys:
                return await self._redis.delete(*keys)
        return 0

    async def close(self) -> None:
        if self._redis:
            await self._redis.close()
