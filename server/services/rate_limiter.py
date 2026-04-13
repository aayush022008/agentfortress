"""Redis-backed rate limiter."""
from __future__ import annotations

import time
from typing import Optional


class RateLimiter:
    """
    Redis-backed rate limiter using a sliding window algorithm.

    Usage::

        limiter = RateLimiter(redis_url="redis://localhost:6379")
        await limiter.setup()
        allowed, remaining = await limiter.check("org:my-org", limit=1000, window=60)
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self._redis_url = redis_url
        self._redis = None

    async def setup(self) -> None:
        """Connect to Redis."""
        if not self._redis_url:
            return
        try:
            import redis.asyncio as aioredis
            self._redis = await aioredis.from_url(self._redis_url, decode_responses=True)
        except ImportError:
            pass

    async def check(
        self,
        key: str,
        limit: int,
        window: int = 60,
    ) -> tuple[bool, int]:
        """
        Check rate limit using sliding window.
        Returns (allowed, remaining).
        """
        if not self._redis:
            return True, limit

        import redis.asyncio as aioredis
        now = time.time()
        pipe = self._redis.pipeline()
        rate_key = f"rl:{key}"

        # Remove old entries outside window
        pipe.zremrangebyscore(rate_key, 0, now - window)
        # Count entries in window
        pipe.zcard(rate_key)
        # Add current request
        pipe.zadd(rate_key, {f"{now}": now})
        # Set TTL
        pipe.expire(rate_key, window)

        results = await pipe.execute()
        current_count = results[1]

        if current_count >= limit:
            return False, 0
        return True, limit - current_count - 1

    async def reset(self, key: str) -> None:
        """Reset the rate limit counter for a key."""
        if self._redis:
            await self._redis.delete(f"rl:{key}")

    async def close(self) -> None:
        if self._redis:
            await self._redis.close()
