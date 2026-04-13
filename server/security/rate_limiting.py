"""Multi-tier rate limiting middleware."""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Callable, Dict, Optional, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Multi-tier rate limiting: per-IP, per-org, per-endpoint.
    Uses sliding window counters (in-memory; replace with Redis for production).
    """

    DEFAULT_LIMITS: Dict[str, Tuple[int, int]] = {
        # endpoint_prefix → (requests, window_seconds)
        "/api/events": (10000, 60),
        "/api/auth": (20, 60),
        "/api/": (500, 60),
    }

    def __init__(
        self,
        app,
        per_ip_limit: int = 1000,
        per_ip_window: int = 60,
        per_org_limit: int = 10000,
        per_org_window: int = 60,
        custom_limits: Optional[Dict[str, Tuple[int, int]]] = None,
    ) -> None:
        super().__init__(app)
        self.per_ip_limit = per_ip_limit
        self.per_ip_window = per_ip_window
        self.per_org_limit = per_org_limit
        self.per_org_window = per_org_window
        self.custom_limits = custom_limits or {}
        self._counters: Dict[str, list] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = self._get_client_ip(request)
        org_id = request.headers.get("X-Org-ID") or request.query_params.get("org_id")
        path = request.url.path

        # Per-IP check
        if not self._check(f"ip:{client_ip}", self.per_ip_limit, self.per_ip_window):
            return self._rate_limited(f"Rate limit exceeded for IP {client_ip}")

        # Per-org check
        if org_id:
            if not self._check(f"org:{org_id}", self.per_org_limit, self.per_org_window):
                return self._rate_limited(f"Rate limit exceeded for org {org_id}")

        # Per-endpoint check
        for prefix, (limit, window) in self.custom_limits.items():
            if path.startswith(prefix):
                if not self._check(f"ep:{client_ip}:{prefix}", limit, window):
                    return self._rate_limited(f"Rate limit exceeded for {prefix}")
                break

        response = await call_next(request)

        # Add rate limit headers
        remaining = self._remaining(f"ip:{client_ip}", self.per_ip_limit, self.per_ip_window)
        response.headers["X-RateLimit-Limit"] = str(self.per_ip_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Window"] = str(self.per_ip_window)

        return response

    def _check(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        timestamps = self._counters[key]
        # Remove old entries
        self._counters[key] = [t for t in timestamps if now - t < window]
        if len(self._counters[key]) >= limit:
            return False
        self._counters[key].append(now)
        return True

    def _remaining(self, key: str, limit: int, window: int) -> int:
        now = time.time()
        count = sum(1 for t in self._counters.get(key, []) if now - t < window)
        return limit - count

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    @staticmethod
    def _rate_limited(detail: str) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"error": "Too Many Requests", "detail": detail},
            headers={"Retry-After": "60"},
        )
