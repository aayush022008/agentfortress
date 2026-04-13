"""Request logging middleware."""

from __future__ import annotations

import logging
import time

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("agentshield.requests")


class LoggingMiddleware(BaseHTTPMiddleware):
    """Logs all incoming requests with timing."""

    async def dispatch(self, request: Request, call_next: any) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = (time.monotonic() - start) * 1000
        logger.info(
            f"{request.method} {request.url.path} "
            f"→ {response.status_code} "
            f"({duration_ms:.1f}ms)"
        )
        return response
