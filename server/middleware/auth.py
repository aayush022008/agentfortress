"""Auth middleware for AgentShield server."""

from __future__ import annotations

import hashlib
import logging

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..config import settings

logger = logging.getLogger(__name__)

# Public paths that don't require auth
PUBLIC_PATHS = {"/", "/health", "/docs", "/redoc", "/openapi.json", "/ws/events"}


class AuthMiddleware(BaseHTTPMiddleware):
    """Validates API key on all non-public endpoints."""

    async def dispatch(self, request: Request, call_next: any) -> Response:
        path = request.url.path
        if path in PUBLIC_PATHS or path.startswith("/ws/"):
            return await call_next(request)

        api_key = request.headers.get(settings.api_key_header)
        if not api_key:
            return Response(
                content='{"detail": "API key required"}',
                status_code=401,
                media_type="application/json",
            )

        # Check admin key
        if api_key == settings.admin_api_key:
            return await call_next(request)

        # In a full implementation, check DB for valid API keys
        # For now, accept any non-empty key in dev mode
        if settings.debug:
            return await call_next(request)

        return Response(
            content='{"detail": "Invalid API key"}',
            status_code=403,
            media_type="application/json",
        )
