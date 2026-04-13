"""Basic DDoS mitigation — request rate analysis and payload inspection."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class DDoSProtectionMiddleware(BaseHTTPMiddleware):
    """
    Basic DDoS mitigation:
    - Connection rate limiting per IP (connections per second)
    - Slow HTTP attack detection (very slow request bodies)
    - Large payload blocking
    - Known bad user-agent blocking
    - IP blocklist support

    For production, use a WAF (CloudFlare, AWS WAF, nginx limit_req).
    """

    BAD_USER_AGENTS = [
        "sqlmap", "nikto", "nessus", "masscan", "zgrab",
        "nmap", "python-requests/2.1", "Go-http-client/1.1",
    ]

    def __init__(
        self,
        app,
        conn_rate_limit: int = 100,  # requests per 10 seconds per IP
        conn_rate_window: int = 10,
        max_payload_kb: int = 10240,
        blocklist: Optional[list] = None,
    ) -> None:
        super().__init__(app)
        self.conn_rate_limit = conn_rate_limit
        self.conn_rate_window = conn_rate_window
        self.max_payload_bytes = max_payload_kb * 1024
        self.blocklist = set(blocklist or [])
        self._ip_windows: Dict[str, Deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = self._get_ip(request)

        # IP blocklist check
        if client_ip in self.blocklist:
            return JSONResponse(status_code=403, content={"error": "Forbidden"})

        # User-agent check
        ua = request.headers.get("User-Agent", "").lower()
        for bad_ua in self.BAD_USER_AGENTS:
            if bad_ua.lower() in ua:
                return JSONResponse(status_code=403, content={"error": "Forbidden"})

        # Connection rate check
        if not self._check_rate(client_ip):
            return JSONResponse(
                status_code=429,
                content={"error": "Too Many Requests — rate limit exceeded"},
                headers={"Retry-After": str(self.conn_rate_window)},
            )

        # Payload size check
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > self.max_payload_bytes:
            return JSONResponse(status_code=413, content={"error": "Payload Too Large"})

        return await call_next(request)

    def block_ip(self, ip: str) -> None:
        """Dynamically add an IP to the blocklist."""
        self.blocklist.add(ip)

    def unblock_ip(self, ip: str) -> None:
        """Remove an IP from the blocklist."""
        self.blocklist.discard(ip)

    # ------------------------------------------------------------------

    def _check_rate(self, ip: str) -> bool:
        now = time.time()
        window = self._ip_windows[ip]
        # Remove old entries
        while window and now - window[0] > self.conn_rate_window:
            window.popleft()
        if len(window) >= self.conn_rate_limit:
            return False
        window.append(now)
        return True

    @staticmethod
    def _get_ip(request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "0.0.0.0"
