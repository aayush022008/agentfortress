"""Deep input sanitization and payload size limits."""
from __future__ import annotations

import html
import json
import re
from typing import Any, Dict, List, Optional, Union

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_STRING_LENGTH = 100_000
MAX_ARRAY_LENGTH = 10_000
MAX_OBJECT_DEPTH = 20

_SQL_INJECTION_PATTERNS = [
    re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE)\b)", re.IGNORECASE),
    re.compile(r"(--|;|/\*|\*/)"),
    re.compile(r"(xp_cmdshell|sp_executesql)", re.IGNORECASE),
]

_XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"<iframe", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
]

_COMMAND_INJECTION_PATTERNS = [
    re.compile(r"[;&|`$]"),
    re.compile(r"\$\("),
    re.compile(r"`[^`]+`"),
]


def sanitize_string(value: str, allow_html: bool = False) -> str:
    """Sanitize a string value."""
    if not allow_html:
        value = html.escape(value)
    if len(value) > MAX_STRING_LENGTH:
        value = value[:MAX_STRING_LENGTH]
    return value


def detect_sql_injection(text: str) -> bool:
    """Return True if text contains SQL injection patterns."""
    for pattern in _SQL_INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def detect_xss(text: str) -> bool:
    """Return True if text contains XSS patterns."""
    for pattern in _XSS_PATTERNS:
        if pattern.search(text):
            return True
    return False


def detect_command_injection(text: str) -> bool:
    """Return True if text contains command injection patterns."""
    for pattern in _COMMAND_INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def validate_payload(
    data: Any,
    depth: int = 0,
    allow_html: bool = False,
) -> tuple[Any, List[str]]:
    """
    Recursively validate and sanitize a payload.
    Returns (sanitized_data, list_of_warnings).
    """
    warnings: List[str] = []

    if depth > MAX_OBJECT_DEPTH:
        warnings.append(f"Object depth exceeds limit ({MAX_OBJECT_DEPTH})")
        return None, warnings

    if isinstance(data, str):
        if len(data) > MAX_STRING_LENGTH:
            warnings.append(f"String truncated (was {len(data)} chars)")
            data = data[:MAX_STRING_LENGTH]
        if detect_sql_injection(data):
            warnings.append("Potential SQL injection detected")
        if detect_xss(data):
            warnings.append("Potential XSS detected")
        if not allow_html:
            data = html.escape(data)

    elif isinstance(data, dict):
        if len(data) > MAX_ARRAY_LENGTH:
            warnings.append(f"Object has too many keys ({len(data)})")
        result = {}
        for k, v in list(data.items())[:MAX_ARRAY_LENGTH]:
            sanitized_v, w = validate_payload(v, depth + 1, allow_html)
            result[k] = sanitized_v
            warnings.extend(w)
        data = result

    elif isinstance(data, list):
        if len(data) > MAX_ARRAY_LENGTH:
            warnings.append(f"Array truncated (was {len(data)} items)")
            data = data[:MAX_ARRAY_LENGTH]
        result_list = []
        for item in data:
            sanitized_item, w = validate_payload(item, depth + 1, allow_html)
            result_list.append(sanitized_item)
            warnings.extend(w)
        data = result_list

    return data, warnings


class InputValidationMiddleware(BaseHTTPMiddleware):
    """Middleware that validates request payload size and content."""

    def __init__(self, app, max_payload_bytes: int = MAX_PAYLOAD_SIZE) -> None:
        super().__init__(app)
        self.max_payload_bytes = max_payload_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > self.max_payload_bytes:
            return JSONResponse(
                status_code=413,
                content={"error": "Request Entity Too Large", "limit_bytes": self.max_payload_bytes},
            )
        return await call_next(request)
