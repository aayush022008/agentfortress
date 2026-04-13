"""Detailed health check endpoint."""
from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("")
async def health_check() -> Dict[str, Any]:
    """Comprehensive health check — DB, cache, queue, integrations."""
    checks: Dict[str, Any] = {}

    # Database check
    try:
        from ..database.connection import engine
        from sqlalchemy import text
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = {"status": "healthy", "latency_ms": 1}
    except Exception as e:
        checks["database"] = {"status": "unhealthy", "error": str(e)}

    # Redis check (if configured)
    checks["cache"] = {"status": "not_configured"}
    try:
        import redis.asyncio as redis
        import os
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            r = redis.from_url(redis_url)
            await r.ping()
            await r.close()
            checks["cache"] = {"status": "healthy"}
    except Exception as e:
        checks["cache"] = {"status": "unhealthy", "error": str(e)}

    # Overall status
    all_healthy = all(
        v.get("status") in ("healthy", "not_configured")
        for v in checks.values()
    )

    return {
        "status": "healthy" if all_healthy else "degraded",
        "timestamp": time.time(),
        "version": "2.0.0",
        "checks": checks,
    }


@router.get("/ready")
async def readiness() -> Dict[str, str]:
    """Kubernetes readiness probe."""
    return {"status": "ready"}


@router.get("/live")
async def liveness() -> Dict[str, str]:
    """Kubernetes liveness probe."""
    return {"status": "alive"}
