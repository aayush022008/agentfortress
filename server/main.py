"""
AgentShield Server — FastAPI entry point.

Provides REST API for event ingestion, session management, alerts,
policies, and analytics. WebSocket for real-time dashboard updates.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database.connection import init_db
from .api import events, sessions, alerts, policies, analytics, organizations, apikeys, replay
from .websocket import router as ws_router
from .middleware.auth import AuthMiddleware
from .middleware.logging import LoggingMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Handle startup and shutdown."""
    logger.info("AgentShield Server starting up...")
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("AgentShield Server shutting down...")


app = FastAPI(
    title="AgentShield API",
    description="Runtime protection and security monitoring for AI agents",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom middleware
app.add_middleware(LoggingMiddleware)

# Include routers
app.include_router(events.router, prefix="/api/events", tags=["Events"])
app.include_router(sessions.router, prefix="/api/sessions", tags=["Sessions"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(policies.router, prefix="/api/policies", tags=["Policies"])
app.include_router(analytics.router, prefix="/api/analytics", tags=["Analytics"])
app.include_router(organizations.router, prefix="/api/organizations", tags=["Organizations"])
app.include_router(apikeys.router, prefix="/api/apikeys", tags=["API Keys"])
app.include_router(replay.router, prefix="/api/replay", tags=["Replay"])
app.include_router(ws_router, prefix="/ws", tags=["WebSocket"])


@app.get("/health", tags=["Health"])
async def health() -> dict:
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/", tags=["Health"])
async def root() -> dict:
    """Root endpoint."""
    return {
        "name": "AgentShield API",
        "version": "1.0.0",
        "docs": "/docs",
    }
