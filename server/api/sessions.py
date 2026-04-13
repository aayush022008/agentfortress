"""Sessions API — agent session management."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func, desc

from ..database.connection import get_db
from ..database.models import AgentSession, Event

router = APIRouter()


class SessionResponse(BaseModel):
    id: str
    agent_name: str
    status: str
    started_at: datetime
    ended_at: Optional[datetime]
    environment: str
    framework: str
    total_events: int
    total_llm_calls: int
    total_tool_calls: int
    max_threat_score: int
    violation_count: int
    risk_score: int


@router.get("/", response_model=list[SessionResponse])
async def list_sessions(
    status: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
) -> list[SessionResponse]:
    """List all agent sessions with optional filtering."""
    query = select(AgentSession).order_by(desc(AgentSession.started_at))
    if status:
        query = query.where(AgentSession.status == status)
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    sessions = result.scalars().all()
    return [
        SessionResponse(
            id=s.id,
            agent_name=s.agent_name,
            status=s.status,
            started_at=s.started_at,
            ended_at=s.ended_at,
            environment=s.environment,
            framework=s.framework,
            total_events=s.total_events,
            total_llm_calls=s.total_llm_calls,
            total_tool_calls=s.total_tool_calls,
            max_threat_score=s.max_threat_score,
            violation_count=s.violation_count,
            risk_score=s.risk_score,
        )
        for s in sessions
    ]


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> SessionResponse:
    """Get a specific session by ID."""
    result = await db.execute(
        select(AgentSession).where(AgentSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return SessionResponse(
        id=session.id,
        agent_name=session.agent_name,
        status=session.status,
        started_at=session.started_at,
        ended_at=session.ended_at,
        environment=session.environment,
        framework=session.framework,
        total_events=session.total_events,
        total_llm_calls=session.total_llm_calls,
        total_tool_calls=session.total_tool_calls,
        max_threat_score=session.max_threat_score,
        violation_count=session.violation_count,
        risk_score=session.risk_score,
    )


@router.get("/{session_id}/events")
async def get_session_events(
    session_id: str,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Get all events for a session."""
    result = await db.execute(
        select(Event)
        .where(Event.session_id == session_id)
        .order_by(Event.timestamp)
        .limit(limit)
        .offset(offset)
    )
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "agent_name": e.agent_name,
            "timestamp": e.timestamp,
            "data": e.data,
            "threat_score": e.threat_score,
            "threat_reasons": e.threat_reasons,
            "blocked": e.blocked,
            "latency_ms": e.latency_ms,
        }
        for e in events
    ]


@router.post("/{session_id}/kill")
async def kill_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Activate the kill switch for a session."""
    result = await db.execute(
        select(AgentSession).where(AgentSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    await db.execute(
        update(AgentSession)
        .where(AgentSession.id == session_id)
        .values(status="killed", ended_at=datetime.utcnow())
    )
    await db.commit()

    # Broadcast kill signal via WebSocket
    from ..websocket import broadcast_event
    await broadcast_event({
        "type": "kill_switch",
        "session_id": session_id,
    })

    return {"status": "killed", "session_id": session_id}


@router.patch("/{session_id}")
async def update_session(
    session_id: str,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update session status."""
    updates: dict = {}
    if status:
        updates["status"] = status
        if status in ("completed", "error"):
            updates["ended_at"] = datetime.utcnow()

    if updates:
        await db.execute(
            update(AgentSession)
            .where(AgentSession.id == session_id)
            .values(**updates)
        )
        await db.commit()

    return {"session_id": session_id, "updated": True}
