"""Replay API — session timeline replay."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database.connection import get_db
from ..database.models import AgentSession, Event

router = APIRouter()


@router.get("/{session_id}")
async def get_session_replay(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get the full replay timeline for a session."""
    result = await db.execute(
        select(AgentSession).where(AgentSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    events_result = await db.execute(
        select(Event)
        .where(Event.session_id == session_id)
        .order_by(Event.timestamp)
    )
    events = events_result.scalars().all()

    start_time = events[0].timestamp if events else session.started_at.timestamp()
    end_time = events[-1].timestamp if events else start_time

    replay_events = []
    for event in events:
        relative_ms = (event.timestamp - start_time) * 1000
        replay_events.append({
            "event_id": event.id,
            "event_type": event.event_type,
            "agent_name": event.agent_name,
            "timestamp": event.timestamp,
            "relative_time_ms": round(relative_ms, 2),
            "data": event.data,
            "threat_score": event.threat_score,
            "threat_reasons": event.threat_reasons,
            "blocked": event.blocked,
            "latency_ms": event.latency_ms,
        })

    return {
        "session_id": session_id,
        "agent_name": session.agent_name,
        "status": session.status,
        "start_time": start_time,
        "end_time": end_time,
        "duration_ms": round((end_time - start_time) * 1000, 2),
        "total_events": len(replay_events),
        "total_llm_calls": session.total_llm_calls,
        "total_tool_calls": session.total_tool_calls,
        "max_threat_score": session.max_threat_score,
        "had_violations": session.violation_count > 0,
        "events": replay_events,
    }
