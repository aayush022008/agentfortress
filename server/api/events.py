"""
Events API — receives events from SDK agents.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from ..database.connection import get_db
from ..database.models import Event, AgentSession
from ..services.threat_detection import ThreatDetectionService
from ..services.alert_manager import AlertManager
from ..websocket import broadcast_event

router = APIRouter()


class EventPayload(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    event_type: str
    agent_name: str
    timestamp: float
    data: dict[str, Any] = {}
    threat_score: int = 0
    threat_reasons: list[str] = []
    blocked: bool = False
    latency_ms: Optional[float] = None


class BatchEventPayload(BaseModel):
    events: list[EventPayload]


class EventResponse(BaseModel):
    event_id: str
    processed: bool
    threat_score: int
    action: str


@router.post("/batch", status_code=status.HTTP_200_OK)
async def ingest_batch_events(
    payload: BatchEventPayload,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Receive a batch of events from an SDK agent.

    This is the primary ingestion endpoint called by agentshield-sdk.
    """
    if not payload.events:
        return {"processed": 0}

    threat_service = ThreatDetectionService()
    alert_manager = AlertManager(db)
    processed = 0

    # Ensure sessions exist
    session_ids = {e.session_id for e in payload.events}
    for session_id in session_ids:
        existing = await db.execute(
            select(AgentSession).where(AgentSession.id == session_id)
        )
        if not existing.scalar_one_or_none():
            first_event = next(e for e in payload.events if e.session_id == session_id)
            session = AgentSession(
                id=session_id,
                agent_name=first_event.agent_name,
                status="active",
                framework=_detect_framework(first_event.data),
            )
            db.add(session)

    # Process events
    events_to_insert: list[Event] = []
    for event_data in payload.events:
        # Re-analyze with server-side threat detection
        server_threat = await threat_service.analyze(event_data)
        final_score = max(event_data.threat_score, server_threat.score)
        final_reasons = list(set(event_data.threat_reasons + server_threat.reasons))

        db_event = Event(
            id=event_data.event_id,
            session_id=event_data.session_id,
            event_type=event_data.event_type,
            agent_name=event_data.agent_name,
            timestamp=event_data.timestamp,
            data=event_data.data,
            threat_score=final_score,
            threat_reasons=final_reasons,
            blocked=event_data.blocked,
            latency_ms=event_data.latency_ms,
        )
        events_to_insert.append(db_event)
        db.add(db_event)

        # Create alerts for significant threats
        if final_score >= 50:
            await alert_manager.create_from_event(
                event=event_data,
                threat_score=final_score,
                threat_reasons=final_reasons,
            )

        # Broadcast to WebSocket clients
        await broadcast_event({
            "type": "event",
            "event_id": event_data.event_id,
            "session_id": event_data.session_id,
            "event_type": event_data.event_type,
            "agent_name": event_data.agent_name,
            "timestamp": event_data.timestamp,
            "threat_score": final_score,
            "blocked": event_data.blocked,
        })
        processed += 1

    # Update session stats
    for session_id in session_ids:
        session_events = [e for e in events_to_insert if e.session_id == session_id]
        max_threat = max((e.threat_score for e in session_events), default=0)
        llm_calls = sum(1 for e in session_events if "llm" in e.event_type)
        tool_calls = sum(1 for e in session_events if "tool" in e.event_type)
        violations = sum(1 for e in session_events if e.blocked)

        await db.execute(
            update(AgentSession)
            .where(AgentSession.id == session_id)
            .values(
                total_events=AgentSession.total_events + len(session_events),
                total_llm_calls=AgentSession.total_llm_calls + llm_calls,
                total_tool_calls=AgentSession.total_tool_calls + tool_calls,
                violation_count=AgentSession.violation_count + violations,
                max_threat_score=max_threat,
            )
        )

    await db.commit()
    return {"processed": processed}


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=EventResponse)
async def ingest_event(
    payload: EventPayload,
    db: AsyncSession = Depends(get_db),
) -> EventResponse:
    """Receive a single event from an SDK agent."""
    batch = BatchEventPayload(events=[payload])
    await ingest_batch_events(batch, db)
    return EventResponse(
        event_id=payload.event_id,
        processed=True,
        threat_score=payload.threat_score,
        action="ALLOW" if not payload.blocked else "BLOCK",
    )


@router.get("/{event_id}")
async def get_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get a specific event by ID."""
    result = await db.execute(select(Event).where(Event.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return {
        "id": event.id,
        "session_id": event.session_id,
        "event_type": event.event_type,
        "agent_name": event.agent_name,
        "timestamp": event.timestamp,
        "data": event.data,
        "threat_score": event.threat_score,
        "threat_reasons": event.threat_reasons,
        "blocked": event.blocked,
        "latency_ms": event.latency_ms,
    }


def _detect_framework(data: dict) -> str:
    """Detect agent framework from event data."""
    method = data.get("method", "")
    if "langchain" in str(data).lower():
        return "langchain"
    elif "crewai" in str(data).lower():
        return "crewai"
    elif "autogen" in str(data).lower():
        return "autogen"
    return "unknown"
