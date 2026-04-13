"""Alerts API — alert management."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, desc, func

from ..database.connection import get_db
from ..database.models import Alert

router = APIRouter()


class AlertResponse(BaseModel):
    id: str
    session_id: Optional[str]
    title: str
    description: str
    severity: str
    alert_type: str
    status: str
    threat_score: int
    created_at: datetime
    updated_at: datetime
    context: dict


class AcknowledgeRequest(BaseModel):
    acknowledged_by: str = "user"
    notes: str = ""


class ResolveRequest(BaseModel):
    resolved_by: str = "user"
    notes: str = ""


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
    session_id: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
) -> list[AlertResponse]:
    """List alerts with optional filtering."""
    query = select(Alert).order_by(desc(Alert.created_at))
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    if alert_type:
        query = query.where(Alert.alert_type == alert_type)
    if session_id:
        query = query.where(Alert.session_id == session_id)
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    alerts = result.scalars().all()
    return [_alert_to_response(a) for a in alerts]


@router.get("/stats")
async def alert_stats(db: AsyncSession = Depends(get_db)) -> dict:
    """Get alert statistics."""
    total = await db.scalar(func.count(Alert.id))
    open_count = await db.scalar(
        select(func.count(Alert.id)).where(Alert.status == "open")
    )
    critical = await db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == "critical", Alert.status == "open")
    )
    high = await db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == "high", Alert.status == "open")
    )
    return {
        "total": total,
        "open": open_count,
        "critical_open": critical,
        "high_open": high,
    }


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)) -> AlertResponse:
    """Get a specific alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_response(alert)


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    body: AcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Acknowledge an alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(
            status="acknowledged",
            acknowledged_at=datetime.utcnow(),
            acknowledged_by=body.acknowledged_by,
            notes=body.notes,
        )
    )
    await db.commit()
    return {"status": "acknowledged", "alert_id": alert_id}


@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    body: ResolveRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Resolve an alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(
            status="resolved",
            resolved_at=datetime.utcnow(),
            resolved_by=body.resolved_by,
            notes=body.notes,
        )
    )
    await db.commit()
    return {"status": "resolved", "alert_id": alert_id}


@router.post("/{alert_id}/false-positive")
async def mark_false_positive(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Mark an alert as a false positive."""
    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(status="false_positive")
    )
    await db.commit()
    return {"status": "false_positive", "alert_id": alert_id}


def _alert_to_response(alert: Alert) -> AlertResponse:
    return AlertResponse(
        id=alert.id,
        session_id=alert.session_id,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        alert_type=alert.alert_type,
        status=alert.status,
        threat_score=alert.threat_score,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
        context=alert.context or {},
    )
