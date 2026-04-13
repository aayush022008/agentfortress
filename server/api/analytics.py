"""Analytics API — aggregated stats and trends."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from ..database.connection import get_db
from ..database.models import Event, Alert, AgentSession

router = APIRouter()


@router.get("/overview")
async def get_overview(db: AsyncSession = Depends(get_db)) -> dict:
    """Get high-level dashboard overview stats."""
    total_sessions = await db.scalar(func.count(AgentSession.id))
    active_sessions = await db.scalar(
        select(func.count(AgentSession.id)).where(AgentSession.status == "active")
    )
    total_events = await db.scalar(func.count(Event.id))
    total_alerts = await db.scalar(func.count(Alert.id))
    open_alerts = await db.scalar(
        select(func.count(Alert.id)).where(Alert.status == "open")
    )
    critical_alerts = await db.scalar(
        select(func.count(Alert.id)).where(
            Alert.severity == "critical", Alert.status == "open"
        )
    )
    blocked_events = await db.scalar(
        select(func.count(Event.id)).where(Event.blocked == True)
    )

    return {
        "total_sessions": total_sessions or 0,
        "active_sessions": active_sessions or 0,
        "total_events": total_events or 0,
        "total_alerts": total_alerts or 0,
        "open_alerts": open_alerts or 0,
        "critical_alerts": critical_alerts or 0,
        "blocked_events": blocked_events or 0,
    }


@router.get("/events-over-time")
async def events_over_time(
    hours: int = Query(default=24, le=168),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Get event counts bucketed by hour for the last N hours."""
    since = datetime.utcnow() - timedelta(hours=hours)
    since_ts = since.timestamp()

    result = await db.execute(
        select(Event.timestamp, Event.threat_score, Event.blocked)
        .where(Event.timestamp >= since_ts)
        .order_by(Event.timestamp)
    )
    rows = result.all()

    # Bucket by hour
    buckets: dict[str, dict] = {}
    for ts, score, blocked in rows:
        dt = datetime.utcfromtimestamp(ts)
        bucket_key = dt.strftime("%Y-%m-%dT%H:00:00Z")
        if bucket_key not in buckets:
            buckets[bucket_key] = {"time": bucket_key, "events": 0, "threats": 0, "blocked": 0}
        buckets[bucket_key]["events"] += 1
        if score >= 50:
            buckets[bucket_key]["threats"] += 1
        if blocked:
            buckets[bucket_key]["blocked"] += 1

    return list(buckets.values())


@router.get("/threat-distribution")
async def threat_distribution(db: AsyncSession = Depends(get_db)) -> list[dict]:
    """Get distribution of threat types from alerts."""
    result = await db.execute(
        select(Alert.alert_type, func.count(Alert.id).label("count"))
        .group_by(Alert.alert_type)
        .order_by(desc("count"))
    )
    rows = result.all()
    return [{"type": row[0], "count": row[1]} for row in rows]


@router.get("/top-agents")
async def top_agents_by_risk(
    limit: int = Query(default=10, le=50),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Get top agents by risk score."""
    result = await db.execute(
        select(
            AgentSession.agent_name,
            func.count(AgentSession.id).label("session_count"),
            func.avg(AgentSession.max_threat_score).label("avg_threat"),
            func.sum(AgentSession.violation_count).label("total_violations"),
        )
        .group_by(AgentSession.agent_name)
        .order_by(desc("avg_threat"))
        .limit(limit)
    )
    rows = result.all()
    return [
        {
            "agent_name": row[0],
            "session_count": row[1],
            "avg_threat_score": round(float(row[2] or 0), 1),
            "total_violations": row[3] or 0,
        }
        for row in rows
    ]


@router.get("/alert-trends")
async def alert_trends(
    days: int = Query(default=7, le=30),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Get daily alert counts for the last N days."""
    since = datetime.utcnow() - timedelta(days=days)

    result = await db.execute(
        select(Alert.created_at, Alert.severity)
        .where(Alert.created_at >= since)
        .order_by(Alert.created_at)
    )
    rows = result.all()

    buckets: dict[str, dict] = {}
    for created_at, severity in rows:
        bucket_key = created_at.strftime("%Y-%m-%d")
        if bucket_key not in buckets:
            buckets[bucket_key] = {
                "date": bucket_key,
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
        buckets[bucket_key]["total"] += 1
        buckets[bucket_key][severity] = buckets[bucket_key].get(severity, 0) + 1

    return list(buckets.values())
