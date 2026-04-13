"""Immutable audit log API endpoints."""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/audit-log", tags=["audit-log"])


class AuditLogEntry(BaseModel):
    action: str
    actor_id: str
    actor_type: str = "user"  # user | api_key | system
    resource_type: str = ""
    resource_id: str = ""
    org_id: Optional[str] = None
    details: Dict[str, Any] = {}
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@router.get("")
async def list_audit_log(
    actor_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None),
    start_time: Optional[float] = Query(None),
    end_time: Optional[float] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    Query the immutable audit log.
    All actions performed on the platform are logged here.
    """
    return {
        "entries": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{entry_id}")
async def get_audit_entry(entry_id: str) -> Dict[str, Any]:
    """Get a specific audit log entry."""
    raise HTTPException(status_code=404, detail="Audit log entry not found")


@router.get("/actors/{actor_id}")
async def get_actor_history(
    actor_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Get audit history for a specific actor."""
    return {"actor_id": actor_id, "entries": [], "total": 0}


@router.get("/export")
async def export_audit_log(
    start_time: Optional[float] = Query(None),
    end_time: Optional[float] = Query(None),
    format: str = Query("ndjson", pattern="^(json|ndjson|csv)$"),
) -> Any:
    """Export audit log in various formats."""
    return {"export_url": f"/api/audit-log/export/download?format={format}", "expires_at": time.time() + 3600}
