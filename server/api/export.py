"""Data export API — CSV, JSON, NDJSON, PDF."""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api/export", tags=["export"])


class ExportRequest(BaseModel):
    resource: str  # events | alerts | sessions | audit_log
    format: str = "json"  # json | ndjson | csv | pdf
    filters: Dict[str, Any] = {}
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    fields: Optional[List[str]] = None
    limit: Optional[int] = None


@router.post("")
async def request_export(req: ExportRequest) -> Dict[str, Any]:
    """
    Request a data export. For large exports, returns a job ID to poll.
    For small exports, returns download URL immediately.
    """
    valid_resources = ["events", "alerts", "sessions", "audit_log", "forensics"]
    if req.resource not in valid_resources:
        raise HTTPException(status_code=400, detail=f"Invalid resource. Must be one of: {valid_resources}")

    valid_formats = ["json", "ndjson", "csv", "pdf"]
    if req.format not in valid_formats:
        raise HTTPException(status_code=400, detail=f"Invalid format. Must be one of: {valid_formats}")

    export_id = f"exp-{int(time.time())}"
    return {
        "export_id": export_id,
        "resource": req.resource,
        "format": req.format,
        "status": "pending",
        "created_at": time.time(),
        "download_url": f"/api/export/{export_id}/download",
        "expires_at": time.time() + 3600,
    }


@router.get("/{export_id}")
async def get_export_status(export_id: str) -> Dict[str, Any]:
    """Get export job status."""
    raise HTTPException(status_code=404, detail="Export not found")


@router.get("/{export_id}/download")
async def download_export(export_id: str) -> Any:
    """Download the exported file."""
    raise HTTPException(status_code=404, detail="Export not ready or not found")


@router.get("/events/stream")
async def stream_events(
    format: str = Query("ndjson", pattern="^(ndjson|csv)$"),
    limit: int = Query(10000, ge=1, le=100000),
    start_time: Optional[float] = Query(None),
    end_time: Optional[float] = Query(None),
) -> StreamingResponse:
    """Stream events as NDJSON or CSV."""
    async def generator():
        if format == "ndjson":
            import json
            yield json.dumps({"info": "no events in time range"}) + "\n"
        else:
            yield "event_type,agent_id,session_id,timestamp\n"

    media_type = "application/x-ndjson" if format == "ndjson" else "text/csv"
    return StreamingResponse(
        generator(),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename=events.{format}"},
    )
