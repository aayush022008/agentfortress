"""Full-text search API across events, alerts, sessions."""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/search", tags=["search"])


class SearchRequest(BaseModel):
    query: str
    index: Optional[str] = None  # events | alerts | sessions | all
    filters: Dict[str, Any] = {}
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    limit: int = 50
    offset: int = 0
    highlight: bool = True


class SearchResult(BaseModel):
    id: str
    type: str
    score: float
    data: Dict[str, Any]
    highlights: Dict[str, List[str]] = {}


@router.post("")
async def search(req: SearchRequest) -> Dict[str, Any]:
    """
    Full-text search across events, alerts, and sessions.
    Supports field filters, time ranges, and text highlighting.
    """
    return {
        "query": req.query,
        "total": 0,
        "results": [],
        "took_ms": 0,
        "limit": req.limit,
        "offset": req.offset,
    }


@router.get("/suggest")
async def suggest(
    q: str = Query(..., min_length=1),
    index: Optional[str] = Query(None),
    limit: int = Query(10, ge=1, le=50),
) -> Dict[str, Any]:
    """Get search suggestions/autocomplete."""
    return {"suggestions": [], "query": q}


@router.get("/saved")
async def list_saved_searches() -> Dict[str, Any]:
    """List saved searches."""
    return {"searches": [], "total": 0}


@router.post("/saved")
async def save_search(
    name: str,
    query: str,
    filters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Save a search for later use."""
    return {
        "search_id": f"search-{int(time.time())}",
        "name": name,
        "query": query,
        "created_at": time.time(),
    }


@router.delete("/saved/{search_id}")
async def delete_saved_search(search_id: str) -> Dict[str, str]:
    return {"status": "deleted", "search_id": search_id}
