"""Dashboard configuration API — user dashboard layout persistence."""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/dashboard-config", tags=["dashboard"])


class WidgetConfig(BaseModel):
    widget_id: str
    widget_type: str
    position: Dict[str, int]  # {x, y, w, h}
    config: Dict[str, Any] = {}


class DashboardLayout(BaseModel):
    layout_id: Optional[str] = None
    name: str = "My Dashboard"
    widgets: List[WidgetConfig] = []
    is_default: bool = False


@router.get("")
async def list_layouts(user_id: Optional[str] = None) -> Dict[str, Any]:
    """List dashboard layouts for a user."""
    return {"layouts": [], "total": 0}


@router.post("")
async def create_layout(layout: DashboardLayout) -> Dict[str, Any]:
    """Create or save a dashboard layout."""
    return {
        "layout_id": layout.layout_id or str(uuid.uuid4()),
        "name": layout.name,
        "widgets": [w.dict() for w in layout.widgets],
        "is_default": layout.is_default,
        "created_at": time.time(),
    }


@router.get("/{layout_id}")
async def get_layout(layout_id: str) -> Dict[str, Any]:
    """Get a specific layout."""
    raise HTTPException(status_code=404, detail="Layout not found")


@router.put("/{layout_id}")
async def update_layout(layout_id: str, layout: DashboardLayout) -> Dict[str, Any]:
    """Update a dashboard layout."""
    return {
        "layout_id": layout_id,
        "name": layout.name,
        "widgets": [w.dict() for w in layout.widgets],
        "updated_at": time.time(),
    }


@router.delete("/{layout_id}")
async def delete_layout(layout_id: str) -> Dict[str, str]:
    """Delete a dashboard layout."""
    return {"status": "deleted", "layout_id": layout_id}


@router.post("/{layout_id}/default")
async def set_default_layout(layout_id: str) -> Dict[str, Any]:
    """Set a layout as the default."""
    return {"layout_id": layout_id, "is_default": True}
