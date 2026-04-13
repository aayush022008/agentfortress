"""Policies API — CRUD for security policies."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete

from ..database.connection import get_db
from ..database.models import Policy

router = APIRouter()


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    action: str  # BLOCK, ALERT, LOG, RATE_LIMIT
    severity: str = "medium"
    condition: dict[str, Any]
    is_enabled: bool = True


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    condition: Optional[dict[str, Any]] = None
    is_enabled: Optional[bool] = None


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: str
    action: str
    severity: str
    condition: dict
    is_enabled: bool
    is_builtin: bool
    trigger_count: int
    created_at: datetime
    updated_at: datetime
    last_triggered_at: Optional[datetime]


@router.get("/", response_model=list[PolicyResponse])
async def list_policies(db: AsyncSession = Depends(get_db)) -> list[PolicyResponse]:
    """List all policies."""
    result = await db.execute(select(Policy).order_by(Policy.created_at))
    policies = result.scalars().all()
    return [_policy_to_response(p) for p in policies]


@router.post("/", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: PolicyCreate,
    db: AsyncSession = Depends(get_db),
) -> PolicyResponse:
    """Create a new security policy."""
    if body.action not in ("BLOCK", "ALERT", "LOG", "RATE_LIMIT"):
        raise HTTPException(status_code=400, detail="Invalid action")

    policy = Policy(
        name=body.name,
        description=body.description,
        action=body.action,
        severity=body.severity,
        condition=body.condition,
        is_enabled=body.is_enabled,
        is_builtin=False,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return _policy_to_response(policy)


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(policy_id: str, db: AsyncSession = Depends(get_db)) -> PolicyResponse:
    """Get a specific policy."""
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _policy_to_response(policy)


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: str,
    body: PolicyUpdate,
    db: AsyncSession = Depends(get_db),
) -> PolicyResponse:
    """Update a policy."""
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.is_builtin:
        # Only allow enable/disable of builtin policies
        if body.is_enabled is not None:
            await db.execute(
                update(Policy).where(Policy.id == policy_id).values(is_enabled=body.is_enabled)
            )
            await db.commit()
            await db.refresh(policy)
            return _policy_to_response(policy)
        raise HTTPException(status_code=403, detail="Cannot modify built-in policies")

    updates: dict = {}
    for field in ("name", "description", "action", "severity", "condition", "is_enabled"):
        val = getattr(body, field)
        if val is not None:
            updates[field] = val
    if updates:
        updates["updated_at"] = datetime.utcnow()
        await db.execute(update(Policy).where(Policy.id == policy_id).values(**updates))
        await db.commit()
        await db.refresh(policy)
    return _policy_to_response(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: str, db: AsyncSession = Depends(get_db)) -> None:
    """Delete a policy."""
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.is_builtin:
        raise HTTPException(status_code=403, detail="Cannot delete built-in policies")
    await db.execute(delete(Policy).where(Policy.id == policy_id))
    await db.commit()


def _policy_to_response(p: Policy) -> PolicyResponse:
    return PolicyResponse(
        id=p.id,
        name=p.name,
        description=p.description,
        action=p.action,
        severity=p.severity,
        condition=p.condition,
        is_enabled=p.is_enabled,
        is_builtin=p.is_builtin,
        trigger_count=p.trigger_count,
        created_at=p.created_at,
        updated_at=p.updated_at,
        last_triggered_at=p.last_triggered_at,
    )
