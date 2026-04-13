"""Organizations API — multi-tenant org management."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from ..database.connection import get_db
from ..database.models import Organization

router = APIRouter()


class OrgCreate(BaseModel):
    name: str
    slug: Optional[str] = None


class OrgResponse(BaseModel):
    id: str
    name: str
    slug: str
    created_at: datetime
    is_active: bool


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


@router.get("/", response_model=list[OrgResponse])
async def list_organizations(db: AsyncSession = Depends(get_db)) -> list[OrgResponse]:
    result = await db.execute(select(Organization).order_by(Organization.created_at))
    orgs = result.scalars().all()
    return [OrgResponse(id=o.id, name=o.name, slug=o.slug, created_at=o.created_at, is_active=o.is_active) for o in orgs]


@router.post("/", response_model=OrgResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(body: OrgCreate, db: AsyncSession = Depends(get_db)) -> OrgResponse:
    slug = body.slug or _slugify(body.name)
    existing = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Organization slug already exists")

    org = Organization(name=body.name, slug=slug)
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return OrgResponse(id=org.id, name=org.name, slug=org.slug, created_at=org.created_at, is_active=org.is_active)


@router.get("/{org_id}", response_model=OrgResponse)
async def get_organization(org_id: str, db: AsyncSession = Depends(get_db)) -> OrgResponse:
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return OrgResponse(id=org.id, name=org.name, slug=org.slug, created_at=org.created_at, is_active=org.is_active)


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(org_id: str, db: AsyncSession = Depends(get_db)) -> None:
    await db.execute(delete(Organization).where(Organization.id == org_id))
    await db.commit()
