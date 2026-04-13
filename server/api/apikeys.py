"""API Keys management."""

from __future__ import annotations

import hashlib
import secrets
import string
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete

from ..database.connection import get_db
from ..database.models import ApiKey

router = APIRouter()


def _generate_api_key() -> tuple[str, str, str]:
    """Generate API key, prefix, and hash. Returns (key, prefix, hash)."""
    key = "as_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))
    prefix = key[:10]
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, prefix, key_hash


class ApiKeyCreate(BaseModel):
    name: str
    organization_id: Optional[str] = None
    scopes: list[str] = ["read", "write"]
    expires_at: Optional[datetime] = None


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    scopes: list[str]
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    is_active: bool


class ApiKeyCreatedResponse(ApiKeyResponse):
    key: str  # Only returned at creation time


@router.get("/", response_model=list[ApiKeyResponse])
async def list_api_keys(db: AsyncSession = Depends(get_db)) -> list[ApiKeyResponse]:
    result = await db.execute(select(ApiKey).order_by(ApiKey.created_at))
    keys = result.scalars().all()
    return [_key_to_response(k) for k in keys]


@router.post("/", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(body: ApiKeyCreate, db: AsyncSession = Depends(get_db)) -> ApiKeyCreatedResponse:
    raw_key, prefix, key_hash = _generate_api_key()
    api_key = ApiKey(
        organization_id=body.organization_id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=prefix,
        scopes=body.scopes,
        expires_at=body.expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    return ApiKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        is_active=api_key.is_active,
        key=raw_key,
    )


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(key_id: str, db: AsyncSession = Depends(get_db)) -> None:
    await db.execute(update(ApiKey).where(ApiKey.id == key_id).values(is_active=False))
    await db.commit()


def _key_to_response(k: ApiKey) -> ApiKeyResponse:
    return ApiKeyResponse(
        id=k.id,
        name=k.name,
        key_prefix=k.key_prefix,
        scopes=k.scopes or [],
        created_at=k.created_at,
        last_used_at=k.last_used_at,
        expires_at=k.expires_at,
        is_active=k.is_active,
    )
