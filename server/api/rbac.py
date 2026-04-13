"""RBAC (Role-Based Access Control) API endpoints."""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/rbac", tags=["rbac"])


class RoleCreate(BaseModel):
    name: str
    description: str = ""
    permissions: List[str] = []


class RoleUpdate(BaseModel):
    description: Optional[str] = None
    permissions: Optional[List[str]] = None


class RoleAssignment(BaseModel):
    user_id: str
    role_id: str
    org_id: Optional[str] = None


# Built-in roles
BUILT_IN_ROLES = [
    {"role_id": "admin", "name": "Admin", "description": "Full access to all resources", "permissions": ["*"], "built_in": True},
    {"role_id": "analyst", "name": "Security Analyst", "description": "View and investigate alerts", "permissions": ["alerts:read", "sessions:read", "events:read", "forensics:read"], "built_in": True},
    {"role_id": "hunter", "name": "Threat Hunter", "description": "Run threat hunts and view intelligence", "permissions": ["hunt:read", "hunt:write", "events:read", "intel:read"], "built_in": True},
    {"role_id": "viewer", "name": "Viewer", "description": "Read-only access", "permissions": ["alerts:read", "sessions:read", "dashboard:read"], "built_in": True},
    {"role_id": "api_user", "name": "API User", "description": "Programmatic API access", "permissions": ["events:write", "sessions:read"], "built_in": True},
]

ALL_PERMISSIONS = [
    "alerts:read", "alerts:write", "alerts:delete",
    "sessions:read", "sessions:write",
    "events:read", "events:write",
    "policies:read", "policies:write",
    "hunt:read", "hunt:write",
    "forensics:read", "forensics:write",
    "compliance:read", "compliance:write",
    "intel:read", "intel:write",
    "users:read", "users:write",
    "rbac:read", "rbac:write",
    "billing:read", "billing:write",
    "settings:read", "settings:write",
    "dashboard:read", "dashboard:write",
    "integrations:read", "integrations:write",
    "audit:read",
    "sandbox:read", "sandbox:write",
    "ml:read",
    "export:read",
    "search:read",
    "*",
]


@router.get("/roles")
async def list_roles(include_built_in: bool = True) -> Dict[str, Any]:
    """List all roles."""
    roles = list(BUILT_IN_ROLES) if include_built_in else []
    return {"roles": roles, "total": len(roles)}


@router.post("/roles")
async def create_role(role: RoleCreate) -> Dict[str, Any]:
    """Create a custom role."""
    return {
        "role_id": str(uuid.uuid4()),
        "name": role.name,
        "description": role.description,
        "permissions": role.permissions,
        "built_in": False,
        "created_at": time.time(),
    }


@router.get("/roles/{role_id}")
async def get_role(role_id: str) -> Dict[str, Any]:
    """Get a role by ID."""
    for r in BUILT_IN_ROLES:
        if r["role_id"] == role_id:
            return r
    raise HTTPException(status_code=404, detail="Role not found")


@router.put("/roles/{role_id}")
async def update_role(role_id: str, update: RoleUpdate) -> Dict[str, Any]:
    """Update a custom role."""
    for r in BUILT_IN_ROLES:
        if r["role_id"] == role_id and r.get("built_in"):
            raise HTTPException(status_code=403, detail="Cannot modify built-in roles")
    raise HTTPException(status_code=404, detail="Role not found")


@router.delete("/roles/{role_id}")
async def delete_role(role_id: str) -> Dict[str, str]:
    """Delete a custom role."""
    for r in BUILT_IN_ROLES:
        if r["role_id"] == role_id and r.get("built_in"):
            raise HTTPException(status_code=403, detail="Cannot delete built-in roles")
    return {"status": "deleted", "role_id": role_id}


@router.get("/permissions")
async def list_permissions() -> Dict[str, Any]:
    """List all available permissions."""
    return {"permissions": ALL_PERMISSIONS}


@router.get("/assignments")
async def list_assignments(
    user_id: Optional[str] = Query(None),
    role_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List role assignments."""
    return {"assignments": [], "total": 0}


@router.post("/assignments")
async def assign_role(assignment: RoleAssignment) -> Dict[str, Any]:
    """Assign a role to a user."""
    return {
        "assignment_id": str(uuid.uuid4()),
        "user_id": assignment.user_id,
        "role_id": assignment.role_id,
        "org_id": assignment.org_id,
        "assigned_at": time.time(),
    }


@router.delete("/assignments/{assignment_id}")
async def revoke_role(assignment_id: str) -> Dict[str, str]:
    """Revoke a role assignment."""
    return {"status": "revoked", "assignment_id": assignment_id}


@router.post("/check")
async def check_permission(
    user_id: str,
    permission: str,
    org_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Check if a user has a specific permission."""
    return {
        "user_id": user_id,
        "permission": permission,
        "allowed": False,
        "reason": "No role assignment found",
    }
