"""RBAC service — permission evaluation and role management."""
from __future__ import annotations

import fnmatch
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class Role:
    role_id: str
    name: str
    description: str = ""
    permissions: List[str] = field(default_factory=list)
    built_in: bool = False
    created_at: float = field(default_factory=time.time)


@dataclass
class RoleAssignment:
    assignment_id: str
    user_id: str
    role_id: str
    org_id: Optional[str] = None
    assigned_at: float = field(default_factory=time.time)
    assigned_by: Optional[str] = None
    expires_at: Optional[float] = None


class RBACService:
    """
    Role-Based Access Control service.
    Manages roles, permissions, and role assignments.
    Supports wildcard permissions (e.g., 'alerts:*', '*').
    """

    def __init__(self) -> None:
        self._roles: Dict[str, Role] = {}
        self._assignments: Dict[str, List[RoleAssignment]] = {}  # user_id → assignments
        self._init_built_in_roles()

    def _init_built_in_roles(self) -> None:
        built_ins = [
            Role("admin", "Admin", "Full platform access", ["*"], built_in=True),
            Role("analyst", "Security Analyst", "View and investigate", ["alerts:read", "sessions:read", "events:read", "forensics:read", "search:read", "export:read"], built_in=True),
            Role("hunter", "Threat Hunter", "Threat hunting", ["hunt:read", "hunt:write", "events:read", "intel:read", "search:read"], built_in=True),
            Role("viewer", "Viewer", "Read-only", ["alerts:read", "sessions:read", "dashboard:read", "search:read"], built_in=True),
            Role("api_user", "API User", "API access", ["events:write", "sessions:read"], built_in=True),
        ]
        for r in built_ins:
            self._roles[r.role_id] = r

    def create_role(
        self,
        name: str,
        permissions: List[str],
        description: str = "",
    ) -> Role:
        role = Role(
            role_id=str(uuid.uuid4()),
            name=name,
            description=description,
            permissions=permissions,
        )
        self._roles[role.role_id] = role
        return role

    def get_role(self, role_id: str) -> Optional[Role]:
        return self._roles.get(role_id)

    def list_roles(self) -> List[Role]:
        return list(self._roles.values())

    def update_role(
        self,
        role_id: str,
        permissions: Optional[List[str]] = None,
        description: Optional[str] = None,
    ) -> Optional[Role]:
        role = self._roles.get(role_id)
        if not role or role.built_in:
            return None
        if permissions is not None:
            role.permissions = permissions
        if description is not None:
            role.description = description
        return role

    def delete_role(self, role_id: str) -> bool:
        role = self._roles.get(role_id)
        if not role or role.built_in:
            return False
        del self._roles[role_id]
        return True

    def assign_role(
        self,
        user_id: str,
        role_id: str,
        org_id: Optional[str] = None,
        assigned_by: Optional[str] = None,
        ttl_days: Optional[int] = None,
    ) -> RoleAssignment:
        if role_id not in self._roles:
            raise ValueError(f"Role not found: {role_id}")
        assignment = RoleAssignment(
            assignment_id=str(uuid.uuid4()),
            user_id=user_id,
            role_id=role_id,
            org_id=org_id,
            assigned_by=assigned_by,
            expires_at=time.time() + ttl_days * 86400 if ttl_days else None,
        )
        self._assignments.setdefault(user_id, []).append(assignment)
        return assignment

    def revoke_role(self, assignment_id: str) -> bool:
        for user_id, assignments in self._assignments.items():
            for i, a in enumerate(assignments):
                if a.assignment_id == assignment_id:
                    assignments.pop(i)
                    return True
        return False

    def get_user_permissions(
        self, user_id: str, org_id: Optional[str] = None
    ) -> Set[str]:
        """Return all permissions for a user (expanded from assigned roles)."""
        now = time.time()
        permissions: Set[str] = set()
        for assignment in self._assignments.get(user_id, []):
            if assignment.expires_at and assignment.expires_at < now:
                continue
            if org_id and assignment.org_id and assignment.org_id != org_id:
                continue
            role = self._roles.get(assignment.role_id)
            if role:
                permissions.update(role.permissions)
        return permissions

    def has_permission(
        self, user_id: str, permission: str, org_id: Optional[str] = None
    ) -> bool:
        """Check if a user has a specific permission. Supports wildcards."""
        user_perms = self.get_user_permissions(user_id, org_id)
        for perm in user_perms:
            if perm == "*" or fnmatch.fnmatch(permission, perm):
                return True
        return False

    def get_user_roles(self, user_id: str) -> List[Role]:
        """Return all active roles for a user."""
        now = time.time()
        roles = []
        for assignment in self._assignments.get(user_id, []):
            if assignment.expires_at and assignment.expires_at < now:
                continue
            role = self._roles.get(assignment.role_id)
            if role:
                roles.append(role)
        return roles
