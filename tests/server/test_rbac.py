"""Tests for RBAC service."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from server.services.rbac_service import RBACService


class TestRBACService:
    def test_built_in_roles_exist(self):
        svc = RBACService()
        roles = svc.list_roles()
        role_names = [r.name for r in roles]
        assert "Admin" in role_names
        assert "Viewer" in role_names

    def test_assign_and_check_permission(self):
        svc = RBACService()
        svc.assign_role("user-001", "analyst")
        assert svc.has_permission("user-001", "alerts:read")
        assert svc.has_permission("user-001", "sessions:read")
        assert not svc.has_permission("user-001", "rbac:write")

    def test_admin_has_all_permissions(self):
        svc = RBACService()
        svc.assign_role("admin-001", "admin")
        assert svc.has_permission("admin-001", "alerts:read")
        assert svc.has_permission("admin-001", "billing:write")
        assert svc.has_permission("admin-001", "anything:here")

    def test_no_role_no_permission(self):
        svc = RBACService()
        assert not svc.has_permission("unknown-user", "alerts:read")

    def test_create_custom_role(self):
        svc = RBACService()
        role = svc.create_role("DevOps", ["sessions:read", "events:read", "export:read"])
        assert role.role_id
        assert not role.built_in

    def test_assign_custom_role(self):
        svc = RBACService()
        role = svc.create_role("DevOps", ["sessions:read"])
        svc.assign_role("devops-001", role.role_id)
        assert svc.has_permission("devops-001", "sessions:read")
        assert not svc.has_permission("devops-001", "alerts:write")

    def test_revoke_role(self):
        svc = RBACService()
        assignment = svc.assign_role("user-002", "viewer")
        assert svc.has_permission("user-002", "alerts:read")
        svc.revoke_role(assignment.assignment_id)
        assert not svc.has_permission("user-002", "alerts:read")

    def test_delete_built_in_role_fails(self):
        svc = RBACService()
        result = svc.delete_role("admin")
        assert not result  # Can't delete built-in

    def test_get_user_roles(self):
        svc = RBACService()
        svc.assign_role("user-003", "analyst")
        svc.assign_role("user-003", "hunter")
        roles = svc.get_user_roles("user-003")
        assert len(roles) == 2

    def test_wildcard_permission(self):
        svc = RBACService()
        role = svc.create_role("Custom", ["alerts:*"])
        svc.assign_role("user-004", role.role_id)
        assert svc.has_permission("user-004", "alerts:read")
        assert svc.has_permission("user-004", "alerts:write")
        assert svc.has_permission("user-004", "alerts:delete")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
