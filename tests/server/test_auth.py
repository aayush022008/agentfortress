"""Tests for server auth modules."""
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from server.auth.jwt import JWTManager
from server.auth.mfa import TOTPManager
from server.auth.api_key_auth import APIKeyAuthService
from server.auth.session_manager import SessionManager


class TestJWTManager:
    def test_generate_and_verify(self):
        mgr = JWTManager.generate()
        token = mgr.create_access_token("user-123", org_id="org-456", roles=["analyst"])
        payload = mgr.verify(token)
        assert payload["sub"] == "user-123"
        assert payload["org_id"] == "org-456"
        assert payload["roles"] == ["analyst"]
        assert payload["type"] == "access"

    def test_expired_token_fails(self):
        mgr = JWTManager.generate()
        # Manually create expired token
        import jwt
        private_key = mgr._private_key
        payload = {
            "sub": "user-123",
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,
            "jti": "test",
            "type": "access",
        }
        token = jwt.encode(payload, private_key, algorithm="RS256")
        with pytest.raises(Exception):
            mgr.verify(token)

    def test_refresh_token(self):
        mgr = JWTManager.generate()
        token = mgr.create_refresh_token("user-123")
        payload = mgr.verify(token)
        assert payload["type"] == "refresh"


class TestTOTPManager:
    def test_setup_and_verify(self):
        mgr = TOTPManager()
        secret, url = mgr.setup("alice@example.com", issuer="TestApp")
        assert secret
        assert "otpauth://totp/" in url
        assert "TestApp" in url

        code = mgr.generate_code(secret)
        assert len(code) == 6
        assert mgr.verify(secret, code)

    def test_invalid_code_rejected(self):
        mgr = TOTPManager()
        secret, _ = mgr.setup("bob@example.com")
        assert not mgr.verify(secret, "000000")  # Likely wrong

    def test_backup_codes(self):
        mgr = TOTPManager()
        codes = mgr.generate_backup_codes(5)
        assert len(codes) == 5
        assert all(len(c) == 8 for c in codes)

        # Use a code
        valid, remaining = mgr.verify_backup_code(codes[0], codes)
        assert valid
        assert len(remaining) == 4

        # Can't reuse
        valid2, _ = mgr.verify_backup_code(codes[0], remaining)
        assert not valid2


class TestAPIKeyAuthService:
    def test_create_and_authenticate(self):
        svc = APIKeyAuthService()
        raw_key, api_key = svc.create_key(
            "Test Key", owner_id="user-001",
            scopes=["events:write", "sessions:read"],
        )
        assert raw_key.startswith("as_")
        result = svc.authenticate(raw_key)
        assert result is not None
        assert result.owner_id == "user-001"

    def test_wrong_key_rejected(self):
        svc = APIKeyAuthService()
        svc.create_key("Key", owner_id="user-001")
        result = svc.authenticate("as_invalidkey12345")
        assert result is None

    def test_scope_check(self):
        svc = APIKeyAuthService()
        raw, _ = svc.create_key("Key", owner_id="u1", scopes=["alerts:read"])
        result = svc.authenticate(raw, required_scope="events:write")
        assert result is None
        result2 = svc.authenticate(raw, required_scope="alerts:read")
        assert result2 is not None

    def test_ip_restriction(self):
        svc = APIKeyAuthService()
        raw, _ = svc.create_key("Key", owner_id="u1", allowed_ips=["192.168.1.1"])
        assert svc.authenticate(raw, client_ip="192.168.1.1") is not None
        assert svc.authenticate(raw, client_ip="10.0.0.1") is None

    def test_revoke_key(self):
        svc = APIKeyAuthService()
        raw, api_key = svc.create_key("Key", owner_id="u1")
        assert svc.authenticate(raw) is not None
        svc.revoke_key(api_key.key_id)
        assert svc.authenticate(raw) is None


class TestSessionManager:
    def test_create_and_validate(self):
        mgr = SessionManager()
        session = mgr.create("user-123", org_id="org-001")
        assert session.session_id
        assert not session.is_expired
        result = mgr.validate(session.session_id)
        assert result is not None
        assert result.user_id == "user-123"

    def test_expired_session(self):
        mgr = SessionManager()
        session = mgr.create("user-123", ttl=1)
        time.sleep(2)
        result = mgr.validate(session.session_id)
        assert result is None

    def test_invalidate(self):
        mgr = SessionManager()
        session = mgr.create("user-123")
        mgr.invalidate(session.session_id)
        assert mgr.get(session.session_id) is None

    def test_invalidate_user_sessions(self):
        mgr = SessionManager()
        mgr.create("user-123")
        mgr.create("user-123")
        mgr.create("user-456")
        count = mgr.invalidate_user_sessions("user-123")
        assert count == 2
        assert mgr.active_count() == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
