"""JWT authentication — RS256 token generation and validation."""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
    load_pem_private_key, load_pem_public_key,
)


class JWTManager:
    """
    JWT token generation and validation using RS256.

    Usage::

        mgr = JWTManager.generate()
        access_token = mgr.create_access_token(user_id="user-123", org_id="org-456")
        payload = mgr.verify(access_token)
    """

    ACCESS_TOKEN_TTL = 3600      # 1 hour
    REFRESH_TOKEN_TTL = 86400 * 30  # 30 days

    def __init__(self, private_key_pem: bytes, public_key_pem: bytes) -> None:
        self._private_key = load_pem_private_key(private_key_pem, password=None)
        self._public_key = load_pem_public_key(public_key_pem)

    @classmethod
    def generate(cls) -> "JWTManager":
        """Generate a new RSA-2048 keypair for JWT signing."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        public_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return cls(private_pem, public_pem)

    @classmethod
    def from_pem_files(cls, private_path: str, public_path: str) -> "JWTManager":
        with open(private_path, "rb") as f:
            private_pem = f.read()
        with open(public_path, "rb") as f:
            public_pem = f.read()
        return cls(private_pem, public_pem)

    def create_access_token(
        self,
        user_id: str,
        org_id: Optional[str] = None,
        roles: Optional[list] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a signed access token."""
        return self._create_token(
            subject=user_id,
            token_type="access",
            ttl=self.ACCESS_TOKEN_TTL,
            extra={
                "org_id": org_id,
                "roles": roles or [],
                **(extra_claims or {}),
            },
        )

    def create_refresh_token(self, user_id: str, org_id: Optional[str] = None) -> str:
        """Create a refresh token."""
        return self._create_token(
            subject=user_id,
            token_type="refresh",
            ttl=self.REFRESH_TOKEN_TTL,
            extra={"org_id": org_id},
        )

    def verify(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT token.
        Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
        """
        import jwt as pyjwt
        payload = pyjwt.decode(
            token,
            self._public_key,
            algorithms=["RS256"],
            options={"require": ["exp", "iat", "sub"]},
        )
        return payload

    def get_public_key_pem(self) -> bytes:
        return self._public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def get_jwks(self) -> Dict[str, Any]:
        """Return JWK Set for public key distribution."""
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        import base64
        import struct
        pub = self._public_key
        if not isinstance(pub, RSAPublicKey):
            raise ValueError("Not RSA key")
        pub_numbers = pub.public_key().public_numbers() if hasattr(pub, "public_key") else pub.public_numbers()
        n = pub_numbers.n
        e = pub_numbers.e

        def int_to_b64(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "n": int_to_b64(n),
                    "e": int_to_b64(e),
                }
            ]
        }

    # ------------------------------------------------------------------

    def _create_token(
        self,
        subject: str,
        token_type: str,
        ttl: int,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        import jwt as pyjwt
        now = int(time.time())
        payload = {
            "sub": subject,
            "iat": now,
            "exp": now + ttl,
            "jti": str(uuid.uuid4()),
            "type": token_type,
            **(extra or {}),
        }
        return pyjwt.encode(payload, self._private_key, algorithm="RS256")
