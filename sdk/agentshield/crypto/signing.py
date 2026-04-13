"""
Ed25519 signing for audit events — tamper-proof logs.
Every audit event is signed with a private key; verifiers use the public key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


@dataclass
class SignedEvent:
    """An audit event with its Ed25519 signature."""

    payload: Dict[str, Any]
    """Original event data."""

    signature_b64: str
    """Base64-encoded Ed25519 signature over the canonical payload bytes."""

    public_key_b64: str
    """Base64-encoded DER public key used to verify the signature."""

    signed_at: float
    """Unix timestamp when the event was signed."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload": self.payload,
            "signature": self.signature_b64,
            "public_key": self.public_key_b64,
            "signed_at": self.signed_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignedEvent":
        return cls(
            payload=d["payload"],
            signature_b64=d["signature"],
            public_key_b64=d["public_key"],
            signed_at=d["signed_at"],
        )


class EventSigner:
    """
    Signs and verifies audit events using Ed25519.

    Usage::

        signer = EventSigner.generate()
        signed = signer.sign({"event_type": "tool_call", "tool": "bash"})
        assert signer.verify(signed)

        # Persist keys
        priv_pem = signer.export_private_key_pem()
        pub_pem = signer.export_public_key_pem()
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
    ) -> None:
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()

        # Cache base64-encoded DER public key
        der_pub = self._public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self._pub_b64 = base64.b64encode(der_pub).decode()

    @classmethod
    def generate(cls) -> "EventSigner":
        """Generate a new Ed25519 key pair."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes, password: Optional[bytes] = None) -> "EventSigner":
        """Load signer from PEM-encoded private key."""
        key = load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("PEM key must be Ed25519")
        return cls(key)

    @classmethod
    def verifier_from_public_pem(cls, pem: bytes) -> "EventSigner._Verifier":
        """Return a verifier-only object from a PEM public key."""
        pub = load_pem_public_key(pem)
        if not isinstance(pub, Ed25519PublicKey):
            raise ValueError("PEM key must be Ed25519")
        return cls._Verifier(pub)

    def sign(self, event: Dict[str, Any]) -> SignedEvent:
        """Sign an event dict and return a SignedEvent."""
        canonical = self._canonicalize(event)
        sig_bytes = self._private_key.sign(canonical)
        sig_b64 = base64.b64encode(sig_bytes).decode()
        return SignedEvent(
            payload=event,
            signature_b64=sig_b64,
            public_key_b64=self._pub_b64,
            signed_at=time.time(),
        )

    def verify(self, signed_event: SignedEvent) -> bool:
        """Verify a signed event. Returns True if signature is valid."""
        try:
            canonical = self._canonicalize(signed_event.payload)
            sig_bytes = base64.b64decode(signed_event.signature_b64)
            self._public_key.verify(sig_bytes, canonical)
            return True
        except Exception:
            return False

    def export_private_key_pem(self, password: Optional[bytes] = None) -> bytes:
        """Export private key as PEM bytes."""
        encryption = (
            NoEncryption()
            if password is None
            else __import__("cryptography.hazmat.primitives.serialization", fromlist=["BestAvailableEncryption"]).BestAvailableEncryption(password)
        )
        return self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption)

    def export_public_key_pem(self) -> bytes:
        """Export public key as PEM bytes."""
        return self._public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    @staticmethod
    def _canonicalize(event: Dict[str, Any]) -> bytes:
        """Produce a deterministic canonical byte representation of the event."""
        return json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()

    class _Verifier:
        """Verifier-only object backed by an Ed25519 public key."""

        def __init__(self, public_key: Ed25519PublicKey) -> None:
            self._public_key = public_key

        def verify(self, signed_event: SignedEvent) -> bool:
            try:
                canonical = EventSigner._canonicalize(signed_event.payload)
                sig_bytes = base64.b64decode(signed_event.signature_b64)
                self._public_key.verify(sig_bytes, canonical)
                return True
            except Exception:
                return False
