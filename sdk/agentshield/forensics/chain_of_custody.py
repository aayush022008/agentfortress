"""
Cryptographically signed chain of custody for forensic evidence.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat
)


@dataclass
class CustodyEntry:
    """A single entry in the chain of custody."""

    entry_id: str
    action: str  # collected | transferred | analyzed | archived | sealed
    actor: str
    description: str
    evidence_hash: str
    timestamp: float
    signature: str
    public_key: str
    previous_entry_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "action": self.action,
            "actor": self.actor,
            "description": self.description,
            "evidence_hash": self.evidence_hash,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "public_key": self.public_key,
            "previous_entry_id": self.previous_entry_id,
        }


class ChainOfCustody:
    """
    Maintains a cryptographically signed chain of custody for evidence.

    Each entry is signed with Ed25519, chaining to the previous entry.
    The chain can be verified to detect tampering.

    Usage::

        coc = ChainOfCustody(case_id="CASE-001")
        coc.generate_keypair()
        coc.record("collected", actor="alice", description="Collected audit logs", evidence_hash=hash)
        coc.record("transferred", actor="bob", description="Transferred to forensics team", ...)
        assert coc.verify()
        coc.save("/output/chain-of-custody.json")
    """

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self._entries: List[CustodyEntry] = []
        self._private_key: Optional[Ed25519PrivateKey] = None
        self._pub_b64: Optional[str] = None

    def generate_keypair(self) -> bytes:
        """Generate a new Ed25519 keypair. Returns the public key PEM."""
        self._private_key = Ed25519PrivateKey.generate()
        pub = self._private_key.public_key()
        self._pub_b64 = base64.b64encode(
            pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        ).decode()
        return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def load_private_key_pem(self, pem: bytes) -> None:
        """Load an existing private key."""
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Must be Ed25519 key")
        self._private_key = key
        pub = key.public_key()
        self._pub_b64 = base64.b64encode(
            pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        ).decode()

    def record(
        self,
        action: str,
        actor: str,
        description: str,
        evidence_hash: str,
    ) -> CustodyEntry:
        """Add a signed entry to the chain."""
        if not self._private_key or not self._pub_b64:
            raise RuntimeError("Generate or load a keypair first.")

        prev_id = self._entries[-1].entry_id if self._entries else None
        entry_id = str(uuid.uuid4())
        timestamp = time.time()

        # Sign: hash(entry_id|action|actor|evidence_hash|timestamp|prev_id)
        sign_data = json.dumps({
            "entry_id": entry_id,
            "action": action,
            "actor": actor,
            "evidence_hash": evidence_hash,
            "timestamp": timestamp,
            "previous_entry_id": prev_id,
            "case_id": self.case_id,
        }, sort_keys=True).encode()

        sig = base64.b64encode(self._private_key.sign(sign_data)).decode()

        entry = CustodyEntry(
            entry_id=entry_id,
            action=action,
            actor=actor,
            description=description,
            evidence_hash=evidence_hash,
            timestamp=timestamp,
            signature=sig,
            public_key=self._pub_b64,
            previous_entry_id=prev_id,
        )
        self._entries.append(entry)
        return entry

    def verify(self) -> bool:
        """Verify the integrity of the entire chain. Returns True if valid."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        for entry in self._entries:
            try:
                pub_der = base64.b64decode(entry.public_key)
                pub_key = load_der_public_key(pub_der)
                if not isinstance(pub_key, Ed25519PublicKey):
                    return False

                sign_data = json.dumps({
                    "entry_id": entry.entry_id,
                    "action": entry.action,
                    "actor": entry.actor,
                    "evidence_hash": entry.evidence_hash,
                    "timestamp": entry.timestamp,
                    "previous_entry_id": entry.previous_entry_id,
                    "case_id": self.case_id,
                }, sort_keys=True).encode()

                sig = base64.b64decode(entry.signature)
                pub_key.verify(sig, sign_data)
            except Exception:
                return False
        return True

    def save(self, path: str) -> None:
        """Persist chain of custody to JSON."""
        data = {
            "case_id": self.case_id,
            "entries": [e.to_dict() for e in self._entries],
        }
        Path(path).write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: str) -> "ChainOfCustody":
        """Load chain of custody from JSON."""
        data = json.loads(Path(path).read_text())
        coc = cls(case_id=data["case_id"])
        coc._entries = [CustodyEntry(**e) for e in data["entries"]]
        return coc

    def get_entries(self) -> List[CustodyEntry]:
        return list(self._entries)
