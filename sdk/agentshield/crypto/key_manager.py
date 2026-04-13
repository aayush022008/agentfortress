"""
Key manager with rotation, versioning, and HSM integration interface.
"""
from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .encryption import FieldEncryptor


@dataclass
class KeyVersion:
    """A versioned encryption key."""

    version: int
    key_b64: str
    created_at: float
    rotated_at: Optional[float] = None
    active: bool = True

    def to_dict(self) -> Dict:
        return {
            "version": self.version,
            "key_b64": self.key_b64,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "KeyVersion":
        return cls(**d)


class KeyManager:
    """
    Manages versioned encryption keys with rotation support.

    Keys are stored in a JSON file (or can be loaded from an HSM).
    The active key is always the highest-version active key.

    Usage::

        km = KeyManager(keystore_path="/etc/agentshield/keys.json")
        km.initialize()  # creates initial key if not exists
        encryptor = km.get_encryptor()
        ciphertext = encryptor.encrypt("sensitive data")

        km.rotate()  # rotate to a new key
        # Old key is kept for decryption; new key used for encryption
    """

    def __init__(
        self,
        keystore_path: str = "agentshield-keys.json",
        hsm_provider: Optional["HSMProvider"] = None,
    ) -> None:
        self._path = Path(keystore_path)
        self._hsm = hsm_provider
        self._versions: Dict[int, KeyVersion] = {}

    def initialize(self) -> None:
        """Load existing keystore or create a new one with a fresh key."""
        if self._path.exists():
            self._load()
        else:
            self._create_initial_key()
            self._save()

    def get_encryptor(self, version: Optional[int] = None) -> FieldEncryptor:
        """Return an encryptor for the given version (or active version)."""
        if version is None:
            kv = self._active_key()
        else:
            kv = self._versions[version]
        return FieldEncryptor.from_base64(kv.key_b64)

    def rotate(self) -> KeyVersion:
        """Generate a new key version. Old keys remain for decryption."""
        # Deactivate current active key (it stays for decryption)
        current = self._active_key()
        current.rotated_at = time.time()

        # Create new key
        new_version = current.version + 1
        new_key = KeyVersion(
            version=new_version,
            key_b64=base64.b64encode(os.urandom(32)).decode(),
            created_at=time.time(),
            active=True,
        )
        # Mark old key as inactive
        current.active = False
        self._versions[new_version] = new_key
        self._save()
        return new_key

    def list_versions(self) -> List[KeyVersion]:
        """Return all key versions sorted by version number."""
        return sorted(self._versions.values(), key=lambda k: k.version)

    def decrypt_any(self, ciphertext: str) -> str:
        """
        Try all key versions to decrypt a ciphertext.
        Useful when re-encrypting old data after rotation.
        """
        for kv in sorted(self._versions.values(), key=lambda k: -k.version):
            try:
                enc = FieldEncryptor.from_base64(kv.key_b64)
                return enc.decrypt(ciphertext)
            except Exception:
                continue
        raise ValueError("Unable to decrypt with any available key version")

    # ------------------------------------------------------------------

    def _active_key(self) -> KeyVersion:
        active = [kv for kv in self._versions.values() if kv.active]
        if not active:
            raise RuntimeError("No active key — call initialize() first")
        return max(active, key=lambda k: k.version)

    def _create_initial_key(self) -> None:
        kv = KeyVersion(
            version=1,
            key_b64=base64.b64encode(os.urandom(32)).decode(),
            created_at=time.time(),
            active=True,
        )
        self._versions[1] = kv

    def _load(self) -> None:
        data = json.loads(self._path.read_text())
        self._versions = {
            int(v): KeyVersion.from_dict(kv) for v, kv in data["versions"].items()
        }

    def _save(self) -> None:
        data = {"versions": {str(v): kv.to_dict() for v, kv in self._versions.items()}}
        # Write atomically
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(self._path)
        self._path.chmod(0o600)


class HSMProvider:
    """
    Abstract HSM (Hardware Security Module) integration interface.
    Implement a concrete subclass for AWS CloudHSM, Azure Dedicated HSM,
    or HashiCorp Vault Transit Engine.
    """

    def generate_key(self, key_id: str) -> str:
        """Generate a key in the HSM. Returns a reference/handle."""
        return key_id

    def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using an HSM-stored key."""
        return plaintext

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using an HSM-stored key."""
        return ciphertext

    def rotate_key(self, key_id: str) -> str:
        """Rotate a key in the HSM. Returns new key handle."""
        return key_id
