"""
AES-256-GCM encryption for sensitive fields at rest.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict, List, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class FieldEncryptor:
    """
    Encrypts and decrypts individual fields within a dict using AES-256-GCM.

    Usage::

        encryptor = FieldEncryptor.generate()
        record = {"user": "alice", "ssn": "123-45-6789", "event": "login"}
        encrypted = encryptor.encrypt_fields(record, fields=["ssn"])
        decrypted = encryptor.decrypt_fields(encrypted, fields=["ssn"])
        assert decrypted["ssn"] == "123-45-6789"
    """

    NONCE_SIZE = 12  # bytes; GCM standard
    TAG_PREFIX = "enc:aes256gcm:"

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes")
        self._aesgcm = AESGCM(key)
        self._key = key

    @classmethod
    def generate(cls) -> "FieldEncryptor":
        """Generate a new random 256-bit key."""
        return cls(os.urandom(32))

    @classmethod
    def from_base64(cls, b64_key: str) -> "FieldEncryptor":
        """Load encryptor from a base64-encoded 32-byte key."""
        key = base64.b64decode(b64_key)
        return cls(key)

    def export_key_b64(self) -> str:
        """Export the key as a base64 string for storage."""
        return base64.b64encode(self._key).decode()

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string and return a prefixed ciphertext string.
        Format: ``enc:aes256gcm:<b64(nonce+ciphertext)>``
        """
        nonce = os.urandom(self.NONCE_SIZE)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode(), None)
        blob = base64.b64encode(nonce + ct).decode()
        return f"{self.TAG_PREFIX}{blob}"

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt a string produced by :meth:`encrypt`.
        Raises ValueError if the ciphertext is not in the expected format.
        """
        if not ciphertext.startswith(self.TAG_PREFIX):
            raise ValueError("Not an encrypted field value")
        blob = base64.b64decode(ciphertext[len(self.TAG_PREFIX):])
        nonce = blob[: self.NONCE_SIZE]
        ct = blob[self.NONCE_SIZE :]
        return self._aesgcm.decrypt(nonce, ct, None).decode()

    def encrypt_fields(
        self, record: Dict[str, Any], fields: List[str]
    ) -> Dict[str, Any]:
        """Return a copy of *record* with specified *fields* encrypted."""
        result = dict(record)
        for field in fields:
            if field in result and result[field] is not None:
                result[field] = self.encrypt(str(result[field]))
        return result

    def decrypt_fields(
        self, record: Dict[str, Any], fields: List[str]
    ) -> Dict[str, Any]:
        """Return a copy of *record* with specified *fields* decrypted."""
        result = dict(record)
        for field in fields:
            if field in result and isinstance(result[field], str):
                if result[field].startswith(self.TAG_PREFIX):
                    result[field] = self.decrypt(result[field])
        return result

    def encrypt_json(self, data: Any) -> str:
        """Serialize *data* to JSON and encrypt the whole thing."""
        return self.encrypt(json.dumps(data))

    def decrypt_json(self, ciphertext: str) -> Any:
        """Decrypt and deserialize a JSON blob encrypted with :meth:`encrypt_json`."""
        return json.loads(self.decrypt(ciphertext))
