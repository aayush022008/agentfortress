"""TOTP MFA — Google Authenticator compatible with backup codes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
import urllib.parse
from typing import List, Optional, Tuple


class TOTPManager:
    """
    TOTP (Time-based One-Time Password) manager.
    Compatible with Google Authenticator, Authy, and other TOTP apps.

    Usage::

        mgr = TOTPManager()
        secret, otpauth_url = mgr.setup("alice@corp.com", issuer="AgentShield")
        # Show QR code from otpauth_url to user ...
        is_valid = mgr.verify(secret, code_from_user)
    """

    DIGITS = 6
    STEP = 30  # seconds
    VALID_WINDOWS = 1  # allow ±1 window for clock drift

    def generate_secret(self) -> str:
        """Generate a new base32-encoded TOTP secret."""
        return base64.b32encode(os.urandom(20)).decode("utf-8").rstrip("=")

    def setup(
        self,
        user_email: str,
        issuer: str = "AgentShield",
        secret: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Set up TOTP for a user.
        Returns (secret, otpauth_url) where otpauth_url can be encoded as a QR code.
        """
        secret = secret or self.generate_secret()
        label = urllib.parse.quote(f"{issuer}:{user_email}")
        params = urllib.parse.urlencode({
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": self.DIGITS,
            "period": self.STEP,
        })
        otpauth_url = f"otpauth://totp/{label}?{params}"
        return secret, otpauth_url

    def generate_code(self, secret: str, timestamp: Optional[float] = None) -> str:
        """Generate the current TOTP code for a secret."""
        ts = int((timestamp or time.time()) / self.STEP)
        return self._hotp(secret, ts)

    def verify(self, secret: str, code: str, timestamp: Optional[float] = None) -> bool:
        """Verify a TOTP code. Returns True if valid."""
        ts = int((timestamp or time.time()) / self.STEP)
        for delta in range(-self.VALID_WINDOWS, self.VALID_WINDOWS + 1):
            expected = self._hotp(secret, ts + delta)
            if hmac.compare_digest(expected, code.strip()):
                return True
        return False

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate one-time backup codes."""
        return [secrets.token_hex(4).upper() for _ in range(count)]

    def verify_backup_code(
        self, code: str, valid_codes: List[str]
    ) -> Tuple[bool, List[str]]:
        """
        Verify a backup code and consume it.
        Returns (is_valid, remaining_codes).
        """
        code = code.strip().upper()
        if code in valid_codes:
            remaining = [c for c in valid_codes if c != code]
            return True, remaining
        return False, valid_codes

    # ------------------------------------------------------------------

    def _hotp(self, secret: str, counter: int) -> str:
        """Compute HOTP value for a given counter."""
        # Pad secret to multiple of 8 if needed
        padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(padded)
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(code % (10 ** self.DIGITS)).zfill(self.DIGITS)
