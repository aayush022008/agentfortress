"""
Virtual filesystem overlay for agent sandboxing.
Restricts what paths an agent can read or write.
"""
from __future__ import annotations

import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class FilesystemPolicy:
    """Defines read/write permissions for sandboxed agents."""

    allowed_read_paths: List[str] = field(default_factory=list)
    """Absolute path prefixes the agent is allowed to read."""

    allowed_write_paths: List[str] = field(default_factory=list)
    """Absolute path prefixes the agent is allowed to write."""

    blocked_paths: List[str] = field(default_factory=list)
    """Absolute path prefixes that are explicitly blocked (takes precedence)."""

    allow_temp_dir: bool = True
    """Automatically allow reads/writes to a temporary scratch directory."""


class VirtualFilesystem:
    """
    Provides a managed scratch directory and enforces filesystem policies
    by wrapping open() and path operations via a context manager.

    In subprocess-based sandboxes you still need OS-level enforcement
    (seccomp, eBPF, or AppArmor). This class provides Python-level
    validation and a scratch-dir lifecycle.
    """

    def __init__(self, policy: Optional[FilesystemPolicy] = None) -> None:
        self.policy = policy or FilesystemPolicy()
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None  # type: ignore[type-arg]
        self._temp_path: Optional[str] = None
        self._violations: List[Dict[str, str]] = []

    def __enter__(self) -> "VirtualFilesystem":
        if self.policy.allow_temp_dir:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="agentshield_sandbox_")
            self._temp_path = self._temp_dir.name
            self.policy.allowed_read_paths.append(self._temp_path)
            self.policy.allowed_write_paths.append(self._temp_path)
        return self

    def __exit__(self, *_: object) -> None:
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None
            self._temp_path = None

    @property
    def scratch_dir(self) -> Optional[str]:
        """Return path to the temporary scratch directory, if created."""
        return self._temp_path

    def check_read(self, path: str) -> bool:
        """Return True if the agent is allowed to read *path*."""
        return self._check(path, self.policy.allowed_read_paths)

    def check_write(self, path: str) -> bool:
        """Return True if the agent is allowed to write *path*."""
        return self._check(path, self.policy.allowed_write_paths)

    def enforce_read(self, path: str) -> None:
        """Raise PermissionError if the agent is not allowed to read *path*."""
        if not self.check_read(path):
            self._record_violation("read", path)
            raise PermissionError(
                f"AgentShield sandbox: read access denied for '{path}'"
            )

    def enforce_write(self, path: str) -> None:
        """Raise PermissionError if the agent is not allowed to write *path*."""
        if not self.check_write(path):
            self._record_violation("write", path)
            raise PermissionError(
                f"AgentShield sandbox: write access denied for '{path}'"
            )

    def list_violations(self) -> List[Dict[str, str]]:
        """Return recorded filesystem violations."""
        return list(self._violations)

    def create_canary_file(self, name: str = "canary.txt") -> str:
        """
        Create a canary file in the scratch directory.
        Returns the full path.  Access to this file is tracked by the caller.
        """
        if self._temp_path is None:
            raise RuntimeError("VirtualFilesystem context not entered.")
        canary_path = os.path.join(self._temp_path, name)
        with open(canary_path, "w") as f:
            f.write(
                "CANARY: This file is monitored. Unauthorised access will be reported."
            )
        return canary_path

    # ------------------------------------------------------------------

    def _check(self, path: str, allowed: List[str]) -> bool:
        resolved = str(Path(path).resolve())
        # Blocked paths take precedence
        for blocked in self.policy.blocked_paths:
            if resolved.startswith(str(Path(blocked).resolve())):
                return False
        for allowed_prefix in allowed:
            if resolved.startswith(str(Path(allowed_prefix).resolve())):
                return True
        return False

    def _record_violation(self, access_type: str, path: str) -> None:
        import datetime
        self._violations.append(
            {
                "type": access_type,
                "path": path,
                "timestamp": datetime.datetime.utcnow().isoformat(),
            }
        )
