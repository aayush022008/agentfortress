"""
Canary file manager — create monitored files and detect agent access.
"""
from __future__ import annotations

import hashlib
import os
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional


@dataclass
class CanaryFile:
    file_id: str
    path: str
    content_hash: str
    created_at: float = field(default_factory=time.time)
    access_count: int = 0
    modified: bool = False
    deleted: bool = False
    last_checked_at: Optional[float] = None

    def to_dict(self) -> Dict:
        return {
            "file_id": self.file_id,
            "path": self.path,
            "access_count": self.access_count,
            "modified": self.modified,
            "deleted": self.deleted,
        }


class CanaryFileManager:
    """
    Creates monitored canary files in specified directories.
    Periodically checks if files have been read, modified, or deleted.

    Uses file access time (atime) and content hash to detect access.

    Usage::

        mgr = CanaryFileManager(base_dir="/tmp/sandbox")
        mgr.on_access(lambda cf: alert(f"Canary accessed: {cf.path}"))
        canary = mgr.create("credentials.txt", content="SECRET_KEY=abc123")
        mgr.check_all()  # call periodically
    """

    def __init__(self, base_dir: Optional[str] = None) -> None:
        self._base_dir = base_dir or "/tmp/agentshield_canaries"
        self._canaries: Dict[str, CanaryFile] = {}
        self._callbacks: List[Callable[[CanaryFile, str], None]] = []

    def on_access(self, callback: Callable[[CanaryFile, str], None]) -> None:
        """Register callback for canary access/modification/deletion events."""
        self._callbacks.append(callback)

    def create(
        self,
        filename: str,
        content: Optional[str] = None,
        subdir: Optional[str] = None,
    ) -> CanaryFile:
        """Create a canary file and begin monitoring it."""
        target_dir = Path(self._base_dir)
        if subdir:
            target_dir = target_dir / subdir
        target_dir.mkdir(parents=True, exist_ok=True)

        path = target_dir / filename
        file_content = content or self._default_content(filename)
        path.write_text(file_content)

        content_hash = hashlib.sha256(file_content.encode()).hexdigest()

        # Record original atime/mtime
        st = path.stat()
        canary = CanaryFile(
            file_id=str(uuid.uuid4()),
            path=str(path),
            content_hash=content_hash,
        )
        self._canaries[canary.file_id] = canary
        return canary

    def check_all(self) -> List[Dict]:
        """
        Check all canary files for access/modification/deletion.
        Returns list of events detected.
        """
        events = []
        for canary in list(self._canaries.values()):
            p = Path(canary.path)
            canary.last_checked_at = time.time()

            if not p.exists():
                if not canary.deleted:
                    canary.deleted = True
                    event = {"type": "deleted", "path": canary.path}
                    events.append(event)
                    self._fire(canary, "deleted")
                continue

            # Check for modification via content hash
            try:
                current_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                if current_hash != canary.content_hash:
                    canary.modified = True
                    event = {"type": "modified", "path": canary.path}
                    events.append(event)
                    self._fire(canary, "modified")

                # Check atime for read detection (only on systems where atime is updated)
                st = p.stat()
                if hasattr(st, "st_atime") and st.st_atime > canary.created_at + 1:
                    canary.access_count += 1
                    event = {"type": "accessed", "path": canary.path}
                    events.append(event)
                    self._fire(canary, "accessed")
            except (IOError, OSError):
                pass

        return events

    def list_canaries(self) -> List[CanaryFile]:
        return list(self._canaries.values())

    def cleanup_all(self) -> None:
        """Remove all canary files from disk."""
        for canary in self._canaries.values():
            try:
                Path(canary.path).unlink(missing_ok=True)
            except OSError:
                pass
        self._canaries.clear()

    # ------------------------------------------------------------------

    def _default_content(self, filename: str) -> str:
        name_lower = filename.lower()
        if "credential" in name_lower or "secret" in name_lower:
            return (
                "# Production Credentials\n"
                f"API_KEY=sk-canary-{uuid.uuid4().hex[:32]}\n"
                f"DB_PASSWORD=canary-{uuid.uuid4().hex[:16]}\n"
                "# DO NOT SHARE\n"
            )
        if "ssh" in name_lower or "key" in name_lower:
            return (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                + "b3BlbnNzaC1rZXktdjEAAAA" + uuid.uuid4().hex * 2 + "\n"
                + "-----END OPENSSH PRIVATE KEY-----\n"
            )
        return f"CANARY_FILE_ID={uuid.uuid4()}\nThis file is monitored by AgentShield.\n"

    def _fire(self, canary: CanaryFile, event_type: str) -> None:
        for cb in self._callbacks:
            try:
                cb(canary, event_type)
            except Exception:
                pass
