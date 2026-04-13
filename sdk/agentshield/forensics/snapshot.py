"""
Agent state snapshots for forensic analysis.
"""
from __future__ import annotations

import copy
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AgentSnapshot:
    """Complete point-in-time snapshot of agent state."""

    snapshot_id: str
    agent_id: str
    session_id: str
    timestamp: float
    context: Dict[str, Any]
    """Agent's current context/memory."""
    tool_state: Dict[str, Any]
    """State of tools (open files, active connections, etc.)."""
    events_count: int
    last_event: Optional[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "context": self.context,
            "tool_state": self.tool_state,
            "events_count": self.events_count,
            "last_event": self.last_event,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AgentSnapshot":
        return cls(**d)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class SnapshotManager:
    """
    Takes and manages agent snapshots for forensic analysis.

    Usage::

        mgr = SnapshotManager(storage_dir="/var/agentshield/snapshots")
        snap = mgr.take_snapshot(
            agent_id="agent-001",
            session_id="sess-123",
            context={"messages": [...], "memory": {}},
            tool_state={"open_files": [], "active_requests": []},
            events=event_list,
        )
        loaded = mgr.load_snapshot(snap.snapshot_id)
    """

    def __init__(self, storage_dir: str = "/tmp/agentshield/snapshots") -> None:
        self._dir = Path(storage_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index: Dict[str, str] = {}  # snapshot_id → file path
        self._load_index()

    def take_snapshot(
        self,
        agent_id: str,
        session_id: str,
        context: Dict[str, Any],
        tool_state: Optional[Dict[str, Any]] = None,
        events: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentSnapshot:
        """Create and persist a new snapshot."""
        snap = AgentSnapshot(
            snapshot_id=str(uuid.uuid4()),
            agent_id=agent_id,
            session_id=session_id,
            timestamp=time.time(),
            context=copy.deepcopy(context),
            tool_state=copy.deepcopy(tool_state or {}),
            events_count=len(events or []),
            last_event=events[-1] if events else None,
            metadata=metadata or {},
        )
        self._persist(snap)
        return snap

    def load_snapshot(self, snapshot_id: str) -> Optional[AgentSnapshot]:
        """Load a snapshot by ID. Returns None if not found."""
        path = self._index.get(snapshot_id)
        if not path or not Path(path).exists():
            return None
        data = json.loads(Path(path).read_text())
        return AgentSnapshot.from_dict(data)

    def list_snapshots(
        self, agent_id: Optional[str] = None, session_id: Optional[str] = None
    ) -> List[AgentSnapshot]:
        """List all snapshots, optionally filtered by agent/session."""
        snapshots = []
        for snap_id, path in self._index.items():
            try:
                data = json.loads(Path(path).read_text())
                snap = AgentSnapshot.from_dict(data)
                if agent_id and snap.agent_id != agent_id:
                    continue
                if session_id and snap.session_id != session_id:
                    continue
                snapshots.append(snap)
            except (IOError, json.JSONDecodeError):
                continue
        return sorted(snapshots, key=lambda s: s.timestamp)

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot. Returns True if deleted."""
        path = self._index.pop(snapshot_id, None)
        if path:
            Path(path).unlink(missing_ok=True)
            self._save_index()
            return True
        return False

    # ------------------------------------------------------------------

    def _persist(self, snap: AgentSnapshot) -> None:
        path = self._dir / f"{snap.snapshot_id}.json"
        path.write_text(snap.to_json())
        self._index[snap.snapshot_id] = str(path)
        self._save_index()

    def _load_index(self) -> None:
        index_path = self._dir / "index.json"
        if index_path.exists():
            try:
                self._index = json.loads(index_path.read_text())
            except json.JSONDecodeError:
                self._index = {}

    def _save_index(self) -> None:
        (self._dir / "index.json").write_text(json.dumps(self._index, indent=2))
