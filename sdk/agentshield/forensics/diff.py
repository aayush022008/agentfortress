"""
Snapshot diff — compare two agent snapshots to see what changed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .snapshot import AgentSnapshot


@dataclass
class FieldDiff:
    path: str
    before: Any
    after: Any
    change_type: str  # added | removed | modified


@dataclass
class SnapshotDiff:
    snapshot_before_id: str
    snapshot_after_id: str
    time_delta: float
    events_added: int
    field_diffs: List[FieldDiff] = field(default_factory=list)
    context_changes: List[FieldDiff] = field(default_factory=list)
    tool_state_changes: List[FieldDiff] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"Diff: {self.snapshot_before_id[:8]}...  →  {self.snapshot_after_id[:8]}...",
            f"Time delta: {self.time_delta:.1f}s | New events: {self.events_added}",
            f"Context changes: {len(self.context_changes)}",
            f"Tool state changes: {len(self.tool_state_changes)}",
        ]
        for d in self.context_changes[:5]:
            lines.append(f"  [{d.change_type}] {d.path}: {repr(d.before)[:50]} → {repr(d.after)[:50]}")
        return "\n".join(lines)

    def has_changes(self) -> bool:
        return bool(self.context_changes or self.tool_state_changes or self.events_added > 0)


def diff_snapshots(before: AgentSnapshot, after: AgentSnapshot) -> SnapshotDiff:
    """
    Compute the diff between two snapshots.
    Returns a SnapshotDiff with all detected changes.
    """
    diff = SnapshotDiff(
        snapshot_before_id=before.snapshot_id,
        snapshot_after_id=after.snapshot_id,
        time_delta=after.timestamp - before.timestamp,
        events_added=after.events_count - before.events_count,
    )

    diff.context_changes = _diff_dicts("context", before.context, after.context)
    diff.tool_state_changes = _diff_dicts("tool_state", before.tool_state, after.tool_state)
    diff.field_diffs = diff.context_changes + diff.tool_state_changes

    return diff


def _diff_dicts(prefix: str, before: Dict, after: Dict, depth: int = 0) -> List[FieldDiff]:
    """Recursively diff two dicts, returning a flat list of FieldDiff."""
    if depth > 8:
        return []

    diffs: List[FieldDiff] = []
    all_keys = set(before.keys()) | set(after.keys())

    for key in sorted(all_keys):
        path = f"{prefix}.{key}"
        if key not in before:
            diffs.append(FieldDiff(path=path, before=None, after=after[key], change_type="added"))
        elif key not in after:
            diffs.append(FieldDiff(path=path, before=before[key], after=None, change_type="removed"))
        else:
            b_val = before[key]
            a_val = after[key]
            if isinstance(b_val, dict) and isinstance(a_val, dict):
                diffs.extend(_diff_dicts(path, b_val, a_val, depth + 1))
            elif b_val != a_val:
                diffs.append(FieldDiff(path=path, before=b_val, after=a_val, change_type="modified"))

    return diffs
