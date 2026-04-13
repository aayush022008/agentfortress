"""
Session replay functionality for AgentShield.

Allows reconstructing and replaying the full timeline of an agent session
for incident investigation and debugging.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ReplayEvent:
    """A single event in a session replay timeline."""

    event_id: str
    event_type: str
    agent_name: str
    timestamp: float
    data: dict
    threat_score: int
    blocked: bool
    latency_ms: Optional[float]
    relative_time_ms: float = 0.0  # Time since session start


@dataclass
class SessionReplay:
    """Complete replay of an agent session."""

    session_id: str
    events: list[ReplayEvent] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    total_events: int = 0
    total_llm_calls: int = 0
    total_tool_calls: int = 0
    max_threat_score: int = 0
    had_violations: bool = False

    @property
    def duration_ms(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "total_events": self.total_events,
            "total_llm_calls": self.total_llm_calls,
            "total_tool_calls": self.total_tool_calls,
            "max_threat_score": self.max_threat_score,
            "had_violations": self.had_violations,
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "agent_name": e.agent_name,
                    "timestamp": e.timestamp,
                    "relative_time_ms": e.relative_time_ms,
                    "data": e.data,
                    "threat_score": e.threat_score,
                    "blocked": e.blocked,
                    "latency_ms": e.latency_ms,
                }
                for e in self.events
            ],
        }


class SessionReplayer:
    """
    Reconstructs session replays from stored events.

    Works with both LocalTransport (SQLite) and remote server data.
    """

    def build_replay(self, events: list[dict]) -> SessionReplay:
        """
        Build a SessionReplay from a list of raw event dicts.

        Args:
            events: List of event dicts (from LocalTransport or server API)

        Returns:
            SessionReplay with computed statistics
        """
        if not events:
            return SessionReplay(session_id="")

        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))
        session_id = sorted_events[0].get("session_id", "")
        start_time = sorted_events[0].get("timestamp", 0)
        end_time = sorted_events[-1].get("timestamp", 0)

        replay_events: list[ReplayEvent] = []
        llm_calls = 0
        tool_calls = 0
        max_threat = 0
        had_violations = False

        for event in sorted_events:
            event_type = event.get("event_type", "")
            threat_score = event.get("threat_score", 0)
            blocked = bool(event.get("blocked", False))

            if "llm" in event_type:
                llm_calls += 1
            elif "tool" in event_type:
                tool_calls += 1

            max_threat = max(max_threat, threat_score)
            if blocked:
                had_violations = True

            relative_ms = (event.get("timestamp", start_time) - start_time) * 1000

            replay_events.append(
                ReplayEvent(
                    event_id=event.get("event_id", ""),
                    event_type=event_type,
                    agent_name=event.get("agent_name", ""),
                    timestamp=event.get("timestamp", 0),
                    data=event.get("data", {}),
                    threat_score=threat_score,
                    blocked=blocked,
                    latency_ms=event.get("latency_ms"),
                    relative_time_ms=relative_ms,
                )
            )

        return SessionReplay(
            session_id=session_id,
            events=replay_events,
            start_time=start_time,
            end_time=end_time,
            total_events=len(replay_events),
            total_llm_calls=llm_calls,
            total_tool_calls=tool_calls,
            max_threat_score=max_threat,
            had_violations=had_violations,
        )

    def export_json(self, replay: SessionReplay, path: str) -> None:
        """Export a session replay to a JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(replay.to_dict(), f, indent=2)

    def load_json(self, path: str) -> SessionReplay:
        """Load a session replay from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        events = [
            ReplayEvent(**{k: v for k, v in e.items()})
            for e in data.get("events", [])
        ]
        return SessionReplay(
            session_id=data["session_id"],
            events=events,
            start_time=data.get("start_time", 0),
            end_time=data.get("end_time", 0),
            total_events=data.get("total_events", 0),
            total_llm_calls=data.get("total_llm_calls", 0),
            total_tool_calls=data.get("total_tool_calls", 0),
            max_threat_score=data.get("max_threat_score", 0),
            had_violations=data.get("had_violations", False),
        )
