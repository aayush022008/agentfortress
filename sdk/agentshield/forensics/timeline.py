"""
Incident timeline reconstructor — builds a complete timeline from audit logs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TimelineEvent:
    timestamp: float
    event_type: str
    description: str
    severity: str  # info | low | medium | high | critical
    raw_event: Dict[str, Any] = field(default_factory=dict)
    agent_id: Optional[str] = None
    session_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
        }


@dataclass
class IncidentTimelineReport:
    incident_id: str
    start_time: float
    end_time: float
    duration_seconds: float
    events: List[TimelineEvent]
    summary: str
    affected_agents: List[str]
    affected_sessions: List[str]
    severity: str


class IncidentTimeline:
    """
    Reconstructs incident timelines from audit log events.

    Usage::

        timeline = IncidentTimeline()
        timeline.ingest_events(audit_events)
        report = timeline.build_report(
            incident_id="INC-001",
            start_time=1710000000,
            end_time=1710003600,
        )
        print(report.summary)
    """

    def __init__(self) -> None:
        self._events: List[TimelineEvent] = []

    def ingest_events(self, raw_events: List[Dict[str, Any]]) -> int:
        """
        Parse raw audit events into TimelineEvents.
        Returns number of events ingested.
        """
        count = 0
        for e in raw_events:
            te = self._parse_event(e)
            if te:
                self._events.append(te)
                count += 1
        self._events.sort(key=lambda e: e.timestamp)
        return count

    def ingest_log_file(self, path: str) -> int:
        """Parse a JSONL audit log file."""
        events = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return self.ingest_events(events)

    def build_report(
        self,
        incident_id: str,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        agent_filter: Optional[List[str]] = None,
        min_severity: str = "info",
    ) -> IncidentTimelineReport:
        """Build a timeline report for a given time window."""
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_sev_idx = severity_order.index(min_severity) if min_severity in severity_order else 0

        filtered = [
            e for e in self._events
            if (start_time is None or e.timestamp >= start_time)
            and (end_time is None or e.timestamp <= end_time)
            and (agent_filter is None or e.agent_id in agent_filter)
            and severity_order.index(e.severity if e.severity in severity_order else "info") >= min_sev_idx
        ]

        if not filtered:
            return IncidentTimelineReport(
                incident_id=incident_id,
                start_time=start_time or 0,
                end_time=end_time or 0,
                duration_seconds=0,
                events=[],
                summary="No events found in the specified window.",
                affected_agents=[],
                affected_sessions=[],
                severity="info",
            )

        t_start = filtered[0].timestamp
        t_end = filtered[-1].timestamp
        agents = list({e.agent_id for e in filtered if e.agent_id})
        sessions = list({e.session_id for e in filtered if e.session_id})

        # Determine overall severity
        sev_counts = {s: 0 for s in severity_order}
        for e in filtered:
            sev_counts[e.severity if e.severity in sev_counts else "info"] += 1
        overall_sev = "info"
        for sev in reversed(severity_order):
            if sev_counts[sev] > 0:
                overall_sev = sev
                break

        summary_lines = [
            f"Incident {incident_id}: {len(filtered)} events over {(t_end - t_start):.0f}s",
            f"Affected agents: {', '.join(agents) or 'unknown'}",
            f"Severity: {overall_sev.upper()}",
        ]
        high_sev = [e for e in filtered if e.severity in ("high", "critical")]
        if high_sev:
            summary_lines.append("Key events:")
            for e in high_sev[:5]:
                summary_lines.append(f"  [{e.severity.upper()}] {e.description}")

        return IncidentTimelineReport(
            incident_id=incident_id,
            start_time=t_start,
            end_time=t_end,
            duration_seconds=t_end - t_start,
            events=filtered,
            summary="\n".join(summary_lines),
            affected_agents=agents,
            affected_sessions=sessions,
            severity=overall_sev,
        )

    def get_events(
        self,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
    ) -> List[TimelineEvent]:
        """Return events filtered by time range."""
        return [
            e for e in self._events
            if (start_time is None or e.timestamp >= start_time)
            and (end_time is None or e.timestamp <= end_time)
        ]

    # ------------------------------------------------------------------

    @staticmethod
    def _parse_event(raw: Dict[str, Any]) -> Optional[TimelineEvent]:
        ts = raw.get("timestamp") or raw.get("created_at") or raw.get("time")
        if ts is None:
            return None
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            import datetime
            try:
                ts = datetime.datetime.fromisoformat(str(ts)).timestamp()
            except ValueError:
                return None

        event_type = raw.get("event_type") or raw.get("type") or "unknown"
        description = (
            raw.get("description")
            or raw.get("message")
            or raw.get("details")
            or f"{event_type}"
        )
        severity = raw.get("severity") or raw.get("level") or "info"
        if severity not in ("info", "low", "medium", "high", "critical"):
            severity = "info"

        return TimelineEvent(
            timestamp=ts,
            event_type=str(event_type),
            description=str(description)[:500],
            severity=severity,
            raw_event=raw,
            agent_id=raw.get("agent_id"),
            session_id=raw.get("session_id"),
        )
