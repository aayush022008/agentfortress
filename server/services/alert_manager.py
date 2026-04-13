"""Alert manager — deduplication and creation."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database.models import Alert


SEVERITY_MAP = {
    range(0, 40): "info",
    range(40, 60): "warning",
    range(60, 80): "high",
    range(80, 101): "critical",
}


def _score_to_severity(score: int) -> str:
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "warning"
    return "info"


def _threat_type(reasons: list[str]) -> str:
    reasons_lower = " ".join(reasons).lower()
    if "prompt injection" in reasons_lower or "jailbreak" in reasons_lower:
        return "prompt_injection"
    elif "pii" in reasons_lower or "ssn" in reasons_lower or "email" in reasons_lower:
        return "pii_leakage"
    elif "exfil" in reasons_lower or "base64" in reasons_lower or "large output" in reasons_lower:
        return "data_exfiltration"
    elif "scope" in reasons_lower or "tool" in reasons_lower:
        return "scope_creep"
    elif "anomal" in reasons_lower or "rate" in reasons_lower:
        return "anomaly"
    return "threat_detected"


class AlertManager:
    """Creates and deduplicates alerts."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create_from_event(
        self,
        event: Any,
        threat_score: int,
        threat_reasons: list[str],
    ) -> Optional[Alert]:
        """Create an alert from an event, with deduplication."""
        alert_type = _threat_type(threat_reasons)
        severity = _score_to_severity(threat_score)

        # Dedup key: session + type + first reason hash
        dedup_content = f"{event.session_id}:{alert_type}:{threat_reasons[0] if threat_reasons else ''}"
        dedup_key = hashlib.md5(dedup_content.encode()).hexdigest()[:16]

        # Check for recent duplicate (within last 5 minutes)
        existing = await self._db.execute(
            select(Alert).where(
                Alert.dedup_key == dedup_key,
                Alert.status == "open",
            )
        )
        if existing.scalar_one_or_none():
            return None  # Deduplicated

        title = self._build_title(alert_type, event.agent_name, threat_score)
        description = "; ".join(threat_reasons[:3])

        alert = Alert(
            session_id=event.session_id,
            title=title,
            description=description,
            severity=severity,
            alert_type=alert_type,
            threat_score=threat_score,
            dedup_key=dedup_key,
            context={
                "event_type": event.event_type,
                "agent_name": event.agent_name,
                "reasons": threat_reasons,
            },
        )
        self._db.add(alert)
        return alert

    def _build_title(self, alert_type: str, agent_name: str, score: int) -> str:
        titles = {
            "prompt_injection": f"Prompt Injection Detected in {agent_name}",
            "pii_leakage": f"PII Leakage Detected from {agent_name}",
            "data_exfiltration": f"Data Exfiltration Attempt by {agent_name}",
            "scope_creep": f"Scope Creep: {agent_name} accessing unauthorized resources",
            "anomaly": f"Anomalous Behavior Detected in {agent_name}",
            "threat_detected": f"Security Threat Detected in {agent_name} (score: {score})",
        }
        return titles.get(alert_type, f"Security Alert from {agent_name}")
