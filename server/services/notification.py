"""Notification service — webhooks, email, Slack."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.request import urlopen, Request
from urllib.error import URLError

from ..config import settings

logger = logging.getLogger(__name__)


class NotificationService:
    """Sends notifications for high-severity alerts."""

    async def notify_alert(self, alert: Any) -> None:
        """Send notifications for a new alert."""
        if settings.slack_webhook_url and alert.severity in ("critical", "high"):
            await self._send_slack(alert)

    async def _send_slack(self, alert: Any) -> None:
        """Send a Slack notification."""
        try:
            color = "#FF0000" if alert.severity == "critical" else "#FF9900"
            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"🚨 AgentShield Alert: {alert.title}",
                    "text": alert.description,
                    "fields": [
                        {"title": "Severity", "value": alert.severity.upper(), "short": True},
                        {"title": "Threat Score", "value": str(alert.threat_score), "short": True},
                        {"title": "Session", "value": alert.session_id or "N/A", "short": True},
                        {"title": "Type", "value": alert.alert_type, "short": True},
                    ],
                }]
            }
            data = json.dumps(payload).encode()
            req = Request(
                settings.slack_webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            urlopen(req, timeout=5)
        except (URLError, Exception) as e:
            logger.error(f"Slack notification failed: {e}")
