"""
Slack integration — post AgentShield alerts to Slack with rich formatting.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from urllib import request, error

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFA500",
    "low": "#FFFF00",
    "info": "#36A64F",
}


class SlackIntegration:
    """
    Posts alerts and notifications to a Slack channel via Incoming Webhooks.

    Usage::

        slack = SlackIntegration(webhook_url="https://hooks.slack.com/services/...")
        slack.post_alert(alert)
        slack.post_message("AgentShield started", channel="#security")
    """

    def __init__(
        self,
        webhook_url: str,
        default_channel: Optional[str] = None,
        bot_name: str = "AgentShield",
        icon_emoji: str = ":shield:",
    ) -> None:
        self.webhook_url = webhook_url
        self.default_channel = default_channel
        self.bot_name = bot_name
        self.icon_emoji = icon_emoji

    def post_alert(self, alert: Dict[str, Any]) -> bool:
        """Post a structured alert to Slack with rich formatting."""
        severity = alert.get("severity", "info").lower()
        color = SEVERITY_COLORS.get(severity, "#36A64F")

        attachment = {
            "color": color,
            "title": f":warning: AgentShield Alert — {alert.get('title', alert.get('alert_type', 'Unknown'))}",
            "text": alert.get("description", alert.get("message", "")),
            "fields": [
                {"title": "Severity", "value": severity.upper(), "short": True},
                {"title": "Agent ID", "value": alert.get("agent_id", "N/A"), "short": True},
                {"title": "Session", "value": alert.get("session_id", "N/A"), "short": True},
                {"title": "Time", "value": str(alert.get("created_at", "N/A")), "short": True},
            ],
            "footer": "AgentShield Security Platform",
            "footer_icon": "https://agentshield.io/logo.png",
            "ts": alert.get("created_at"),
        }

        payload: Dict[str, Any] = {
            "username": self.bot_name,
            "icon_emoji": self.icon_emoji,
            "attachments": [attachment],
        }
        if self.default_channel:
            payload["channel"] = self.default_channel

        return self._post(payload)

    def post_message(self, text: str, channel: Optional[str] = None) -> bool:
        """Post a simple text message."""
        payload: Dict[str, Any] = {
            "text": text,
            "username": self.bot_name,
            "icon_emoji": self.icon_emoji,
        }
        if channel or self.default_channel:
            payload["channel"] = channel or self.default_channel
        return self._post(payload)

    def post_incident_summary(self, incident: Dict[str, Any]) -> bool:
        """Post an incident summary with action buttons (if interactive)."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 Incident: {incident.get('title', 'Unknown')}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {incident.get('severity', 'N/A').upper()}"},
                    {"type": "mrkdwn", "text": f"*Status:* {incident.get('status', 'open')}"},
                    {"type": "mrkdwn", "text": f"*Agents Affected:* {incident.get('agents_affected', 0)}"},
                    {"type": "mrkdwn", "text": f"*Events:* {incident.get('event_count', 0)}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{incident.get('summary', 'No summary available')}"},
            },
            {"type": "divider"},
        ]
        payload: Dict[str, Any] = {
            "blocks": blocks,
            "username": self.bot_name,
            "icon_emoji": self.icon_emoji,
        }
        return self._post(payload)

    # ------------------------------------------------------------------

    def _post(self, payload: Dict[str, Any]) -> bool:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except error.URLError as e:
            logger.error("Slack post failed: %s", e)
            return False
        except Exception as e:
            logger.error("Slack post error: %s", e)
            return False
