"""PagerDuty integration — create/resolve incidents via Events API v2."""
from __future__ import annotations

import json
import logging
import socket
import time
from typing import Any, Dict, Optional
from urllib import request, error

logger = logging.getLogger(__name__)

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

SEVERITY_MAP = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
    "info": "info",
}


class PagerDutyIntegration:
    """
    Creates and resolves PagerDuty incidents from AgentShield alerts.

    Usage::

        pd = PagerDutyIntegration(routing_key="your-integration-key")
        dedup_key = pd.trigger(alert)
        # ... later ...
        pd.resolve(dedup_key)
    """

    def __init__(self, routing_key: str) -> None:
        self.routing_key = routing_key
        self._dedup_keys: Dict[str, str] = {}  # alert_id → dedup_key

    def trigger(self, alert: Dict[str, Any]) -> str:
        """Trigger a PagerDuty incident. Returns dedup_key."""
        severity = SEVERITY_MAP.get(alert.get("severity", "info"), "warning")
        dedup_key = alert.get("alert_id") or alert.get("id") or f"agentshield-{int(time.time())}"

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": f"AgentShield: {alert.get('title', alert.get('alert_type', 'Security Alert'))}",
                "severity": severity,
                "source": socket.gethostname(),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "component": "AgentShield",
                "group": alert.get("agent_id", "unknown-agent"),
                "class": alert.get("alert_type", "security"),
                "custom_details": {
                    "agent_id": alert.get("agent_id"),
                    "session_id": alert.get("session_id"),
                    "description": alert.get("description"),
                    "severity": alert.get("severity"),
                },
            },
            "links": [
                {
                    "href": f"http://agentshield.local/alerts/{dedup_key}",
                    "text": "View in AgentShield",
                }
            ],
        }

        self._send(payload)
        self._dedup_keys[str(alert.get("alert_id", dedup_key))] = dedup_key
        return dedup_key

    def resolve(self, dedup_key: str) -> bool:
        """Resolve a PagerDuty incident by dedup_key."""
        payload = {
            "routing_key": self.routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        }
        return self._send(payload)

    def acknowledge(self, dedup_key: str) -> bool:
        """Acknowledge a PagerDuty incident."""
        payload = {
            "routing_key": self.routing_key,
            "event_action": "acknowledge",
            "dedup_key": dedup_key,
        }
        return self._send(payload)

    # ------------------------------------------------------------------

    def _send(self, payload: Dict[str, Any]) -> bool:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            PAGERDUTY_EVENTS_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 201, 202)
        except error.URLError as e:
            logger.error("PagerDuty send failed: %s", e)
            return False
