"""Splunk HEC integration — forward AgentShield events to Splunk."""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional
from urllib import request, error
import ssl

logger = logging.getLogger(__name__)


class SplunkIntegration:
    """
    Forwards events to Splunk via the HTTP Event Collector (HEC).

    Usage::

        splunk = SplunkIntegration(
            hec_url="https://splunk.corp.com:8088",
            hec_token="your-hec-token",
            index="agentshield",
            sourcetype="agentshield:event",
        )
        splunk.send_event(event)
        splunk.send_batch(events)
    """

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        index: str = "agentshield",
        sourcetype: str = "agentshield:event",
        source: str = "agentshield",
        verify_ssl: bool = True,
    ) -> None:
        self.hec_url = hec_url.rstrip("/") + "/services/collector/event"
        self.hec_token = hec_token
        self.index = index
        self.sourcetype = sourcetype
        self.source = source
        self.verify_ssl = verify_ssl

    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send a single event to Splunk HEC."""
        payload = self._wrap(event)
        return self._post(json.dumps(payload).encode("utf-8"))

    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send multiple events to Splunk HEC in one request (newline-delimited)."""
        lines = [json.dumps(self._wrap(e)) for e in events]
        return self._post("\n".join(lines).encode("utf-8"))

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send an alert as a Splunk Notable Event."""
        event = {
            "alert_id": alert.get("alert_id") or alert.get("id"),
            "alert_type": alert.get("alert_type", "security"),
            "severity": alert.get("severity", "medium"),
            "agent_id": alert.get("agent_id"),
            "session_id": alert.get("session_id"),
            "description": alert.get("description"),
            "created_at": alert.get("created_at"),
            "_sourcetype": "agentshield:alert",
        }
        return self.send_event(event)

    # ------------------------------------------------------------------

    def _wrap(self, event: Dict[str, Any]) -> Dict[str, Any]:
        ts = event.get("timestamp") or event.get("created_at") or time.time()
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            ts = time.time()

        return {
            "time": ts,
            "host": "agentshield",
            "source": self.source,
            "sourcetype": event.pop("_sourcetype", self.sourcetype),
            "index": self.index,
            "event": event,
        }

    def _post(self, data: bytes) -> bool:
        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }
        req = request.Request(self.hec_url, data=data, headers=headers, method="POST")
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with request.urlopen(req, context=ctx, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error("Splunk HEC send failed: %s", e)
            return False
