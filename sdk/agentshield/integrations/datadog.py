"""Datadog integration — send metrics and events to Datadog."""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional
from urllib import request, error

logger = logging.getLogger(__name__)

DD_API_URL = "https://api.datadoghq.com"


class DatadogIntegration:
    """
    Sends AgentShield metrics and events to Datadog.

    Usage::

        dd = DatadogIntegration(api_key="your-api-key")
        dd.send_event(alert)
        dd.send_metric("agentshield.alerts.count", 1, tags=["severity:high"])
        dd.send_service_check("agentshield.health", status=0)
    """

    def __init__(
        self,
        api_key: str,
        app_key: Optional[str] = None,
        site: str = "datadoghq.com",
        default_tags: Optional[List[str]] = None,
    ) -> None:
        self.api_key = api_key
        self.app_key = app_key
        self.base_url = f"https://api.{site}"
        self.default_tags = default_tags or ["service:agentshield"]

    def send_event(self, alert: Dict[str, Any]) -> bool:
        """Send an alert as a Datadog event."""
        severity = alert.get("severity", "info").lower()
        alert_level_map = {
            "critical": "error", "high": "error",
            "medium": "warning", "low": "info", "info": "info",
        }
        tags = list(self.default_tags) + [
            f"severity:{severity}",
            f"agent_id:{alert.get('agent_id', 'unknown')}",
            f"alert_type:{alert.get('alert_type', 'unknown')}",
        ]
        payload = {
            "title": f"AgentShield: {alert.get('title', alert.get('alert_type', 'Alert'))}",
            "text": f"%%% \n{alert.get('description', '')} \n%%%",
            "date_happened": int(alert.get("created_at", time.time())),
            "alert_type": alert_level_map.get(severity, "info"),
            "tags": tags,
            "source_type_name": "agentshield",
        }
        return self._post("/api/v1/events", payload)

    def send_metric(
        self,
        metric_name: str,
        value: float,
        metric_type: str = "count",
        tags: Optional[List[str]] = None,
        timestamp: Optional[float] = None,
    ) -> bool:
        """Send a metric to Datadog."""
        ts = int(timestamp or time.time())
        all_tags = list(self.default_tags) + (tags or [])
        payload = {
            "series": [
                {
                    "metric": metric_name,
                    "points": [[ts, value]],
                    "type": metric_type,
                    "tags": all_tags,
                    "host": "agentshield",
                }
            ]
        }
        return self._post("/api/v1/series", payload)

    def send_service_check(
        self,
        check_name: str,
        status: int = 0,
        message: str = "",
        tags: Optional[List[str]] = None,
    ) -> bool:
        """
        Send a service check. status: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN.
        """
        payload = {
            "check": check_name,
            "status": status,
            "message": message,
            "tags": list(self.default_tags) + (tags or []),
            "timestamp": int(time.time()),
        }
        return self._post("/api/v1/check_run", payload)

    def send_log(self, message: str, level: str = "info", extra: Optional[Dict[str, Any]] = None) -> bool:
        """Send a log entry to Datadog Logs."""
        payload = {
            "message": message,
            "level": level,
            "service": "agentshield",
            "ddsource": "agentshield",
            "ddtags": ",".join(self.default_tags),
            **(extra or {}),
        }
        return self._post("/api/v2/logs", [payload])

    # ------------------------------------------------------------------

    def _post(self, path: str, payload: Any) -> bool:
        data = json.dumps(payload).encode("utf-8")
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "DD-API-KEY": self.api_key,
        }
        if self.app_key:
            headers["DD-APPLICATION-KEY"] = self.app_key

        req = request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 202)
        except Exception as e:
            logger.error("Datadog send failed: %s", e)
            return False
