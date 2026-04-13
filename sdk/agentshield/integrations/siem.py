"""Generic SIEM integration — CEF and LEEF format event forwarding."""
from __future__ import annotations

import logging
import socket
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SIEMIntegration:
    """
    Generic SIEM integration that forwards events in CEF (Common Event Format)
    or LEEF (Log Event Extended Format) via syslog UDP/TCP.

    CEF is used by ArcSight, QRadar (also accepts CEF), and many others.
    LEEF is used by IBM QRadar natively.

    Usage::

        siem = SIEMIntegration(
            host="siem.corp.com", port=514,
            format="CEF", protocol="UDP",
            vendor="AgentShield", product="AgentShield", version="2.0",
        )
        siem.send_alert(alert)
        siem.send_events(events)
    """

    CEF_VERSION = "CEF:0"
    LEEF_VERSION = "LEEF:2.0"

    SEVERITY_CEF_MAP = {
        "critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1
    }

    def __init__(
        self,
        host: str,
        port: int = 514,
        format: str = "CEF",
        protocol: str = "UDP",
        vendor: str = "AgentShield",
        product: str = "AgentShield",
        version: str = "2.0",
        device_event_class_id: str = "AgentShield",
    ) -> None:
        self.host = host
        self.port = port
        self.format = format.upper()
        self.protocol = protocol.upper()
        self.vendor = vendor
        self.product = product
        self.version = version
        self.device_event_class_id = device_event_class_id

    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send an alert as a SIEM event."""
        if self.format == "CEF":
            msg = self._format_cef(alert)
        else:
            msg = self._format_leef(alert)
        return self._send(msg)

    def send_events(self, events: List[Dict[str, Any]]) -> int:
        """Send multiple events. Returns count of successfully sent."""
        count = 0
        for event in events:
            if self.send_alert(event):
                count += 1
        return count

    # ------------------------------------------------------------------

    def _format_cef(self, event: Dict[str, Any]) -> str:
        """Format event as CEF string."""
        severity = event.get("severity", "info").lower()
        sev_num = self.SEVERITY_CEF_MAP.get(severity, 1)
        name = event.get("title") or event.get("alert_type") or "AgentShield Event"

        # Extension fields
        ext = {
            "cs1": event.get("agent_id", ""),
            "cs1Label": "AgentID",
            "cs2": event.get("session_id", ""),
            "cs2Label": "SessionID",
            "cs3": event.get("description", "")[:200].replace("|", "\|").replace("\\", "\\\\"),
            "cs3Label": "Description",
            "rt": str(int(event.get("created_at", time.time()) * 1000)),
            "deviceSeverity": severity,
        }
        ext_str = " ".join(f"{k}={v}" for k, v in ext.items() if v)

        # CEF header: version|device_vendor|device_product|device_version|sig_id|name|severity|ext
        header_parts = [
            self.CEF_VERSION,
            self._escape_header(self.vendor),
            self._escape_header(self.product),
            self._escape_header(self.version),
            self._escape_header(event.get("alert_type", "unknown")),
            self._escape_header(name),
            str(sev_num),
            ext_str,
        ]
        return "|".join(header_parts)

    def _format_leef(self, event: Dict[str, Any]) -> str:
        """Format event as LEEF string."""
        severity = event.get("severity", "info")
        name = event.get("title") or event.get("alert_type") or "AgentShield Event"

        header = (
            f"{self.LEEF_VERSION}|{self.vendor}|{self.product}|{self.version}|{name}|"
        )
        attrs = {
            "sev": str(self.SEVERITY_CEF_MAP.get(severity.lower(), 1)),
            "agentID": event.get("agent_id", ""),
            "sessionID": event.get("session_id", ""),
            "devTime": str(int(event.get("created_at", time.time()) * 1000)),
            "msg": event.get("description", "")[:200],
        }
        attr_str = "\t".join(f"{k}={v}" for k, v in attrs.items() if v)
        return header + attr_str

    def _send(self, message: str) -> bool:
        data = message.encode("utf-8")
        try:
            if self.protocol == "UDP":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(data, (self.host, self.port))
            else:  # TCP
                with socket.create_connection((self.host, self.port), timeout=5) as s:
                    s.sendall(data + b"\n")
            return True
        except (socket.error, OSError) as e:
            logger.error("SIEM send failed: %s", e)
            return False

    @staticmethod
    def _escape_header(value: str) -> str:
        return str(value).replace("\\", "\\\\").replace("|", "\\|")
