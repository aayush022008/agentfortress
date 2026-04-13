"""Jira integration — create tickets for security incidents."""
from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, Optional
from urllib import request, error

logger = logging.getLogger(__name__)

PRIORITY_MAP = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


class JiraIntegration:
    """
    Creates Jira issues for AgentShield security incidents.

    Usage::

        jira = JiraIntegration(
            base_url="https://your-org.atlassian.net",
            email="user@org.com",
            api_token="your-api-token",
            project_key="SEC",
        )
        issue_key = jira.create_issue(alert)
        jira.add_comment(issue_key, "Investigation started.")
        jira.resolve_issue(issue_key)
    """

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Bug",
        labels: Optional[list] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        self.issue_type = issue_type
        self.labels = labels or ["agentshield", "security"]
        creds = f"{email}:{api_token}"
        self._auth_header = "Basic " + base64.b64encode(creds.encode()).decode()

    def create_issue(self, alert: Dict[str, Any]) -> str:
        """Create a Jira issue. Returns the issue key (e.g. SEC-123)."""
        severity = alert.get("severity", "medium").lower()
        title = alert.get("title") or alert.get("alert_type") or "AgentShield Security Alert"
        description = (
            f"*AgentShield Security Incident*\n\n"
            f"*Severity:* {severity.upper()}\n"
            f"*Agent ID:* {alert.get('agent_id', 'N/A')}\n"
            f"*Session ID:* {alert.get('session_id', 'N/A')}\n\n"
            f"*Description:*\n{alert.get('description', 'No description')}\n\n"
            f"*Details:*\n{{code}}{json.dumps(alert, indent=2, default=str)[:2000]}{{code}}"
        )

        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[AgentShield] {title}",
                "description": description,
                "issuetype": {"name": self.issue_type},
                "priority": {"name": PRIORITY_MAP.get(severity, "Medium")},
                "labels": self.labels,
            }
        }

        resp = self._request("POST", "/rest/api/2/issue", payload)
        return resp.get("key", "")

    def add_comment(self, issue_key: str, comment: str) -> bool:
        """Add a comment to an existing Jira issue."""
        self._request("POST", f"/rest/api/2/issue/{issue_key}/comment", {"body": comment})
        return True

    def resolve_issue(self, issue_key: str, transition_name: str = "Done") -> bool:
        """Transition an issue to resolved state."""
        # Get available transitions
        transitions = self._request("GET", f"/rest/api/2/issue/{issue_key}/transitions")
        for t in transitions.get("transitions", []):
            if t.get("name") == transition_name:
                self._request(
                    "POST",
                    f"/rest/api/2/issue/{issue_key}/transitions",
                    {"transition": {"id": t["id"]}},
                )
                return True
        return False

    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Dict[str, Any]:
        url = self.base_url + path
        data = json.dumps(body).encode("utf-8") if body else None
        req = request.Request(
            url,
            data=data,
            headers={
                "Authorization": self._auth_header,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method=method,
        )
        try:
            with request.urlopen(req, timeout=15) as resp:
                body_bytes = resp.read()
                return json.loads(body_bytes) if body_bytes else {}
        except error.HTTPError as e:
            logger.error("Jira API error %s: %s", e.code, e.read().decode(errors="replace"))
            return {}
        except error.URLError as e:
            logger.error("Jira URL error: %s", e)
            return {}
