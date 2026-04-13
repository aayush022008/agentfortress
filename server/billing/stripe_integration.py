"""Stripe billing — disabled. AgentShield is fully free and open-source."""
from __future__ import annotations

from typing import Any, Dict, Optional


class StripeIntegration:
    """
    Billing is disabled. AgentShield is 100% free and open-source.
    This class is a no-op stub kept for import compatibility.
    """

    def __init__(self, api_key: str = "", webhook_secret: Optional[str] = None) -> None:
        pass

    def create_customer(self, email: str, name: str, **kwargs) -> Dict[str, Any]:
        return {"id": "free", "email": email, "name": name}

    def create_subscription(self, *args, **kwargs) -> Dict[str, Any]:
        return {"id": "free", "status": "active", "plan": "free"}

    def cancel_subscription(self, *args, **kwargs) -> Dict[str, Any]:
        return {"status": "cancelled"}

    def get_subscription(self, *args, **kwargs) -> Optional[Dict[str, Any]]:
        return {"id": "free", "status": "active"}

    def create_portal_session(self, *args, **kwargs) -> Dict[str, Any]:
        return {"url": ""}

    def handle_webhook(self, *args, **kwargs) -> Dict[str, Any]:
        return {}
