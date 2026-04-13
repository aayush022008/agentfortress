"""Stripe billing integration — subscriptions, invoices, webhooks."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional
from urllib import request, error

logger = logging.getLogger(__name__)

STRIPE_API_BASE = "https://api.stripe.com/v1"


class StripeIntegration:
    """
    Stripe billing integration for AgentShield subscriptions.

    Usage::

        stripe = StripeIntegration(api_key="sk_live_...")
        customer = stripe.create_customer("alice@corp.com", "Acme Corp")
        sub = stripe.create_subscription(customer["id"], price_id="price_xxx")
    """

    def __init__(self, api_key: str, webhook_secret: Optional[str] = None) -> None:
        self.api_key = api_key
        self.webhook_secret = webhook_secret

    def create_customer(
        self,
        email: str,
        name: str = "",
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a Stripe customer."""
        data = {"email": email}
        if name:
            data["name"] = name
        if org_id:
            data["metadata[org_id]"] = org_id
        return self._post("/customers", data)

    def create_subscription(
        self,
        customer_id: str,
        price_id: str,
        trial_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create a Stripe subscription."""
        data = {
            "customer": customer_id,
            "items[0][price]": price_id,
        }
        if trial_days:
            data["trial_period_days"] = str(trial_days)
        return self._post("/subscriptions", data)

    def cancel_subscription(
        self, subscription_id: str, at_period_end: bool = True
    ) -> Dict[str, Any]:
        """Cancel a subscription."""
        data = {"cancel_at_period_end": "true" if at_period_end else "false"}
        return self._post(f"/subscriptions/{subscription_id}", data, method="DELETE" if not at_period_end else "POST")

    def get_subscription(self, subscription_id: str) -> Dict[str, Any]:
        return self._get(f"/subscriptions/{subscription_id}")

    def list_invoices(self, customer_id: str, limit: int = 10) -> Dict[str, Any]:
        return self._get(f"/invoices?customer={customer_id}&limit={limit}")

    def create_billing_portal(
        self, customer_id: str, return_url: str
    ) -> Dict[str, Any]:
        """Create a Stripe billing portal session."""
        data = {"customer": customer_id, "return_url": return_url}
        return self._post("/billing_portal/sessions", data)

    def verify_webhook(self, payload: bytes, signature: str) -> Optional[Dict[str, Any]]:
        """Verify a Stripe webhook signature. Returns event dict or None."""
        if not self.webhook_secret:
            raise ValueError("webhook_secret not configured")
        try:
            import hmac
            import hashlib
            import time

            parts = dict(p.split("=", 1) for p in signature.split(","))
            timestamp = parts.get("t", "0")
            v1 = parts.get("v1", "")

            signed_payload = f"{timestamp}.{payload.decode()}"
            expected = hmac.new(
                self.webhook_secret.encode(),
                signed_payload.encode(),
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(expected, v1):
                return None

            # Reject events older than 5 minutes
            if abs(int(time.time()) - int(timestamp)) > 300:
                return None

            return json.loads(payload)
        except Exception as e:
            logger.error("Webhook verification failed: %s", e)
            return None

    # ------------------------------------------------------------------

    def _post(self, path: str, data: Dict[str, str], method: str = "POST") -> Dict[str, Any]:
        from urllib.parse import urlencode
        encoded = urlencode(data).encode("utf-8")
        req = request.Request(
            STRIPE_API_BASE + path,
            data=encoded,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method=method,
        )
        try:
            with request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except error.HTTPError as e:
            body = e.read().decode(errors="replace")
            logger.error("Stripe API error %d: %s", e.code, body)
            try:
                return json.loads(body)
            except Exception:
                return {"error": body}

    def _get(self, path: str) -> Dict[str, Any]:
        req = request.Request(
            STRIPE_API_BASE + path,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            with request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception as e:
            logger.error("Stripe GET error: %s", e)
            return {}
