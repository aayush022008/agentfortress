"""Billing API endpoints."""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

router = APIRouter(prefix="/api/billing", tags=["billing"])


class CreateSubscriptionRequest(BaseModel):
    org_id: str
    plan_id: str
    billing_cycle: str = "monthly"
    payment_method_id: Optional[str] = None


class UpgradePlanRequest(BaseModel):
    new_plan_id: str
    billing_cycle: Optional[str] = None


@router.get("/plans")
async def list_plans() -> Dict[str, Any]:
    """List all available billing plans."""
    from .plans import PLANS
    return {
        "plans": [
            {
                "plan_id": p.plan_id,
                "display_name": p.display_name,
                "description": p.description,
                "price_monthly_usd": p.price_monthly_usd,
                "price_yearly_usd": p.price_yearly_usd,
                "features": p.features,
                "limits": {
                    "events_per_month": p.limits.events_per_month,
                    "agents_per_month": p.limits.agents_per_month,
                    "users_max": p.limits.users_max,
                },
            }
            for p in PLANS.values()
        ]
    }


@router.get("/subscription/{org_id}")
async def get_subscription(org_id: str) -> Dict[str, Any]:
    """Get current subscription for an org."""
    return {
        "org_id": org_id,
        "plan_id": "free",
        "status": "active",
        "billing_cycle": "monthly",
        "current_period_end": time.time() + 30 * 86400,
    }


@router.post("/subscription")
async def create_subscription(req: CreateSubscriptionRequest) -> Dict[str, Any]:
    """Create or update a subscription."""
    from .plans import PLANS
    if req.plan_id not in PLANS:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {req.plan_id}")
    return {
        "subscription_id": f"sub-{int(time.time())}",
        "org_id": req.org_id,
        "plan_id": req.plan_id,
        "billing_cycle": req.billing_cycle,
        "status": "active",
        "created_at": time.time(),
    }


@router.post("/subscription/{org_id}/upgrade")
async def upgrade_plan(org_id: str, req: UpgradePlanRequest) -> Dict[str, Any]:
    """Upgrade to a different plan."""
    return {
        "org_id": org_id,
        "new_plan_id": req.new_plan_id,
        "status": "active",
        "upgraded_at": time.time(),
    }


@router.post("/subscription/{org_id}/cancel")
async def cancel_subscription(org_id: str) -> Dict[str, Any]:
    """Cancel subscription at period end."""
    return {"org_id": org_id, "cancel_at_period_end": True}


@router.get("/usage/{org_id}")
async def get_usage(org_id: str) -> Dict[str, Any]:
    """Get current usage for an org."""
    return {
        "org_id": org_id,
        "events": 0,
        "agents": 0,
        "api_calls": 0,
        "period_start": time.time() - 15 * 86400,
        "period_end": time.time() + 15 * 86400,
    }


@router.get("/invoices/{org_id}")
async def list_invoices(
    org_id: str,
    limit: int = Query(10, ge=1, le=50),
) -> Dict[str, Any]:
    """List invoices for an org."""
    return {"invoices": [], "total": 0}


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request) -> Dict[str, str]:
    """Handle Stripe webhook events."""
    payload = await request.body()
    signature = request.headers.get("Stripe-Signature", "")
    return {"received": "ok"}


@router.post("/portal/{org_id}")
async def create_billing_portal(org_id: str, return_url: str) -> Dict[str, Any]:
    """Create a Stripe customer portal session."""
    return {"url": f"https://billing.stripe.com/p/session/test_{org_id}"}
