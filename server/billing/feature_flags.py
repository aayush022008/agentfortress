"""Feature flags — gate features based on subscription plan."""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional
from functools import wraps

from fastapi import HTTPException, Request

from .plans import PLANS, has_feature


class FeatureFlags:
    """
    Feature gating based on subscription plan.

    Usage::

        flags = FeatureFlags()
        if flags.is_enabled("ml_detection", org_plan="pro"):
            # run ML detection
            pass

        # As a FastAPI dependency:
        @app.get("/api/ml/score")
        async def score(flags: FeatureFlags = Depends(get_feature_flags)):
            flags.require("ml_detection", org_plan=get_org_plan(request))
    """

    def is_enabled(self, feature: str, org_plan: str = "free") -> bool:
        """Check if a feature is available for the given plan."""
        return has_feature(org_plan, feature)

    def require(self, feature: str, org_plan: str = "free") -> None:
        """Raise HTTP 403 if the feature is not available on the plan."""
        if not self.is_enabled(feature, org_plan):
            raise HTTPException(
                status_code=403,
                detail=f"Feature '{feature}' is not available on the '{org_plan}' plan. Please upgrade.",
            )

    def get_limit(self, limit_name: str, org_plan: str = "free") -> Optional[int]:
        """Get a usage limit for the plan."""
        plan = PLANS.get(org_plan)
        if not plan:
            plan = PLANS.get("free")
        if plan:
            return getattr(plan.limits, limit_name, None)
        return None

    def plan_features(self, org_plan: str) -> list:
        """Return list of features available on a plan."""
        plan = PLANS.get(org_plan)
        return plan.features if plan else []


def require_feature(feature: str):
    """FastAPI route decorator that requires a specific feature flag."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, request: Request = None, **kwargs):
            # In real app, get org_plan from JWT/session
            org_plan = "enterprise"  # placeholder
            FeatureFlags().require(feature, org_plan)
            return await func(*args, request=request, **kwargs)
        return wrapper
    return decorator
