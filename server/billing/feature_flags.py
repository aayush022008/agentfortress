"""Feature flags — all features are free and available to everyone."""
from __future__ import annotations

from typing import Callable, Optional
from functools import wraps

from fastapi import Request

from .plans import has_feature, PLANS


class FeatureFlags:
    """
    AgentShield is fully free and open-source.
    All features are enabled for everyone — no paywalls, no plan checks.
    """

    def is_enabled(self, feature: str, org_plan: str = "free") -> bool:
        """All features are always enabled."""
        return True

    def require(self, feature: str, org_plan: str = "free") -> None:
        """No-op — all features are freely available."""
        pass

    def get_limit(self, limit_name: str, org_plan: str = "free") -> Optional[int]:
        """Returns unlimited (999_999_999) for all limits."""
        plan = PLANS.get("free")
        if plan:
            return getattr(plan.limits, limit_name, 999_999_999)
        return 999_999_999

    def plan_features(self, org_plan: str) -> list:
        """Returns all features for everyone."""
        return PLANS["free"].features


def require_feature(feature: str):
    """No-op decorator — all features are free."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, request: Request = None, **kwargs):
            return await func(*args, request=request, **kwargs)
        return wrapper
    return decorator
