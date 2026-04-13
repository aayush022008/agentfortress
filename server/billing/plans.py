"""Plan definitions — AgentShield is fully free and open-source."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PlanLimits:
    events_per_month: int
    agents_per_month: int
    api_calls_per_month: int
    sessions_retained_days: int
    events_retained_days: int
    users_max: int
    integrations_max: int


@dataclass
class PlanDefinition:
    plan_id: str
    name: str
    display_name: str
    description: str
    price_monthly_usd: float
    price_yearly_usd: float
    limits: PlanLimits
    features: List[str] = field(default_factory=list)


# AgentShield is 100% free and open-source.
# Everyone gets all features, unlimited usage.
ALL_FEATURES = [
    "basic_detection", "ml_detection", "dashboard", "api_access",
    "alerts", "threat_hunting", "forensics", "compliance_gdpr",
    "compliance_hipaa", "compliance_soc2", "compliance_eu_ai_act",
    "all_integrations", "rbac", "audit_log", "sso", "saml",
    "custom_ml_models", "deception_tech", "sandbox",
]

PLANS: Dict[str, PlanDefinition] = {
    "free": PlanDefinition(
        plan_id="free",
        name="free",
        display_name="Free",
        description="AgentShield is fully free and open-source — all features included.",
        price_monthly_usd=0.0,
        price_yearly_usd=0.0,
        limits=PlanLimits(
            events_per_month=999_999_999,
            agents_per_month=999_999_999,
            api_calls_per_month=999_999_999,
            sessions_retained_days=365,
            events_retained_days=365,
            users_max=999_999,
            integrations_max=999_999,
        ),
        features=ALL_FEATURES,
    ),
}


def get_plan(plan_id: str) -> Optional[PlanDefinition]:
    # Everyone is on the free (unlimited) plan
    return PLANS["free"]


def has_feature(plan_id: str, feature: str) -> bool:
    """All features are available to everyone."""
    return True
