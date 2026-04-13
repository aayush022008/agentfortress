"""Plan definitions with feature gates and limits."""
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
    stripe_price_id_monthly: Optional[str] = None
    stripe_price_id_yearly: Optional[str] = None


PLANS: Dict[str, PlanDefinition] = {
    "free": PlanDefinition(
        plan_id="free",
        name="free",
        display_name="Free",
        description="For individuals and small projects",
        price_monthly_usd=0.0,
        price_yearly_usd=0.0,
        limits=PlanLimits(
            events_per_month=10_000,
            agents_per_month=5,
            api_calls_per_month=1_000,
            sessions_retained_days=7,
            events_retained_days=7,
            users_max=1,
            integrations_max=1,
        ),
        features=["basic_detection", "dashboard", "api_access"],
    ),
    "starter": PlanDefinition(
        plan_id="starter",
        name="starter",
        display_name="Starter",
        description="For small teams",
        price_monthly_usd=49.0,
        price_yearly_usd=470.0,
        limits=PlanLimits(
            events_per_month=500_000,
            agents_per_month=50,
            api_calls_per_month=50_000,
            sessions_retained_days=30,
            events_retained_days=30,
            users_max=5,
            integrations_max=3,
        ),
        features=["basic_detection", "dashboard", "api_access", "alerts", "slack_integration"],
    ),
    "pro": PlanDefinition(
        plan_id="pro",
        name="pro",
        display_name="Pro",
        description="For growing security teams",
        price_monthly_usd=199.0,
        price_yearly_usd=1_908.0,
        limits=PlanLimits(
            events_per_month=5_000_000,
            agents_per_month=500,
            api_calls_per_month=1_000_000,
            sessions_retained_days=90,
            events_retained_days=90,
            users_max=25,
            integrations_max=10,
        ),
        features=[
            "basic_detection", "ml_detection", "dashboard", "api_access",
            "alerts", "threat_hunting", "forensics", "compliance_gdpr",
            "compliance_soc2", "slack_integration", "pagerduty_integration",
            "jira_integration", "rbac", "audit_log",
        ],
    ),
    "enterprise": PlanDefinition(
        plan_id="enterprise",
        name="enterprise",
        display_name="Enterprise",
        description="For large enterprises with advanced requirements",
        price_monthly_usd=999.0,
        price_yearly_usd=9_588.0,
        limits=PlanLimits(
            events_per_month=100_000_000,
            agents_per_month=10_000,
            api_calls_per_month=50_000_000,
            sessions_retained_days=365,
            events_retained_days=365,
            users_max=500,
            integrations_max=100,
        ),
        features=[
            "basic_detection", "ml_detection", "dashboard", "api_access",
            "alerts", "threat_hunting", "forensics", "compliance_gdpr",
            "compliance_hipaa", "compliance_soc2", "compliance_eu_ai_act",
            "all_integrations", "rbac", "audit_log", "sso", "saml",
            "custom_ml_models", "deception_tech", "sandbox",
            "dedicated_support", "sla_99_9", "on_premise",
        ],
    ),
}


def get_plan(plan_id: str) -> Optional[PlanDefinition]:
    return PLANS.get(plan_id)


def has_feature(plan_id: str, feature: str) -> bool:
    """Check if a plan has a specific feature."""
    plan = get_plan(plan_id)
    if not plan:
        return False
    return feature in plan.features or "all_integrations" in plan.features
