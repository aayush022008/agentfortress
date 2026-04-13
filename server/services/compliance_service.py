"""Compliance service — run compliance checks and generate findings."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ...sdk.agentshield.compliance.gdpr import GDPRChecker
from ...sdk.agentshield.compliance.hipaa import HIPAAChecker
from ...sdk.agentshield.compliance.soc2 import SOC2Checker
from ...sdk.agentshield.compliance.eu_ai_act import EUAIActChecker
from ...sdk.agentshield.compliance.reporter import ComplianceReporter


@dataclass
class ComplianceFinding:
    finding_id: str
    framework: str
    severity: str
    category: str
    description: str
    recommendation: str
    status: str = "open"  # open | resolved | accepted_risk
    created_at: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "framework": self.framework,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "status": self.status,
            "created_at": self.created_at,
        }


class ComplianceService:
    """
    Runs compliance checks against collected event data and maintains findings.

    Usage::

        svc = ComplianceService()
        findings = await svc.run_gdpr_check(events, region="eu-west-1")
        all_findings = svc.list_findings(framework="gdpr")
    """

    def __init__(self) -> None:
        self._findings: Dict[str, ComplianceFinding] = {}

    async def run_gdpr_check(
        self,
        events: List[Dict[str, Any]],
        region: Optional[str] = None,
    ) -> List[ComplianceFinding]:
        checker = GDPRChecker(data_residency_region=region)
        report = checker.assess(events, current_region=region)
        return self._convert_findings("gdpr", report.findings, "severity", "category", "description", "recommendation")

    async def run_hipaa_check(
        self,
        events: List[Dict[str, Any]],
        **kwargs: Any,
    ) -> List[ComplianceFinding]:
        checker = HIPAAChecker()
        report = checker.assess(events, **kwargs)
        return self._convert_findings("hipaa", report.findings, "severity", "category", "description", "recommendation")

    async def run_soc2_check(self, **kwargs: Any) -> List[ComplianceFinding]:
        checker = SOC2Checker()
        report = checker.assess(**kwargs)
        failed = [c for c in report.controls if c.status == "fail"]
        return self._convert_findings("soc2", failed, "category", "control_id", "description", "recommendation")

    async def run_eu_ai_act_check(
        self, use_cases: List[str], **kwargs: Any
    ) -> List[ComplianceFinding]:
        checker = EUAIActChecker()
        report = checker.assess(use_cases=use_cases, **kwargs)
        failed = [r for r in report.requirements if r.status == "non_compliant"]
        return self._convert_findings("eu_ai_act", failed, "article", "requirement_id", "description", "recommendation")

    async def run_all_checks(
        self,
        events: List[Dict[str, Any]],
        region: Optional[str] = None,
        use_cases: Optional[List[str]] = None,
        soc2_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, List[ComplianceFinding]]:
        results = {}
        results["gdpr"] = await self.run_gdpr_check(events, region=region)
        results["hipaa"] = await self.run_hipaa_check(events)
        results["soc2"] = await self.run_soc2_check(**(soc2_config or {}))
        if use_cases:
            results["eu_ai_act"] = await self.run_eu_ai_act_check(use_cases)
        return results

    def list_findings(
        self,
        framework: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[ComplianceFinding]:
        findings = list(self._findings.values())
        if framework:
            findings = [f for f in findings if f.framework == framework]
        if status:
            findings = [f for f in findings if f.status == status]
        if severity:
            findings = [f for f in findings if f.severity == severity]
        return sorted(findings, key=lambda f: f.created_at, reverse=True)

    def resolve_finding(self, finding_id: str) -> bool:
        f = self._findings.get(finding_id)
        if not f:
            return False
        f.status = "resolved"
        f.resolved_at = time.time()
        return True

    # ------------------------------------------------------------------

    def _convert_findings(
        self,
        framework: str,
        items: List[Any],
        severity_attr: str,
        category_attr: str,
        desc_attr: str,
        rec_attr: str,
    ) -> List[ComplianceFinding]:
        findings = []
        for item in items:
            if isinstance(item, dict):
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4()),
                    framework=framework,
                    severity=item.get(severity_attr, "medium"),
                    category=item.get(category_attr, ""),
                    description=item.get(desc_attr, ""),
                    recommendation=item.get(rec_attr, ""),
                )
            else:
                finding = ComplianceFinding(
                    finding_id=str(uuid.uuid4()),
                    framework=framework,
                    severity=getattr(item, severity_attr, "medium"),
                    category=getattr(item, category_attr, ""),
                    description=getattr(item, desc_attr, ""),
                    recommendation=getattr(item, rec_attr, ""),
                )
            self._findings[finding.finding_id] = finding
            findings.append(finding)
        return findings
