"""
EU AI Act compliance checker.
Risk classification, conformity assessment, and human oversight logging
per the EU Artificial Intelligence Act (Regulation (EU) 2024/1689).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AIRiskLevel(Enum):
    UNACCEPTABLE = "unacceptable"  # Article 5 — prohibited
    HIGH = "high"                  # Annex III — high risk
    LIMITED = "limited"            # Article 52 — transparency obligations
    MINIMAL = "minimal"            # All other AI systems


@dataclass
class ConformityRequirement:
    requirement_id: str
    article: str
    description: str
    status: str  # compliant | non_compliant | not_applicable
    recommendation: str = ""


@dataclass
class EUAIActReport:
    risk_level: AIRiskLevel
    compliant: bool
    score: float
    requirements: List[ConformityRequirement] = field(default_factory=list)
    human_oversight_logged: bool = False
    technical_documentation: bool = False
    conformity_assessment_done: bool = False


# High-risk AI use cases (Annex III)
HIGH_RISK_USES = [
    "biometric_identification",
    "critical_infrastructure",
    "education_assessment",
    "employment_recruitment",
    "essential_services",
    "law_enforcement",
    "migration_asylum",
    "justice_democracy",
]

# Prohibited uses (Article 5)
PROHIBITED_USES = [
    "subliminal_manipulation",
    "exploitation_of_vulnerabilities",
    "social_scoring",
    "real_time_biometric",
    "emotion_recognition_workplace",
]


class EUAIActChecker:
    """
    Evaluates EU AI Act compliance for an AI agent deployment.

    Usage::

        checker = EUAIActChecker()
        report = checker.assess(
            use_cases=["employment_recruitment"],
            has_human_oversight=True,
            has_technical_docs=True,
            ...
        )
    """

    def classify_risk(self, use_cases: List[str]) -> AIRiskLevel:
        """Determine the risk level based on declared use cases."""
        for use_case in use_cases:
            if use_case in PROHIBITED_USES:
                return AIRiskLevel.UNACCEPTABLE
        for use_case in use_cases:
            if use_case in HIGH_RISK_USES:
                return AIRiskLevel.HIGH
        # Check for limited risk (transparency requirements)
        if any(u in ["chatbot", "emotion_recognition", "deepfake"] for u in use_cases):
            return AIRiskLevel.LIMITED
        return AIRiskLevel.MINIMAL

    def assess(
        self,
        use_cases: List[str],
        has_human_oversight: bool = False,
        has_technical_docs: bool = False,
        has_conformity_assessment: bool = False,
        has_transparency_disclosure: bool = False,
        has_data_governance: bool = False,
        has_accuracy_metrics: bool = False,
        has_robustness_testing: bool = False,
        has_cybersecurity_measures: bool = False,
        has_incident_reporting: bool = False,
        human_oversight_log_count: int = 0,
    ) -> EUAIActReport:
        """Run a full EU AI Act conformity assessment."""
        risk_level = self.classify_risk(use_cases)
        reqs: List[ConformityRequirement] = []

        def req(rid: str, article: str, desc: str, satisfied: bool, rec: str = "") -> None:
            reqs.append(ConformityRequirement(
                requirement_id=rid,
                article=article,
                description=desc,
                status="compliant" if satisfied else "non_compliant",
                recommendation="" if satisfied else rec,
            ))

        if risk_level == AIRiskLevel.UNACCEPTABLE:
            reqs.append(ConformityRequirement(
                requirement_id="ART5",
                article="Article 5",
                description="Prohibited AI system detected",
                status="non_compliant",
                recommendation="Cease operation immediately. This AI use is prohibited under EU AI Act Article 5.",
            ))
            return EUAIActReport(
                risk_level=risk_level, compliant=False, score=0.0, requirements=reqs
            )

        if risk_level == AIRiskLevel.HIGH:
            req("ART9", "Article 9", "Risk management system in place", has_robustness_testing, "Implement continuous risk management system per Article 9.")
            req("ART10", "Article 10", "Data governance and management practices", has_data_governance, "Establish data governance covering training/validation data lineage.")
            req("ART11", "Article 11", "Technical documentation prepared", has_technical_docs, "Prepare technical documentation per Annex IV before deployment.")
            req("ART12", "Article 12", "Automatic logging enabled for high-risk AI", has_human_oversight, "Enable detailed automatic logging of AI system operation.")
            req("ART13", "Article 13", "Transparency and information to users", has_transparency_disclosure, "Provide clear disclosure to users about AI involvement.")
            req("ART14", "Article 14", "Human oversight measures in place", has_human_oversight, "Implement human oversight allowing intervention and correction.")
            req("ART15", "Article 15", "Accuracy, robustness, cybersecurity", has_accuracy_metrics and has_cybersecurity_measures, "Achieve appropriate accuracy levels; implement cybersecurity safeguards.")
            req("ART43", "Article 43", "Conformity assessment completed", has_conformity_assessment, "Complete conformity assessment (internal or third-party) before market placement.")
            req("ART62", "Article 62", "Serious incident reporting capability", has_incident_reporting, "Establish procedure to report serious incidents to national authority.")

        elif risk_level == AIRiskLevel.LIMITED:
            req("ART52", "Article 52", "Transparency disclosure to users", has_transparency_disclosure, "Inform users they are interacting with an AI system.")

        # Minimal risk — no mandatory requirements but best practices
        if risk_level == AIRiskLevel.MINIMAL:
            reqs.append(ConformityRequirement(
                requirement_id="MINIMAL",
                article="N/A",
                description="Minimal risk — no mandatory requirements",
                status="compliant",
            ))

        failed = [r for r in reqs if r.status == "non_compliant"]
        total = len(reqs)
        score = (total - len(failed)) / total * 100 if total else 100.0

        return EUAIActReport(
            risk_level=risk_level,
            compliant=len(failed) == 0,
            score=round(score, 1),
            requirements=reqs,
            human_oversight_logged=human_oversight_log_count > 0,
            technical_documentation=has_technical_docs,
            conformity_assessment_done=has_conformity_assessment,
        )
