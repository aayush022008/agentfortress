"""
HIPAA compliance checker — PHI detection (18 Safe Harbor identifiers),
audit controls, and access logging.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# HIPAA Safe Harbor — 18 PHI identifiers (45 CFR §164.514(b)(2))
_PHI_PATTERNS: Dict[str, re.Pattern] = {
    "name": re.compile(r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b"),
    "geographic_subdivision": re.compile(
        r"\b\d{5}(?:-\d{4})?\b"  # ZIP code
    ),
    "date": re.compile(
        r"\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-]\d{2,4}\b"
    ),
    "phone_number": re.compile(r"\b(?:\+?1\s?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"),
    "fax_number": re.compile(r"\bfax[:\s]+(?:\+?1\s?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b", re.IGNORECASE),
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "mrn": re.compile(r"\b(?:mrn|medical.record.number)[:\s]*\d{6,12}\b", re.IGNORECASE),
    "health_plan_number": re.compile(r"\b(?:member.id|plan.id)[:\s]*[A-Z0-9]{8,15}\b", re.IGNORECASE),
    "account_number": re.compile(r"\baccount[:\s#]*\d{8,16}\b", re.IGNORECASE),
    "certificate_license": re.compile(r"\b(?:license|cert)[:\s#]*[A-Z0-9]{6,15}\b", re.IGNORECASE),
    "vehicle_identifier": re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),  # VIN
    "device_identifier": re.compile(r"\b(?:device.id|serial)[:\s]*[A-Z0-9\-]{8,20}\b", re.IGNORECASE),
    "url": re.compile(r"https?://[^\s]+"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "biometric_identifier": re.compile(r"\b(?:fingerprint|retina|iris|voiceprint)\b", re.IGNORECASE),
    "full_face_photo": re.compile(r"\b(?:photo|image|headshot).{0,20}patient\b", re.IGNORECASE),
    "unique_identifier": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
}


@dataclass
class HIPAAFinding:
    severity: str
    category: str
    description: str
    recommendation: str
    phi_types: List[str] = field(default_factory=list)


@dataclass
class HIPAAReport:
    compliant: bool
    score: float
    findings: List[HIPAAFinding] = field(default_factory=list)
    phi_detected: bool = False
    access_log_present: bool = False
    audit_controls_present: bool = False


class HIPAAChecker:
    """
    HIPAA Security Rule compliance checker for AI agent deployments.

    Checks for:
    - PHI in agent outputs (18 Safe Harbor identifiers)
    - Audit controls (§164.312(b))
    - Access logging (§164.312(a)(1))
    - Transmission security (§164.312(e))
    """

    def scan_phi(self, text: str) -> Dict[str, List[str]]:
        """Scan text for PHI — returns dict of identifier type → matches."""
        results: Dict[str, List[str]] = {}
        for identifier, pattern in _PHI_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                results[identifier] = matches[:10]  # cap to 10 per type
        return results

    def scan_event(self, event: Dict[str, Any]) -> Dict[str, List[str]]:
        """Scan all string values in an event dict for PHI."""
        combined = _flatten_str_values(event)
        return self.scan_phi(combined)

    def assess(
        self,
        events: List[Dict[str, Any]],
        has_audit_log: bool = False,
        has_access_log: bool = False,
        encryption_at_rest: bool = False,
        encryption_in_transit: bool = False,
    ) -> HIPAAReport:
        """Run a HIPAA compliance assessment."""
        findings: List[HIPAAFinding] = []
        phi_found: Set[str] = set()

        for event in events:
            phi = self.scan_event(event)
            phi_found.update(phi.keys())

        if phi_found:
            findings.append(
                HIPAAFinding(
                    severity="critical",
                    category="phi_exposure",
                    description=f"PHI identifiers detected in agent events: {', '.join(sorted(phi_found))}",
                    recommendation="Implement PHI masking/de-identification before storing agent events. Use Safe Harbor method.",
                    phi_types=sorted(phi_found),
                )
            )

        if not has_audit_log:
            findings.append(
                HIPAAFinding(
                    severity="high",
                    category="audit_controls",
                    description="No audit controls detected (HIPAA §164.312(b))",
                    recommendation="Implement comprehensive audit logging for all PHI access and modifications.",
                )
            )

        if not has_access_log:
            findings.append(
                HIPAAFinding(
                    severity="high",
                    category="access_logging",
                    description="Access logging not configured (HIPAA §164.312(a)(1))",
                    recommendation="Log all access to ePHI including user ID, timestamp, and action.",
                )
            )

        if not encryption_at_rest:
            findings.append(
                HIPAAFinding(
                    severity="high",
                    category="encryption_at_rest",
                    description="Data at rest is not encrypted (HIPAA §164.312(a)(2)(iv))",
                    recommendation="Encrypt all stored ePHI using AES-256 or equivalent.",
                )
            )

        if not encryption_in_transit:
            findings.append(
                HIPAAFinding(
                    severity="high",
                    category="transmission_security",
                    description="Transmission security not confirmed (HIPAA §164.312(e)(1))",
                    recommendation="Use TLS 1.2+ for all ePHI transmissions.",
                )
            )

        score = 100.0
        deductions = {"critical": 30, "high": 15, "medium": 8, "low": 3}
        for f in findings:
            score -= deductions.get(f.severity, 0)
        score = max(0.0, score)

        return HIPAAReport(
            compliant=score >= 80 and not any(f.severity == "critical" for f in findings),
            score=score,
            findings=findings,
            phi_detected=bool(phi_found),
            access_log_present=has_access_log,
            audit_controls_present=has_audit_log,
        )


def _flatten_str_values(obj: Any, depth: int = 0) -> str:
    if depth > 8:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_str_values(v, depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten_str_values(item, depth + 1) for item in obj)
    return str(obj)
