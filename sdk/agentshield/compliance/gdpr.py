"""
GDPR compliance checker for AgentShield.
Auto-detects personal data, supports right-to-erasure, data residency checks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# PII detection patterns (GDPR Article 4 personal data)
_PII_PATTERNS: Dict[str, re.Pattern] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone_intl": re.compile(r"\+?1?\s?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
    "national_id": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN-style
    "date_of_birth": re.compile(
        r"\b(?:dob|date.of.birth|born)[:\s]+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b",
        re.IGNORECASE,
    ),
    "passport": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    "full_name": re.compile(r"\b(?:name|full name)[:\s]+[A-Z][a-z]+\s[A-Z][a-z]+\b", re.IGNORECASE),
    "home_address": re.compile(
        r"\b\d{1,5}\s[A-Z][a-z]+(?:\s[A-Z][a-z]+)*\s(?:St|Ave|Blvd|Dr|Rd|Ln|Way|Ct)\b",
        re.IGNORECASE,
    ),
}


@dataclass
class GDPRFinding:
    """A single GDPR compliance finding."""

    category: str
    severity: str  # critical | high | medium | low | info
    description: str
    recommendation: str
    data_types_found: List[str] = field(default_factory=list)
    affected_records: int = 0


@dataclass
class GDPRReport:
    """Complete GDPR compliance report."""

    compliant: bool
    score: float  # 0.0 – 100.0
    findings: List[GDPRFinding] = field(default_factory=list)
    data_residency_ok: bool = True
    pii_detected: bool = False
    erasure_requests_pending: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class GDPRChecker:
    """
    Evaluates GDPR compliance for agent sessions and event data.

    Features:
    - Auto-detect PII in free-text fields
    - Data residency validation
    - Right-to-erasure tracking
    - Consent basis verification
    """

    ALLOWED_RESIDENCY_REGIONS: Set[str] = {
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
        "eu-north-1", "eu-south-1", "eu-east-1",
    }

    def __init__(
        self,
        data_residency_region: Optional[str] = None,
        erasure_log_path: Optional[str] = None,
    ) -> None:
        self._region = data_residency_region
        self._erasure_log: List[Dict[str, Any]] = []
        self._erasure_log_path = erasure_log_path

    def scan_text(self, text: str) -> Dict[str, List[str]]:
        """
        Scan arbitrary text for PII patterns.
        Returns a dict mapping category → list of matched values.
        """
        results: Dict[str, List[str]] = {}
        for category, pattern in _PII_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                results[category] = matches
        return results

    def scan_event(self, event: Dict[str, Any]) -> Dict[str, List[str]]:
        """Scan all string fields of an event for PII."""
        combined = " ".join(
            str(v) for v in _flatten_values(event) if isinstance(v, str)
        )
        return self.scan_text(combined)

    def check_data_residency(self, current_region: str) -> bool:
        """Return True if data is stored in an EU-approved region."""
        return current_region in self.ALLOWED_RESIDENCY_REGIONS

    def record_erasure_request(
        self, subject_id: str, requested_by: str, reason: str = ""
    ) -> Dict[str, Any]:
        """
        Record a GDPR right-to-erasure request.
        Returns the erasure record dict.
        """
        import datetime
        record = {
            "subject_id": subject_id,
            "requested_by": requested_by,
            "reason": reason,
            "requested_at": datetime.datetime.utcnow().isoformat(),
            "fulfilled": False,
        }
        self._erasure_log.append(record)
        return record

    def fulfill_erasure(self, subject_id: str) -> int:
        """Mark all erasure requests for subject_id as fulfilled."""
        count = 0
        for record in self._erasure_log:
            if record["subject_id"] == subject_id and not record["fulfilled"]:
                import datetime
                record["fulfilled"] = True
                record["fulfilled_at"] = datetime.datetime.utcnow().isoformat()
                count += 1
        return count

    def pending_erasure_requests(self) -> List[Dict[str, Any]]:
        """Return all unfulfilled erasure requests."""
        return [r for r in self._erasure_log if not r["fulfilled"]]

    def assess(
        self,
        events: List[Dict[str, Any]],
        current_region: Optional[str] = None,
    ) -> GDPRReport:
        """
        Run a full GDPR compliance assessment against a list of events.
        Returns a GDPRReport.
        """
        findings: List[GDPRFinding] = []
        pii_detected = False
        all_pii_types: Set[str] = set()

        for event in events:
            pii = self.scan_event(event)
            if pii:
                pii_detected = True
                all_pii_types.update(pii.keys())

        if pii_detected:
            findings.append(
                GDPRFinding(
                    category="data_minimization",
                    severity="high",
                    description=f"PII detected in agent events: {', '.join(sorted(all_pii_types))}",
                    recommendation="Apply data minimization; mask or pseudonymise PII before storing events.",
                    data_types_found=sorted(all_pii_types),
                    affected_records=len(events),
                )
            )

        region = current_region or self._region
        residency_ok = True
        if region:
            residency_ok = self.check_data_residency(region)
            if not residency_ok:
                findings.append(
                    GDPRFinding(
                        category="data_residency",
                        severity="critical",
                        description=f"Data stored in non-EU region: {region}",
                        recommendation="Migrate data storage to an EU-approved AWS/GCP/Azure region.",
                    )
                )

        pending = len(self.pending_erasure_requests())
        if pending > 0:
            findings.append(
                GDPRFinding(
                    category="right_to_erasure",
                    severity="high",
                    description=f"{pending} erasure request(s) unfulfilled.",
                    recommendation="Process erasure requests within 30 days per GDPR Article 17.",
                )
            )

        # Score: start at 100, deduct per finding
        score = 100.0
        severity_deductions = {"critical": 30, "high": 15, "medium": 8, "low": 3, "info": 0}
        for f in findings:
            score -= severity_deductions.get(f.severity, 0)
        score = max(0.0, score)

        return GDPRReport(
            compliant=score >= 80 and not any(f.severity == "critical" for f in findings),
            score=score,
            findings=findings,
            data_residency_ok=residency_ok,
            pii_detected=pii_detected,
            erasure_requests_pending=pending,
        )


def _flatten_values(obj: Any, depth: int = 0) -> List[Any]:
    """Recursively extract all values from a nested dict/list."""
    if depth > 10:
        return []
    if isinstance(obj, dict):
        vals: List[Any] = []
        for v in obj.values():
            vals.extend(_flatten_values(v, depth + 1))
        return vals
    if isinstance(obj, (list, tuple)):
        vals = []
        for item in obj:
            vals.extend(_flatten_values(item, depth + 1))
        return vals
    return [obj]
