"""
SOC 2 Type II compliance checker.
Covers the five Trust Services Criteria: Security, Availability,
Processing Integrity, Confidentiality, and Privacy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SOC2Control:
    """A single SOC 2 control check."""

    control_id: str
    """SOC 2 control reference (e.g., CC6.1)."""

    category: str
    """Trust Services Criterion."""

    description: str
    status: str  # pass | fail | not_evaluated
    evidence: str = ""
    recommendation: str = ""


@dataclass
class SOC2Report:
    compliant: bool
    score: float
    controls: List[SOC2Control] = field(default_factory=list)
    failed_controls: List[str] = field(default_factory=list)


class SOC2Checker:
    """
    Evaluates SOC 2 Trust Services Criteria for an AgentShield deployment.

    Pass platform configuration flags to :meth:`assess` to get a structured
    compliance report with pass/fail per control.
    """

    def assess(
        self,
        has_encryption_at_rest: bool = False,
        has_encryption_in_transit: bool = False,
        has_access_controls: bool = False,
        has_mfa: bool = False,
        has_audit_logging: bool = False,
        has_monitoring_alerts: bool = False,
        has_incident_response: bool = False,
        has_change_management: bool = False,
        has_backup: bool = False,
        has_dr_plan: bool = False,
        has_input_validation: bool = False,
        has_error_handling: bool = False,
        has_data_classification: bool = False,
        has_retention_policy: bool = False,
        has_privacy_notice: bool = False,
        uptime_sla_percent: float = 0.0,
    ) -> SOC2Report:
        """Run a SOC 2 control assessment. Returns a SOC2Report."""
        controls: List[SOC2Control] = []

        def check(control_id: str, category: str, description: str, passed: bool, recommendation: str) -> None:
            controls.append(
                SOC2Control(
                    control_id=control_id,
                    category=category,
                    description=description,
                    status="pass" if passed else "fail",
                    recommendation="" if passed else recommendation,
                )
            )

        # Security (CC6)
        check("CC6.1", "Security", "Logical and physical access controls implemented", has_access_controls, "Implement RBAC with least-privilege access.")
        check("CC6.2", "Security", "Multi-factor authentication enabled", has_mfa, "Enable TOTP or FIDO2 MFA for all user accounts.")
        check("CC6.7", "Security", "Encryption at rest implemented", has_encryption_at_rest, "Encrypt all stored data with AES-256.")
        check("CC6.8", "Security", "Encryption in transit implemented", has_encryption_in_transit, "Enforce TLS 1.2+ on all endpoints.")

        # Monitoring (CC7)
        check("CC7.1", "Security", "Security monitoring and alerting in place", has_monitoring_alerts, "Deploy real-time alerting for security events.")
        check("CC7.2", "Security", "Audit logging enabled", has_audit_logging, "Enable immutable audit logs for all privileged actions.")
        check("CC7.3", "Security", "Incident response plan documented", has_incident_response, "Document and test incident response procedures.")

        # Change Management (CC8)
        check("CC8.1", "Security", "Change management controls in place", has_change_management, "Implement change management with approval workflows.")

        # Availability (A1)
        check("A1.1", "Availability", f"Uptime SLA met (current: {uptime_sla_percent:.2f}%)", uptime_sla_percent >= 99.9, "Achieve ≥99.9% uptime with redundancy and failover.")
        check("A1.2", "Availability", "Backup and recovery procedures in place", has_backup, "Implement automated backups with tested restore procedures.")
        check("A1.3", "Availability", "Disaster recovery plan documented", has_dr_plan, "Document and test disaster recovery procedures annually.")

        # Processing Integrity (PI1)
        check("PI1.1", "Processing Integrity", "Input validation implemented", has_input_validation, "Validate all inputs at API boundaries.")
        check("PI1.2", "Processing Integrity", "Error handling does not expose sensitive data", has_error_handling, "Sanitize error messages before returning to clients.")

        # Confidentiality (C1)
        check("C1.1", "Confidentiality", "Data classification policy in place", has_data_classification, "Classify data (public/internal/confidential/restricted) and enforce controls.")
        check("C1.2", "Confidentiality", "Data retention policy defined", has_retention_policy, "Define and enforce data retention schedules.")

        # Privacy (P1)
        check("P1.1", "Privacy", "Privacy notice provided", has_privacy_notice, "Provide clear privacy notice per GDPR/CCPA.")

        failed = [c.control_id for c in controls if c.status == "fail"]
        score = (len(controls) - len(failed)) / len(controls) * 100 if controls else 100.0

        return SOC2Report(
            compliant=len(failed) == 0,
            score=round(score, 1),
            controls=controls,
            failed_controls=failed,
        )
