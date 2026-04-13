"""Tests for compliance modules."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.compliance.gdpr import GDPRChecker
from agentshield.compliance.hipaa import HIPAAChecker
from agentshield.compliance.soc2 import SOC2Checker
from agentshield.compliance.eu_ai_act import EUAIActChecker, AIRiskLevel
from agentshield.compliance.reporter import ComplianceReporter


class TestGDPRChecker:
    def test_scan_text_detects_email(self):
        checker = GDPRChecker()
        text = "Contact alice@example.com for help"
        results = checker.scan_text(text)
        assert "email" in results
        assert "alice@example.com" in results["email"]

    def test_scan_text_detects_ssn(self):
        checker = GDPRChecker()
        text = "Social security number: 123-45-6789"
        results = checker.scan_text(text)
        assert "national_id" in results

    def test_scan_text_clean(self):
        checker = GDPRChecker()
        results = checker.scan_text("The weather is nice today.")
        assert not results

    def test_data_residency_eu(self):
        checker = GDPRChecker()
        assert checker.check_data_residency("eu-west-1") is True
        assert checker.check_data_residency("us-east-1") is False

    def test_erasure_request(self):
        checker = GDPRChecker()
        record = checker.record_erasure_request("user-123", "admin", "User requested")
        assert record["subject_id"] == "user-123"
        assert not record["fulfilled"]
        count = checker.fulfill_erasure("user-123")
        assert count == 1
        assert len(checker.pending_erasure_requests()) == 0

    def test_assess_with_pii_events(self):
        checker = GDPRChecker()
        events = [
            {"event_type": "tool_call", "output": "User email: test@example.com"},
        ]
        report = checker.assess(events, current_region="us-east-1")
        assert report.pii_detected
        assert not report.data_residency_ok
        assert any(f.category == "data_minimization" for f in report.findings)

    def test_assess_clean(self):
        checker = GDPRChecker()
        events = [{"event_type": "tool_call", "output": "42"}]
        report = checker.assess(events, current_region="eu-west-1")
        assert not report.pii_detected
        assert report.data_residency_ok


class TestHIPAAChecker:
    def test_scan_phi_ssn(self):
        checker = HIPAAChecker()
        text = "Patient SSN: 123-45-6789"
        results = checker.scan_phi(text)
        assert "ssn" in results

    def test_scan_phi_email(self):
        checker = HIPAAChecker()
        text = "Patient email: patient@hospital.com"
        results = checker.scan_phi(text)
        assert "email_address" in results

    def test_assess_with_phi(self):
        checker = HIPAAChecker()
        events = [{"event_type": "query", "output": "Patient SSN: 123-45-6789, DOB: 01/15/1985"}]
        report = checker.assess(events, has_audit_log=False, has_access_log=False)
        assert report.phi_detected
        assert not report.compliant
        assert any(f.severity == "critical" for f in report.findings)

    def test_assess_compliant(self):
        checker = HIPAAChecker()
        report = checker.assess(
            [], has_audit_log=True, has_access_log=True,
            encryption_at_rest=True, encryption_in_transit=True
        )
        assert not report.phi_detected
        assert report.compliant


class TestSOC2Checker:
    def test_all_controls_pass(self):
        checker = SOC2Checker()
        report = checker.assess(
            has_encryption_at_rest=True, has_encryption_in_transit=True,
            has_access_controls=True, has_mfa=True, has_audit_logging=True,
            has_monitoring_alerts=True, has_incident_response=True,
            has_change_management=True, has_backup=True, has_dr_plan=True,
            has_input_validation=True, has_error_handling=True,
            has_data_classification=True, has_retention_policy=True,
            has_privacy_notice=True, uptime_sla_percent=99.95,
        )
        assert report.compliant
        assert report.score == 100.0

    def test_failed_controls(self):
        checker = SOC2Checker()
        report = checker.assess(has_mfa=False, has_audit_logging=False)
        assert not report.compliant
        assert "CC6.2" in report.failed_controls
        assert "CC7.2" in report.failed_controls


class TestEUAIActChecker:
    def test_prohibited_use_case(self):
        checker = EUAIActChecker()
        report = checker.assess(use_cases=["social_scoring"])
        assert report.risk_level == AIRiskLevel.UNACCEPTABLE
        assert not report.compliant
        assert report.score == 0.0

    def test_high_risk_employment(self):
        checker = EUAIActChecker()
        report = checker.assess(
            use_cases=["employment_recruitment"],
            has_human_oversight=True,
            has_technical_docs=True,
            has_conformity_assessment=True,
            has_transparency_disclosure=True,
            has_data_governance=True,
            has_accuracy_metrics=True,
            has_robustness_testing=True,
            has_cybersecurity_measures=True,
            has_incident_reporting=True,
        )
        assert report.risk_level == AIRiskLevel.HIGH
        assert report.compliant

    def test_minimal_risk(self):
        checker = EUAIActChecker()
        report = checker.assess(use_cases=["text_summarization"])
        assert report.risk_level == AIRiskLevel.MINIMAL
        assert report.compliant


class TestComplianceReporter:
    def test_generate_json_report(self, tmp_path):
        reporter = ComplianceReporter(organization="Test Corp", assessor="Security Team")

        gdpr_checker = GDPRChecker()
        gdpr_report = gdpr_checker.assess([{"output": "hello"}], current_region="eu-west-1")
        reporter.add_section("GDPR", gdpr_report)

        output_path = str(tmp_path / "report.json")
        path = reporter.save_json(output_path)
        assert os.path.exists(path)

        import json
        data = json.loads(open(path).read())
        assert "meta" in data
        assert "sections" in data
        assert data["meta"]["organization"] == "Test Corp"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
