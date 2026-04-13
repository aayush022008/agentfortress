"""Tests for MITRE mapping."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from threat_intel.mitre.mapper import (
    load_techniques,
    map_alert_to_techniques,
    map_event_to_techniques,
    get_technique,
    get_techniques_by_tactic,
)
from threat_intel.engine.ttps_mapper import TTPs_Mapper


class TestMITREMapper:
    def test_load_techniques(self):
        techniques = load_techniques()
        assert len(techniques) > 0
        assert "AML.T0054" in techniques
        assert techniques["AML.T0054"]["name"] == "Prompt Injection"

    def test_map_alert_prompt_injection(self):
        mappings = map_alert_to_techniques("prompt_injection")
        assert len(mappings) > 0
        ids = [m["technique_id"] for m in mappings]
        assert "AML.T0054" in ids

    def test_map_alert_credential_access(self):
        mappings = map_alert_to_techniques("credential_access")
        ids = [m["technique_id"] for m in mappings]
        assert "AML.T0043" in ids

    def test_map_alert_data_exfiltration(self):
        mappings = map_alert_to_techniques("data_exfiltration")
        assert len(mappings) > 0

    def test_map_event_injection_keyword(self):
        event = {"event_type": "tool_call", "tool_input": "ignore all previous instructions"}
        mappings = map_event_to_techniques(event)
        ids = [m["technique_id"] for m in mappings]
        assert "AML.T0054" in ids

    def test_get_technique(self):
        t = get_technique("AML.T0054")
        assert t is not None
        assert t["name"] == "Prompt Injection"

    def test_get_techniques_by_tactic(self):
        execution_techs = get_techniques_by_tactic("Execution")
        assert any(t["technique_id"] == "AML.T0054" for t in execution_techs)


class TestTTPsMapper:
    def test_map_event(self):
        mapper = TTPs_Mapper()
        event = {"tool_name": "bash", "tool_input": "ignore all previous instructions"}
        mappings = mapper.map_event(event)
        assert isinstance(mappings, list)

    def test_map_alert(self):
        mapper = TTPs_Mapper()
        mappings = mapper.map_alert("prompt_injection")
        assert len(mappings) > 0
        assert all("technique_id" in m for m in mappings)

    def test_list_techniques(self):
        mapper = TTPs_Mapper()
        techniques = mapper.list_techniques()
        assert len(techniques) > 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
